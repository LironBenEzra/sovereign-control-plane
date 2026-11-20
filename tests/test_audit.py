from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from control_plane.audit.chain import GENESIS_HASH, record_digest
from control_plane.audit.keys import keyed_hash, load_or_create_signing_key, sign_digest
from control_plane.audit.log import AuditIntegrityError, AuditLog
from control_plane.audit.verify import main as verify_main
from control_plane.audit.verify import parse_lines, receipt_problem, verify_chain
from control_plane.evidence import signals_from_evidence
from tests.conftest import EMAIL, PERSON, SSN, HarnessFactory


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def log(tmp_path: Path, key: Ed25519PrivateKey) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl", key)
    for i in range(4):
        log.append("note", f"id-{i}", {"n": i})
    return log


def read(log: AuditLog) -> list[dict[str, Any]]:
    return [dict(r) for r in log.read()]


def rewrite(log: AuditLog, records: list[dict[str, Any]]) -> None:
    log.path.write_text("".join(json.dumps(r) + "\n" for r in records))


def first_problem(log: AuditLog, key: Ed25519PrivateKey) -> tuple[int | None, str]:
    records, parse_problems = parse_lines(log.path.read_text().splitlines())
    problems = [*verify_chain(records, key.public_key()).chain_problems, *parse_problems]
    assert problems, "expected the verifier to find a problem"
    return problems[0].seq, problems[0].reason


def test_records_are_chained_and_signed(log: AuditLog, key: Ed25519PrivateKey) -> None:
    records = read(log)

    assert [r["seq"] for r in records] == [0, 1, 2, 3]
    assert records[0]["prev_hash"] == GENESIS_HASH
    assert all(records[i]["prev_hash"] == records[i - 1]["hash"] for i in range(1, 4))

    report = verify_chain(records, key.public_key())
    assert report.ok
    assert (report.records, report.head_seq, report.head_hash) == (4, 3, records[3]["hash"])


def test_editing_a_record_is_detected(log: AuditLog, key: Ed25519PrivateKey) -> None:
    records = read(log)
    records[1]["body"]["n"] = 999
    rewrite(log, records)

    assert first_problem(log, key) == (1, "content does not match its hash")


def test_editing_a_record_and_recomputing_its_hash_is_detected(
    log: AuditLog, key: Ed25519PrivateKey
) -> None:
    # An attacker who can write the file but does not hold the signing key.
    records = read(log)
    records[1]["body"]["n"] = 999
    records[1]["hash"] = record_digest(records[1])
    rewrite(log, records)

    assert first_problem(log, key) == (1, "signature is not valid")


def test_rewriting_the_chain_with_another_key_is_detected(
    log: AuditLog, key: Ed25519PrivateKey
) -> None:
    attacker = Ed25519PrivateKey.generate()
    records = read(log)
    prev = GENESIS_HASH
    for record in records:
        record["prev_hash"] = prev
        record["hash"] = prev = record_digest(record)
        record["sig"] = sign_digest(attacker, record["hash"])
    rewrite(log, records)

    assert first_problem(log, key) == (0, "signature is not valid")


def test_deleting_a_record_is_detected(log: AuditLog, key: Ed25519PrivateKey) -> None:
    records = read(log)
    del records[1]
    rewrite(log, records)

    assert first_problem(log, key) == (1, "expected seq 1, found 2")


def test_reordering_records_is_detected(log: AuditLog, key: Ed25519PrivateKey) -> None:
    records = read(log)
    records[1], records[2] = records[2], records[1]
    rewrite(log, records)

    assert first_problem(log, key)[0] == 1


def test_a_corrupt_line_is_detected(log: AuditLog, key: Ed25519PrivateKey) -> None:
    with log.path.open("a") as handle:
        handle.write('{"seq": 4, "truncated')

    assert first_problem(log, key) == (4, "line is not valid JSON")


def test_truncation_passes_the_chain_but_fails_a_kept_receipt(
    log: AuditLog, key: Ed25519PrivateKey
) -> None:
    records = read(log)
    receipt_seq, receipt_hash = records[3]["seq"], records[3]["hash"]
    rewrite(log, records[:2])
    truncated = read(log)

    # This is the known limit of a hash chain on its own...
    assert verify_chain(truncated, key.public_key()).ok
    # ...and the reason every API response carries a receipt.
    problem = receipt_problem(truncated, receipt_seq, receipt_hash)
    assert problem is not None and "truncated" in problem


def test_a_reopened_log_continues_the_same_chain(
    tmp_path: Path, log: AuditLog, key: Ed25519PrivateKey
) -> None:
    reopened = AuditLog(log.path, key)
    reopened.append("note", "later", {})

    records = read(reopened)
    assert records[4]["seq"] == 4
    assert records[4]["prev_hash"] == records[3]["hash"]
    assert verify_chain(records, key.public_key()).ok


def test_a_tampered_log_cannot_be_opened_for_writing(log: AuditLog, key: Ed25519PrivateKey) -> None:
    records = read(log)
    records[2]["body"]["n"] = 7
    rewrite(log, records)

    with pytest.raises(AuditIntegrityError, match="record 2"):
        AuditLog(log.path, key)


def test_a_decision_without_an_outcome_is_reported_as_interrupted(
    tmp_path: Path, key: Ed25519PrivateKey
) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", key)
    log.append("decision", "done", {})
    log.append("outcome", "done", {})
    log.append("decision", "crashed-mid-flight", {})

    report = verify_chain(read(log), key.public_key())

    assert report.ok
    assert report.incomplete == ["crashed-mid-flight"]


def test_an_outcome_without_a_decision_breaks_verification(
    tmp_path: Path, key: Ed25519PrivateKey
) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", key)
    log.append("outcome", "orphan", {})

    assert first_problem(log, key) == (0, "outcome without a decision")


def test_a_request_ends_with_an_outcome_or_an_error(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", key)
    for event in ("received", "detection", "decision", "model_call", "outcome"):
        log.append(event, "answered", {})
    for event in ("received", "detection", "error"):
        log.append(event, "failed", {})
    log.append("received", "crashed-during-detection", {})
    # Logs written before `received` existed start a request with its decision.
    log.append("decision", "older-format", {})

    report = verify_chain(read(log), key.public_key())

    assert report.ok
    assert report.incomplete == ["crashed-during-detection", "older-format"]


@pytest.mark.parametrize(
    ("events", "problem"),
    [
        (["detection"], "detection without a received record"),
        (["model_call"], "model_call without a received record"),
        (["error"], "error without a received record"),
        (["received", "received"], "second received for one audit_id"),
        (["received", "decision", "decision"], "second decision for one audit_id"),
        (["received", "outcome"], "outcome without a decision"),
        (["received", "decision", "error", "outcome"], "outcome without a decision"),
    ],
)
def test_a_request_record_out_of_order_breaks_verification(
    tmp_path: Path, key: Ed25519PrivateKey, events: list[str], problem: str
) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", key)
    for event in events:
        log.append(event, "request", {})

    assert first_problem(log, key) == (len(events) - 1, problem)


def test_findings_from_older_records_with_a_value_hash_still_read_back() -> None:
    # Records written before value_hmac was dropped must keep replaying.
    older = {
        "detectors": [{"name": "presidio", "version": "x", "ok": True, "error": None}],
        "findings": [
            {
                "entity_type": "PERSON",
                "start": 33,
                "end": 42,
                "score": 0.85,
                "detector": "presidio",
                "recognizer": "SpacyRecognizer",
                "value_hmac": "3ee1ed75" * 8,
            }
        ],
    }

    (finding,) = signals_from_evidence(older).findings

    assert (finding.entity_type, finding.start, finding.end) == ("PERSON", 33, 42)
    assert finding.score == 0.85


def test_keyed_hash_depends_on_the_key() -> None:
    assert keyed_hash(b"a" * 32, SSN) != keyed_hash(b"b" * 32, SSN)
    assert keyed_hash(b"a" * 32, SSN) == keyed_hash(b"a" * 32, SSN)


# ---------------------------------------------------------------- replay, end to end


def test_every_decision_replays_from_evidence_alone(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    for prompt in (
        "What is a hash chain?",
        f"Email {EMAIL} about the meeting with {PERSON}.",
        f"My SSN is {SSN}.",
        "password = S3cretValue!",
    ):
        harness.plane.handle(prompt)

    report = harness.verify()

    assert report.ok
    assert report.replayed == 4
    assert report.incomplete == []


def test_replay_catches_a_decision_that_does_not_follow_from_its_signals(
    make_harness: HarnessFactory,
) -> None:
    # An insider who holds the signing key rewrites "block" to "allow" and re-signs
    # everything. The chain verifies, but the action no longer follows from the
    # recorded signals and policy.
    harness = make_harness()
    harness.plane.handle("password = S3cretValue!")
    signing_key = load_or_create_signing_key(harness.data_dir / "keys")
    records: list[dict[str, Any]] = [
        json.loads(line) for line in harness.audit.path.read_text().splitlines()
    ]
    prev = GENESIS_HASH
    for record in records:
        if record["event"] == "decision":
            record["body"]["decision"]["action"] = "allow"
        record["prev_hash"] = prev
        record["hash"] = prev = record_digest(record)
        record["sig"] = sign_digest(signing_key, record["hash"])
    harness.audit.path.write_text("".join(json.dumps(r) + "\n" for r in records))

    report = harness.verify()

    assert not report.chain_problems
    assert [p.reason for p in report.replay_problems] == [
        "decision replays as block (block-secrets), recorded allow (block-secrets)"
    ]


def test_replay_detects_a_modified_policy_snapshot(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    result = harness.plane.handle("hello")
    assert result.policy is not None
    snapshot = harness.data_dir / "policies" / f"{result.policy.sha256}.yaml"
    snapshot.write_text(snapshot.read_text().replace("action: block", "action: allow"))

    report = harness.verify()

    assert not report.ok
    assert "was modified" in report.replay_problems[0].reason


def test_verifier_command_line(
    make_harness: HarnessFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = make_harness()
    result = harness.plane.handle("hello")
    receipt = f"{result.outcome_receipt.seq}:{result.outcome_receipt.hash}"

    assert verify_main(["--data-dir", str(harness.data_dir), "--receipt", receipt]) == 0
    assert "RESULT: OK" in capsys.readouterr().out

    wrong = f"{result.outcome_receipt.seq}:{'0' * 64}"
    assert verify_main(["--data-dir", str(harness.data_dir), "--receipt", wrong]) == 1
    assert "RECEIPT MISMATCH" in capsys.readouterr().out
