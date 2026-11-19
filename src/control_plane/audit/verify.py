"""Verify the audit log without the server: chain, signatures, pairing and replay.

Run it as a command:

    python -m control_plane.audit.verify --data-dir data

It needs only the log, the public key and the policy snapshots. It checks that

1. every record's hash matches its content, and links to the record before it;
2. every record is signed by the audit key;
3. every decision has exactly one outcome (a missing outcome is an interrupted request);
4. re-running classification and policy on the recorded signals gives the recorded
   decision. This is what "reconstruct the decision from the evidence alone" means here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from control_plane.audit.chain import (
    BUILTIN_RULE_PREFIX,
    EVENT_DECISION,
    EVENT_OUTCOME,
    GENESIS_HASH,
    HASHED_FIELDS,
    record_digest,
)
from control_plane.audit.keys import PUBLIC_KEY_FILE, load_public_key, signature_is_valid
from control_plane.classification import classify
from control_plane.evidence import signals_from_evidence
from control_plane.policy import PolicyError, decide, parse_policy

_REQUIRED_FIELDS = (*HASHED_FIELDS, "hash", "sig", "key_id")


@dataclass(frozen=True)
class Problem:
    seq: int | None
    reason: str


@dataclass
class Report:
    records: int = 0
    head_seq: int | None = None
    head_hash: str | None = None
    chain_problems: list[Problem] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    replayed: int = 0
    replay_problems: list[Problem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.chain_problems and not self.replay_problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "chain_problems": [vars(p) for p in self.chain_problems],
            "incomplete_requests": self.incomplete,
            "decisions_replayed": self.replayed,
            "replay_problems": [vars(p) for p in self.replay_problems],
        }


def parse_lines(lines: Iterable[str]) -> tuple[list[dict[str, Any]], list[Problem]]:
    records: list[dict[str, Any]] = []
    for number, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return records, [Problem(number, "line is not valid JSON")]
        if not isinstance(record, dict) or any(k not in record for k in _REQUIRED_FIELDS):
            return records, [Problem(number, "record is missing required fields")]
        records.append(record)
    return records, []


def verify_chain(records: Sequence[dict[str, Any]], public_key: Ed25519PublicKey) -> Report:
    """Check hashes, links, signatures and decision/outcome pairing.

    Stops at the first broken record: once the chain is broken, nothing after it
    can be trusted.
    """
    report = Report()
    prev_hash = GENESIS_HASH
    open_decisions: dict[str, int] = {}

    for expected_seq, record in enumerate(records):
        seq = record["seq"]
        if seq != expected_seq:
            report.chain_problems.append(
                Problem(expected_seq, f"expected seq {expected_seq}, found {seq}")
            )
            break
        if record["prev_hash"] != prev_hash:
            report.chain_problems.append(Problem(seq, "prev_hash does not match previous record"))
            break
        if record_digest(record) != record["hash"]:
            report.chain_problems.append(Problem(seq, "content does not match its hash"))
            break
        if not signature_is_valid(public_key, record["hash"], record["sig"]):
            report.chain_problems.append(Problem(seq, "signature is not valid"))
            break

        audit_id = record["audit_id"]
        if record["event"] == EVENT_DECISION:
            if audit_id in open_decisions:
                report.chain_problems.append(Problem(seq, "second decision for one audit_id"))
                break
            open_decisions[audit_id] = seq
        elif record["event"] == EVENT_OUTCOME:
            if audit_id not in open_decisions:
                report.chain_problems.append(Problem(seq, "outcome without a decision"))
                break
            del open_decisions[audit_id]

        prev_hash = record["hash"]
        report.records += 1
        report.head_seq = seq
        report.head_hash = record["hash"]

    report.incomplete = sorted(open_decisions, key=open_decisions.__getitem__)
    return report


def replay_decisions(records: Sequence[dict[str, Any]], policy_dir: Path, report: Report) -> None:
    """Re-run classify and decide on each decision record's signals and compare."""
    for record in records[: report.records]:
        if record["event"] != EVENT_DECISION:
            continue
        problem = _replay_one(record, policy_dir)
        report.replayed += 1
        if problem:
            report.replay_problems.append(Problem(record["seq"], problem))


def _replay_one(record: dict[str, Any], policy_dir: Path) -> str | None:  # noqa: PLR0911
    body = record["body"]
    recorded = body["decision"]

    if recorded["rule_id"].startswith(BUILTIN_RULE_PREFIX):
        return None if recorded["action"] == "block" else "built-in rule did not block"

    sha256 = body["policy"]["sha256"]
    snapshot = policy_dir / f"{sha256}.yaml"
    try:
        raw = snapshot.read_bytes()
    except OSError:
        return f"policy snapshot {sha256[:12]} is missing"
    if hashlib.sha256(raw).hexdigest() != sha256:
        return f"policy snapshot {sha256[:12]} was modified"
    try:
        policy = parse_policy(raw)
    except PolicyError:
        return f"policy snapshot {sha256[:12]} is not a valid policy"

    classification = classify(signals_from_evidence(body["signals"]), policy)
    if classification.label.value != body["classification"]["label"]:
        return (
            f"classification replays as {classification.label.value}, "
            f"recorded {body['classification']['label']}"
        )
    if list(classification.categories) != body["classification"]["categories"]:
        return "categories do not match the recorded signals"

    decision = decide(classification, policy)
    if (decision.action.value, decision.rule_id) != (recorded["action"], recorded["rule_id"]):
        return (
            f"decision replays as {decision.action.value} ({decision.rule_id}), "
            f"recorded {recorded['action']} ({recorded['rule_id']})"
        )
    return None


def verify_log(log_path: Path, public_key: Ed25519PublicKey, policy_dir: Path | None) -> Report:
    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return Report()
    records, parse_problems = parse_lines(lines)
    report = verify_chain(records, public_key)
    report.chain_problems.extend(parse_problems)
    if policy_dir is not None:
        replay_decisions(records, policy_dir, report)
    return report


def receipt_problem(records: Sequence[dict[str, Any]], seq: int, digest: str) -> str | None:
    """Check a receipt a caller kept. Catches truncation and wholesale rewrites."""
    if seq >= len(records):
        return f"record {seq} is not in the log: the log was truncated"
    if records[seq]["hash"] != digest:
        return f"record {seq} has a different hash than the receipt: the log was rewritten"
    return None


def _print_report(report: Report) -> None:
    print(f"records verified : {report.records}")
    if report.head_hash:
        print(f"chain head       : seq {report.head_seq}  {report.head_hash}")
    print(f"decisions replayed: {report.replayed}")
    for problem in report.chain_problems:
        print(f"CHAIN BROKEN at record {problem.seq}: {problem.reason}")
    for problem in report.replay_problems:
        print(f"REPLAY MISMATCH at record {problem.seq}: {problem.reason}")
    for audit_id in report.incomplete:
        print(f"interrupted request (decision without outcome): {audit_id}")
    print("RESULT: " + ("OK - the log is intact" if report.ok else "FAILED"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the control plane's audit log.")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--log", type=Path, help="default: <data-dir>/audit/audit.jsonl")
    parser.add_argument("--public-key", type=Path, help="default: <data-dir>/keys/...pub")
    parser.add_argument("--policies", type=Path, help="default: <data-dir>/policies")
    parser.add_argument(
        "--receipt",
        action="append",
        default=[],
        metavar="SEQ:HASH",
        help="a receipt returned by the API; may be given more than once",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    log_path = args.log or args.data_dir / "audit" / "audit.jsonl"
    public_key = load_public_key(args.public_key or args.data_dir / "keys" / PUBLIC_KEY_FILE)
    report = verify_log(log_path, public_key, args.policies or args.data_dir / "policies")

    receipt_failures: list[str] = []
    if args.receipt:
        records, _ = parse_lines(log_path.read_text(encoding="utf-8").splitlines())
        for receipt in args.receipt:
            seq, _, digest = receipt.partition(":")
            if problem := receipt_problem(records, int(seq), digest):
                receipt_failures.append(problem)

    if args.json:
        print(json.dumps({**report.to_dict(), "receipt_problems": receipt_failures}, indent=2))
    else:
        _print_report(report)
        for failure in receipt_failures:
            print(f"RECEIPT MISMATCH: {failure}")
    return 0 if report.ok and not receipt_failures else 1


if __name__ == "__main__":
    sys.exit(main())
