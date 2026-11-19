"""The pipeline end to end, with fakes only at the detector and model boundaries."""

from __future__ import annotations

import hashlib

import pytest

from control_plane.audit.chain import INVALID_REQUEST_RULE_ID, POLICY_UNAVAILABLE_RULE_ID
from control_plane.detection.rules import RuleDetector
from control_plane.models import Action, Label, OutcomeStatus
from control_plane.pipeline import EvidenceUnavailableError, normalize_prompt
from tests.conftest import (
    AWS_KEY,
    DEFAULT_POLICY_PATH,
    EMAIL,
    PERSON,
    SSN,
    WEAK_PHONE,
    FakeProvider,
    HarnessFactory,
    KeywordDetector,
)

CLEAN = "Explain what a hash chain is in two sentences."
PII = f"Write a short reply to {PERSON} at {EMAIL}."
SECRET = f"Why does this fail? aws_key={AWS_KEY}"
REGULATED = f"My SSN is {SSN}, what tax forms do I need?"


# ---------------------------------------------------------------- the four actions


def test_clean_prompt_is_allowed_to_the_external_model(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    result = harness.plane.handle(CLEAN)

    assert result.decision.action is Action.ALLOW
    assert result.classification.label is Label.NO_PRIVATE_DATA
    assert result.status is OutcomeStatus.COMPLETED
    assert harness.external.prompts == [CLEAN]
    assert harness.sovereign.prompts == []
    assert result.response == f"echo: {CLEAN}"


def test_pii_is_redacted_before_egress_and_restored_in_the_answer(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness()

    result = harness.plane.handle(PII)

    assert result.decision.action is Action.REDACT
    (sent,) = harness.external.prompts
    assert sent == "Write a short reply to <PERSON_1> at <EMAIL_ADDRESS_1>."
    assert EMAIL not in sent and PERSON not in sent
    assert result.forwarded_prompt == sent
    # The caller, inside the boundary, gets the real values back.
    assert result.response == f"echo: {PII}"


def test_a_secret_is_blocked_and_no_model_is_called(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    result = harness.plane.handle(SECRET)

    assert result.decision.action is Action.BLOCK
    assert result.decision.rule_id == "block-secrets"
    assert result.status is OutcomeStatus.BLOCKED
    assert result.model is None
    assert harness.external.prompts == harness.sovereign.prompts == []


def test_regulated_data_goes_to_the_sovereign_model_unredacted(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness()

    result = harness.plane.handle(REGULATED)

    assert result.decision.action is Action.ROUTE_SOVEREIGN
    assert harness.sovereign.prompts == [REGULATED]
    assert harness.external.prompts == []
    assert result.model is not None and result.model.in_boundary


# ---------------------------------------------------------------- fail closed


def test_detector_failure_keeps_the_prompt_inside(make_harness: HarnessFactory) -> None:
    broken = KeywordDetector(name="presidio", error=RuntimeError("model crashed"))
    harness = make_harness(detectors=[RuleDetector(), broken])

    result = harness.plane.handle(CLEAN)

    assert result.classification.label is Label.UNKNOWN_ASSUME_PRIVATE
    assert result.decision.action is Action.ROUTE_SOVEREIGN
    assert result.decision.fail_closed
    assert harness.external.prompts == []


def test_detector_timeout_keeps_the_prompt_inside(make_harness: HarnessFactory) -> None:
    harness = make_harness(detectors=[KeywordDetector(delay_s=1.0)], detection_timeout_s=0.05)

    result = harness.plane.handle(CLEAN)

    assert result.classification.label is Label.UNKNOWN_ASSUME_PRIVATE
    assert harness.external.prompts == []


def test_low_confidence_evidence_is_treated_as_private(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    result = harness.plane.handle(f"Is {WEAK_PHONE} a valid thing?")

    assert result.classification.label is Label.UNCERTAIN
    assert result.decision.action is Action.ROUTE_SOVEREIGN
    assert harness.external.prompts == []


@pytest.mark.parametrize("policy_text", ["", "id: broken\nrules: nonsense\n", "{{not yaml"])
def test_an_invalid_policy_blocks_everything(
    make_harness: HarnessFactory, policy_text: str
) -> None:
    harness = make_harness(policy_text=policy_text)

    result = harness.plane.handle(CLEAN)

    assert result.decision.action is Action.BLOCK
    assert result.decision.rule_id == POLICY_UNAVAILABLE_RULE_ID
    assert result.policy is None
    assert harness.external.prompts == harness.sovereign.prompts == []
    assert harness.verify().ok


def test_a_missing_policy_file_blocks_everything(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    harness.policy_path.unlink()

    assert harness.plane.handle(CLEAN).decision.rule_id == POLICY_UNAVAILABLE_RULE_ID
    assert harness.external.prompts == []


def test_no_matching_rule_blocks(make_harness: HarnessFactory) -> None:
    text = DEFAULT_POLICY_PATH.read_text()
    without_allow = (
        text[: text.index("  - id: allow-clean")] + text[text.index("# Applies when no") :]
    )
    harness = make_harness(policy_text=without_allow)

    result = harness.plane.handle(CLEAN)

    assert (result.decision.action, result.decision.rule_id) == (Action.BLOCK, "default")
    assert harness.external.prompts == []


def test_no_decision_record_means_no_model_call(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    harness.plane.handle(CLEAN)  # loads the policy, so only the decision write fails next
    harness.audit.fail_on = frozenset({"decision"})

    with pytest.raises(EvidenceUnavailableError) as raised:
        harness.plane.handle(CLEAN)

    assert raised.value.stage == "decision"
    assert len(harness.external.prompts) == 1  # only the first, successful request


def test_no_outcome_record_means_the_answer_is_withheld(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    harness.audit.fail_on = frozenset({"outcome"})

    with pytest.raises(EvidenceUnavailableError) as raised:
        harness.plane.handle(CLEAN)

    assert raised.value.stage == "outcome"
    # The interrupted request is visible to a reviewer: a decision with no outcome.
    assert harness.verify().incomplete == [raised.value.audit_id]


def test_sovereign_model_down_blocks_and_never_falls_back_outside(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness(sovereign=FakeProvider("ollama", in_boundary=True, error="connection"))

    result = harness.plane.handle(REGULATED)

    assert result.decision.action is Action.ROUTE_SOVEREIGN
    assert result.status is OutcomeStatus.BLOCKED
    assert result.reason == "sovereign_model_unavailable:connection"
    assert harness.external.prompts == []
    assert result.response is not None and SSN not in result.response


def test_a_destination_missing_from_the_allowlist_is_refused(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness(external=FakeProvider("some-other-cloud", in_boundary=False))

    result = harness.plane.handle(CLEAN)

    assert result.decision.action is Action.ALLOW
    assert result.status is OutcomeStatus.BLOCKED
    assert result.reason == "egress_denied:destination_not_allowlisted"
    assert harness.external.prompts == []
    (outcome,) = harness.records("outcome")
    assert outcome["body"]["egress"] == {
        "destination": "some-other-cloud",
        "payload_sha256": hashlib.sha256(CLEAN.encode()).hexdigest(),
        "payload_chars": len(CLEAN),
        "allowed": False,
        "attempted": False,
    }


def test_external_model_failure_is_recorded_as_an_attempted_egress(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness(external=FakeProvider("anthropic", in_boundary=False, error="timeout"))

    result = harness.plane.handle(CLEAN)

    assert result.status is OutcomeStatus.FAILED
    assert result.response is None
    (outcome,) = harness.records("outcome")
    # The request may have left before the timeout, and the evidence says so.
    assert outcome["body"]["egress"]["attempted"] is True
    assert outcome["body"]["model"]["error"] == "timeout"


def test_a_failed_output_scan_withholds_the_answer(make_harness: HarnessFactory) -> None:
    detector = KeywordDetector()
    harness = make_harness(detectors=[detector])
    original_detect = detector.detect

    def fail_on_model_output(text: str, entity_types: object) -> list:
        if text.startswith("echo:"):
            raise RuntimeError("scanner crashed")
        return original_detect(text, entity_types)  # type: ignore[arg-type]

    detector.detect = fail_on_model_output  # type: ignore[method-assign]

    result = harness.plane.handle(CLEAN)

    assert result.status is OutcomeStatus.WITHHELD
    assert result.response is None


def test_secrets_in_a_model_answer_are_removed(make_harness: HarnessFactory) -> None:
    leaky = FakeProvider("anthropic", in_boundary=False, reply=f"Try this key: {AWS_KEY}")
    harness = make_harness(external=leaky)

    result = harness.plane.handle(CLEAN)

    assert result.response == "Try this key: <AWS_ACCESS_KEY_1>"
    (outcome,) = harness.records("outcome")
    assert outcome["body"]["response"]["output_redactions"] == {"AWS_ACCESS_KEY": 1}


# ---------------------------------------------------------------- evidence


def test_every_request_leaves_a_decision_and_an_outcome(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    for prompt in (CLEAN, PII, SECRET, REGULATED):
        harness.plane.handle(prompt)

    events = [r["event"] for r in harness.records()]
    assert events == ["policy_loaded"] + ["decision", "outcome"] * 4
    report = harness.verify()
    assert report.ok and report.replayed == 4 and report.incomplete == []


def test_the_audit_log_holds_no_raw_private_values(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    for prompt in (PII, SECRET, REGULATED):
        harness.plane.handle(prompt)

    log_text = harness.log_text()
    for private_value in (EMAIL, PERSON, SSN, AWS_KEY):
        assert private_value not in log_text


def test_the_decision_record_explains_itself(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    result = harness.plane.handle(PII)

    (decision,) = harness.records("decision")
    body = decision["body"]
    assert body["classification"]["label"] == "contains_private_data"
    assert body["classification"]["categories"] == ["pii"]
    assert {f["entity_type"] for f in body["signals"]["findings"]} == {"EMAIL_ADDRESS", "PERSON"}
    assert all(len(f["value_hmac"]) == 64 for f in body["signals"]["findings"])
    assert body["policy"]["sha256"] == hashlib.sha256(harness.policy_path.read_bytes()).hexdigest()
    assert body["decision"] == {
        "action": "redact",
        "rule_id": "redact-pii",
        "rationale": result.decision.rationale,
        "fail_closed": False,
    }


def test_the_outcome_record_says_what_left_the_boundary(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    result = harness.plane.handle(PII)

    (outcome,) = harness.records("outcome")
    body = outcome["body"]
    assert result.forwarded_prompt is not None
    assert body["egress"]["destination"] == "anthropic"
    assert body["egress"]["allowed"] is True and body["egress"]["attempted"] is True
    assert (
        body["egress"]["payload_sha256"]
        == hashlib.sha256(result.forwarded_prompt.encode()).hexdigest()
    )
    assert body["redaction"] == {
        "spans": 2,
        "by_entity": {"EMAIL_ADDRESS": 1, "PERSON": 1},
        "placeholders_restored": 2,
    }
    assert body["model"]["in_boundary"] is False and body["model"]["called"] is True


def test_a_blocked_request_records_that_no_model_was_called(make_harness: HarnessFactory) -> None:
    harness = make_harness()

    harness.plane.handle(SECRET)

    (outcome,) = harness.records("outcome")
    assert outcome["body"]["model"] is None
    assert outcome["body"]["egress"] is None
    assert outcome["body"]["status"] == "blocked"


def test_a_policy_edit_is_recorded_and_takes_effect_on_the_next_request(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness()
    assert harness.plane.handle(CLEAN).decision.action is Action.ALLOW

    stricter = DEFAULT_POLICY_PATH.read_text().replace(
        "    when:\n      label: [no_private_data]\n    action: allow",
        "    when:\n      label: [no_private_data]\n    action: route_sovereign",
    )
    harness.policy_path.write_text(stricter)

    assert harness.plane.handle(CLEAN).decision.action is Action.ROUTE_SOVEREIGN
    loaded = harness.records("policy_loaded")
    assert len(loaded) == 2
    assert loaded[0]["body"]["sha256"] != loaded[1]["body"]["sha256"]
    assert harness.verify().ok


def test_rejected_requests_are_audited_without_their_content(
    make_harness: HarnessFactory,
) -> None:
    harness = make_harness()

    result = harness.plane.reject("body_too_large")

    assert result.decision.rule_id == INVALID_REQUEST_RULE_ID
    assert result.classification.label is Label.INVALID_INPUT
    (decision,) = harness.records("decision")
    assert decision["body"]["request"]["rejected"] == "body_too_large"
    assert decision["body"]["request"]["prompt_hmac"] is None
    assert harness.verify().ok


# ---------------------------------------------------------------- untrusted input


def test_invisible_characters_cannot_hide_a_secret(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    hidden = "pass\u200bword = S3cretValue!"

    result = harness.plane.handle(hidden)

    assert result.decision.action is Action.BLOCK
    (decision,) = harness.records("decision")
    assert decision["body"]["request"]["normalization_changed"] is True


def test_normalization_folds_lookalike_characters() -> None:
    # Fullwidth letters and a zero-width joiner.
    assert normalize_prompt("\uff41\uff42\u200d\uff43") == "abc"
