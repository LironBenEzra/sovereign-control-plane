from __future__ import annotations

import pytest

from control_plane.classification import classify
from control_plane.detection.base import DetectorRunner
from control_plane.detection.rules import CREDENTIAL_TYPES, RULES, RuleDetector
from control_plane.models import DetectorRun, Finding, Label, Signals
from control_plane.policy import Policy
from tests.conftest import AWS_KEY, EMAIL, PERSON, WEAK_PHONE, KeywordDetector

OK = (DetectorRun("fake", "test", ok=True),)


def finding(entity_type: str, score: float) -> Finding:
    return Finding(entity_type, 0, 5, score, "fake", "test")


# ---------------------------------------------------------------- pattern rules


@pytest.mark.parametrize(
    ("text", "entity_type"),
    [
        (f"my key is {AWS_KEY} ok", "AWS_ACCESS_KEY"),
        ("token ghp_" + "a1B2" * 9, "GITHUB_TOKEN"),
        ("use xoxb-123456789012-abcdefghij", "SLACK_TOKEN"),
        ("export KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "API_KEY"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY"),
        (
            "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
            "JWT",
        ),
        ("db is postgres://admin:hunter2pass@db.internal:5432/app", "CONNECTION_STRING"),
        ("password = S3cretValue!", "CREDENTIAL_ASSIGNMENT"),
        ("the patient was diagnosed with diabetes", "HEALTH_CONTEXT"),
        (
            "blob 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "HIGH_ENTROPY_STRING",
        ),
    ],
)
def test_rule_detector_finds(text: str, entity_type: str, default_policy: Policy) -> None:
    findings = RuleDetector().detect(text, default_policy.entity_types)

    assert entity_type in {f.entity_type for f in findings}


@pytest.mark.parametrize(
    "text",
    [
        "What is the capital of France?",
        "Please reset my password, I forgot it.",
        "The token count was 12345678901234567890123456789012 in total.",
    ],
)
def test_rule_detector_ignores_ordinary_text(text: str, default_policy: Policy) -> None:
    assert RuleDetector().detect(text, default_policy.entity_types) == []


def test_every_rule_but_the_health_terms_finds_a_credential() -> None:
    # A new credential rule must be listed too, or a policy could allow its value out.
    assert {rule.entity_type for rule in RULES} - {"HEALTH_CONTEXT"} == CREDENTIAL_TYPES


# ---------------------------------------------------------------- runner


def test_a_failing_detector_does_not_hide_the_others() -> None:
    runner = DetectorRunner(
        [KeywordDetector(), KeywordDetector(name="broken", error=RuntimeError(EMAIL))], 5.0
    )

    signals = runner.run(f"mail {EMAIL}", ["EMAIL_ADDRESS"])

    assert [f.entity_type for f in signals.findings] == ["EMAIL_ADDRESS"]
    failed = next(run for run in signals.detectors if not run.ok)
    # The class name is kept, never the message: messages can contain the prompt.
    assert (failed.name, failed.error) == ("broken", "RuntimeError")


def test_a_slow_detector_times_out_and_is_marked_failed() -> None:
    runner = DetectorRunner([KeywordDetector(delay_s=1.0)], timeout_s=0.05)

    signals = runner.run("anything", ["EMAIL_ADDRESS"])

    assert [(run.ok, run.error) for run in signals.detectors] == [(False, "TimeoutError")]


def test_a_masked_text_detector_reads_the_text_with_the_values_masked() -> None:
    text = f"Ask {PERSON} at {EMAIL} or {WEAK_PHONE} about the launch."
    reader = KeywordDetector({"launch": ("UNRELEASED_PRODUCT", 0.7)}, name="semantic")
    runner = DetectorRunner([KeywordDetector()], 5.0, masked_text_detectors=[reader])

    signals = runner.run(
        text, ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "UNRELEASED_PRODUCT"], mask_min_score=0.5
    )

    # The phone number scores 0.4, below the masking score: a redaction would keep it too.
    assert reader.calls == [
        f"Ask <PERSON_1> at <EMAIL_ADDRESS_1> or {WEAK_PHONE} about the launch."
    ]
    (found,) = (f for f in signals.findings if f.detector == "semantic")
    assert text[found.start : found.end] == "launch"


def test_no_model_reads_the_text_when_a_value_detector_failed() -> None:
    # The failed detector may have missed a value, so the masked text cannot be trusted.
    broken = KeywordDetector(name="presidio", error=RuntimeError())
    reader = KeywordDetector({}, name="semantic")
    runner = DetectorRunner([RuleDetector(), broken], 5.0, masked_text_detectors=[reader])

    runner.run(f"key {AWS_KEY} for {PERSON}", ["AWS_ACCESS_KEY", "PERSON"])

    assert reader.calls == []


# ---------------------------------------------------------------- classification


def test_no_findings_is_no_private_data(default_policy: Policy) -> None:
    result = classify(Signals((), OK), default_policy)

    assert result.label is Label.NO_PRIVATE_DATA
    assert result.categories == ()


def test_a_confident_finding_is_private_data(default_policy: Policy) -> None:
    result = classify(Signals((finding("EMAIL_ADDRESS", 1.0),), OK), default_policy)

    assert result.label is Label.CONTAINS_PRIVATE_DATA
    assert result.categories == ("pii",)
    assert "EMAIL_ADDRESS x1" in result.rationale


def test_only_low_confidence_findings_is_uncertain(default_policy: Policy) -> None:
    result = classify(Signals((finding("PHONE_NUMBER", 0.4),), OK), default_policy)

    assert result.label is Label.UNCERTAIN
    assert result.categories == ("pii",)


def test_low_confidence_findings_still_count_next_to_confident_ones(default_policy: Policy) -> None:
    signals = Signals((finding("EMAIL_ADDRESS", 1.0), finding("US_SSN", 0.4)), OK)

    result = classify(signals, default_policy)

    # The weak SSN must still pull the prompt into the regulated category.
    assert result.label is Label.CONTAINS_PRIVATE_DATA
    assert result.categories == ("government_id", "pii")


def test_a_failed_detector_means_unknown_even_with_other_findings(default_policy: Policy) -> None:
    runs = (*OK, DetectorRun("presidio", "x", ok=False, error="TimeoutError"))

    result = classify(Signals((finding("EMAIL_ADDRESS", 1.0),), runs), default_policy)

    assert result.label is Label.UNKNOWN_ASSUME_PRIVATE
    assert result.categories == ("pii",)
    assert "presidio" in result.rationale
