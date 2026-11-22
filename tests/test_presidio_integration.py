"""The real detectors and the shipped policy, end to end. Needs the spaCy model."""

from __future__ import annotations

import pytest

from control_plane.classification import classify
from control_plane.detection.base import DetectorRunner
from control_plane.detection.presidio import PresidioDetector
from control_plane.detection.rules import RuleDetector
from control_plane.models import Action
from control_plane.policy import Policy, decide

pytestmark = pytest.mark.presidio

SPACY_MODEL = "en_core_web_md"


@pytest.fixture(scope="module")
def runner() -> DetectorRunner:
    pytest.importorskip(SPACY_MODEL, reason="spaCy model is not installed")
    return DetectorRunner([RuleDetector(), PresidioDetector(SPACY_MODEL)], timeout_s=30)


@pytest.mark.parametrize(
    ("prompt", "action", "entity_types"),
    [
        ("Explain what a hash chain is in two sentences.", Action.ALLOW, set()),
        (
            "Write a short reply to Dana Levi at dana.levi@example.com about Tuesday.",
            Action.REDACT,
            {"PERSON", "EMAIL_ADDRESS"},
        ),
        (
            "My SSN is 536-90-4399, which tax forms do I need?",
            Action.ROUTE_SOVEREIGN,
            {"US_SSN"},
        ),
        ("Call me on 212-555-0123 tomorrow.", Action.ROUTE_SOVEREIGN, {"PHONE_NUMBER"}),
        (
            "Why does this fail? AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            Action.BLOCK,
            {"AWS_ACCESS_KEY"},
        ),
    ],
)
def test_shipped_policy_with_real_detectors(
    runner: DetectorRunner,
    default_policy: Policy,
    prompt: str,
    action: Action,
    entity_types: set[str],
) -> None:
    signals = runner.run(prompt, default_policy.entity_types)
    classification = classify(signals, default_policy)

    assert all(run.ok for run in signals.detectors)
    assert entity_types <= {f.entity_type for f in classification.counted}
    assert decide(classification, default_policy).action is action
