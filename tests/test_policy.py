from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from control_plane.models import Action, Classification, Label
from control_plane.policy import (
    DEFAULT_RULE_ID,
    DETECTION_FAILED_GUARD_ID,
    Policy,
    PolicyError,
    PolicyStore,
    decide,
    parse_policy,
)
from tests.conftest import DEFAULT_POLICY_PATH


def classification(label: Label, *categories: str) -> Classification:
    return Classification(
        label=label, categories=tuple(sorted(categories)), counted=(), rationale=""
    )


def policy_with(**changes: object) -> Policy:
    data = yaml.safe_load(DEFAULT_POLICY_PATH.read_text())
    data.update(changes)
    return parse_policy(yaml.safe_dump(data).encode())


@pytest.mark.parametrize(
    ("label", "categories", "action", "rule_id"),
    [
        (Label.NO_PRIVATE_DATA, (), Action.ALLOW, "allow-clean"),
        (Label.CONTAINS_PRIVATE_DATA, ("pii",), Action.REDACT, "redact-pii"),
        (Label.CONTAINS_PRIVATE_DATA, ("secret",), Action.BLOCK, "block-secrets"),
        (
            Label.CONTAINS_PRIVATE_DATA,
            ("government_id",),
            Action.ROUTE_SOVEREIGN,
            "keep-regulated-in-boundary",
        ),
        (Label.UNCERTAIN, ("pii",), Action.ROUTE_SOVEREIGN, "protect-when-unsure"),
        (Label.UNKNOWN_ASSUME_PRIVATE, (), Action.ROUTE_SOVEREIGN, "protect-when-unsure"),
    ],
)
def test_default_policy_decisions(
    default_policy: Policy, label: Label, categories: tuple[str, ...], action: Action, rule_id: str
) -> None:
    decision = decide(classification(label, *categories), default_policy)

    assert (decision.action, decision.rule_id) == (action, rule_id)


def test_first_matching_rule_wins(default_policy: Policy) -> None:
    # A secret next to PII must be blocked, not redacted: block-secrets comes first.
    decision = decide(classification(Label.CONTAINS_PRIVATE_DATA, "pii", "secret"), default_policy)

    assert decision.rule_id == "block-secrets"


def test_no_matching_rule_falls_back_to_default_block() -> None:
    policy = policy_with(rules=[])

    decision = decide(classification(Label.NO_PRIVATE_DATA), policy)

    assert (decision.action, decision.rule_id) == (Action.BLOCK, DEFAULT_RULE_ID)
    assert decision.fail_closed


def test_same_input_and_policy_always_give_the_same_decision(default_policy: Policy) -> None:
    subject = classification(Label.CONTAINS_PRIVATE_DATA, "pii", "financial")

    decisions = {decide(subject, default_policy) for _ in range(200)}

    assert len(decisions) == 1


def test_detection_failure_can_never_leave_the_boundary() -> None:
    # A policy that tries to allow everything, including when detection failed.
    policy = policy_with(rules=[{"id": "allow-all", "action": "allow"}])

    decision = decide(classification(Label.UNKNOWN_ASSUME_PRIVATE), policy)

    assert decision.action is Action.BLOCK
    assert decision.rule_id == DETECTION_FAILED_GUARD_ID
    assert decision.fail_closed


def test_a_rule_that_sends_uncertain_prompts_out_is_not_labelled_fail_closed() -> None:
    policy = policy_with(rules=[{"id": "allow-all", "action": "allow"}])

    decision = decide(classification(Label.UNCERTAIN, "pii"), policy)

    assert decision.action is Action.ALLOW
    assert not decision.fail_closed


@pytest.mark.parametrize(
    "broken",
    [
        {"unknown_key": 1},
        {"default_action": "allow"},
        {"default_action": "redact"},
        {"rules": [{"id": "r", "action": "allow", "when": {"any_category": ["typo"]}}]},
        {"rules": [{"id": "r", "action": "allow"}, {"id": "r", "action": "block"}]},
        {"rules": [{"id": "r", "action": "explode"}]},
        {"categories": {"a": ["PERSON"], "b": ["PERSON"]}, "rules": [], "response": {}},
        {"detection": {"min_score": 0.8, "confident_score": 0.2}},
        {"response": {"redact_categories": ["typo"]}},
    ],
)
def test_invalid_policies_are_rejected(broken: dict[str, object]) -> None:
    with pytest.raises(PolicyError):
        policy_with(**broken)


def test_malformed_yaml_is_a_policy_error() -> None:
    with pytest.raises(PolicyError):
        parse_policy(b"id: [unclosed")


def test_store_snapshots_each_version_and_picks_up_edits(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(DEFAULT_POLICY_PATH.read_text())
    store = PolicyStore(path, tmp_path / "snapshots")

    first = store.current()
    path.write_text(DEFAULT_POLICY_PATH.read_text().replace('version: "1.0.0"', 'version: "1.0.1"'))
    second = store.current()

    assert first.sha256 != second.sha256
    assert second.document.version == "1.0.1"
    for policy in (first, second):
        assert (tmp_path / "snapshots" / f"{policy.sha256}.yaml").read_bytes() == policy.raw


def test_store_raises_when_the_file_is_missing_or_broken(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    store = PolicyStore(path, tmp_path / "snapshots")

    with pytest.raises(PolicyError):
        store.current()

    path.write_text("not: a policy")
    with pytest.raises(PolicyError):
        store.current()
