from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
import yaml

from control_plane.models import Action, Classification, Label
from control_plane.policy import (
    DEFAULT_RULE_ID,
    DETECTION_FAILED_GUARD_ID,
    Policy,
    PolicyDocument,
    PolicyError,
    PolicyStore,
    decide,
    describe_changes,
    parse_policy,
    policy_from_document,
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


def test_store_starts_from_the_default_and_later_edits_to_the_file_change_nothing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(DEFAULT_POLICY_PATH.read_text())
    store = PolicyStore(path, tmp_path / "policies")

    first = store.current()
    path.write_text(re.sub(r'^version: ".*"$', 'version: "9.9.9"', path.read_text(), flags=re.M))

    # The store, not the file, holds the policy in force. The file is only the default.
    assert store.current() == first
    assert store.active_sha256() == first.sha256
    assert (tmp_path / "policies" / f"{first.sha256}.yaml").read_bytes() == first.raw
    assert store.default().document.version == "9.9.9"


def test_store_fails_closed_when_the_version_in_force_is_damaged(tmp_path: Path) -> None:
    store = PolicyStore(DEFAULT_POLICY_PATH, tmp_path / "policies")
    policy = store.current()
    snapshot = tmp_path / "policies" / f"{policy.sha256}.yaml"
    snapshot.write_text(DEFAULT_POLICY_PATH.read_text().replace("action: block", "action: allow"))

    with pytest.raises(PolicyError, match="modified on disk"):
        store.current()

    store.save_snapshot(policy)  # saving that version again repairs it
    assert store.current().sha256 == policy.sha256


def test_store_raises_when_the_default_is_missing_or_broken(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    store = PolicyStore(path, tmp_path / "snapshots")

    with pytest.raises(PolicyError):
        store.current()

    path.write_text("not: a policy")
    with pytest.raises(PolicyError):
        store.current()


def test_a_policy_saved_from_the_editor_reads_back_as_the_same_document(
    default_policy: Policy,
) -> None:
    saved = policy_from_document(default_policy.document)

    assert parse_policy(saved.raw).document == default_policy.document
    assert saved.sha256 == hashlib.sha256(saved.raw).hexdigest()


@pytest.mark.parametrize("rule_id", ["default", "Block Secrets", "guard:mine", "", "a" * 65])
def test_a_rule_cannot_take_a_reserved_or_malformed_id(rule_id: str) -> None:
    data = yaml.safe_load(DEFAULT_POLICY_PATH.read_text())
    data["rules"][0]["id"] = rule_id

    with pytest.raises(PolicyError):
        parse_policy(yaml.safe_dump(data).encode())


def test_each_change_is_described_in_one_sentence(default_policy: Policy) -> None:
    data = default_policy.document.model_dump(mode="json")
    for rule in data["rules"]:
        if rule["id"] == "allow-clean":
            rule["action"] = "route_sovereign"
    data["rules"] = [rule for rule in data["rules"] if rule["id"] != "redact-pii"]
    data["rules"].insert(
        0, {"id": "block-health", "when": {"any_category": ["health"]}, "action": "block"}
    )
    data["categories"]["pii"].append("LOCATION")
    data["detection"]["min_score"] = 0.5
    data["egress"]["allowed_destinations"] = []

    changes = describe_changes(default_policy.document, PolicyDocument.model_validate(data))

    assert changes == [
        "Entity type in pii added: LOCATION.",
        "Detection min score changed from 0.35 to 0.5.",
        "Added rule block-health at position 1: category health, block.",
        "Removed rule redact-pii.",
        "Rule allow-clean: action changed from allow to route_sovereign.",
        "Allowed destination removed: anthropic.",
    ]


def test_moving_a_rule_is_a_change(default_policy: Policy) -> None:
    data = default_policy.document.model_dump(mode="json")
    data["rules"].append(data["rules"].pop(0))

    (change,) = describe_changes(default_policy.document, PolicyDocument.model_validate(data))

    assert change.startswith("Rule order changed to: block-prompt-injection,")
    assert change.endswith("allow-clean, block-secrets.")
