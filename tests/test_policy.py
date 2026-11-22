from __future__ import annotations

import re
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
    credential_leaks,
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
        (Label.UNKNOWN_ASSUME_PRIVATE, (), Action.BLOCK, "block-when-detection-failed"),
        (
            Label.UNKNOWN_ASSUME_PRIVATE,
            ("government_id",),
            Action.BLOCK,
            "block-when-detection-failed",
        ),
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


def test_detection_failure_can_never_leave_the_boundary() -> None:
    # A policy that tries to allow everything, including when detection failed.
    policy = policy_with(rules=[{"id": "allow-all", "action": "allow"}])

    decision = decide(classification(Label.UNKNOWN_ASSUME_PRIVATE), policy)

    assert decision.action is Action.BLOCK
    assert decision.rule_id == DETECTION_FAILED_GUARD_ID
    assert decision.fail_closed


@pytest.mark.parametrize(
    "broken",
    [
        # The fallback must fail closed.
        {"default_action": "allow"},
        # A typo in a category would make the rule silently never match.
        {"rules": [{"id": "r", "action": "allow", "when": {"any_category": ["typo"]}}]},
        # The audit log names the rule that decided, so ids must be unique.
        {"rules": [{"id": "r", "action": "allow"}, {"id": "r", "action": "block"}]},
    ],
)
def test_invalid_policies_are_rejected(broken: dict[str, object]) -> None:
    with pytest.raises(PolicyError):
        policy_with(**broken)


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


def first_rule_as(action: str) -> Policy:
    """The shipped policy with its first rule, block-secrets, given another action."""
    rules = yaml.safe_load(DEFAULT_POLICY_PATH.read_text())["rules"]
    rules[0]["action"] = action
    return policy_with(rules=rules)


def test_a_rule_that_would_send_credentials_out_unchanged_is_named() -> None:
    assert credential_leaks(first_rule_as("allow").document) == [
        (
            "rules.0.action",
            "block-secrets would send prompts with secret data out unchanged, and secret "
            "holds credentials (API_KEY, AWS_ACCESS_KEY, CONNECTION_STRING, "
            "CREDENTIAL_ASSIGNMENT, GITHUB_TOKEN, JWT, PRIVATE_KEY, SLACK_TOKEN). Choose "
            "block, route_sovereign or redact.",
        )
    ]


def test_a_credential_counts_whatever_its_category_is_called() -> None:
    data = yaml.safe_load(DEFAULT_POLICY_PATH.read_text())
    data["categories"]["secret"].remove("AWS_ACCESS_KEY")
    data["categories"]["deploy_keys"] = ["AWS_ACCESS_KEY"]
    data["rules"].insert(
        0, {"id": "allow-deploy-keys", "action": "allow", "when": {"any_category": ["deploy_keys"]}}
    )

    leaks = credential_leaks(parse_policy(yaml.safe_dump(data).encode()).document)

    assert [path for path, _ in leaks] == ["rules.0.action"]


def test_a_default_that_would_send_credentials_out_is_never_put_in_force(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_bytes(first_rule_as("allow").raw)
    store = PolicyStore(path, tmp_path / "snapshots")

    with pytest.raises(PolicyError, match="the default policy is refused: block-secrets"):
        store.current()
    assert store.active_sha256() is None
