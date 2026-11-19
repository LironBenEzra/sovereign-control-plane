"""The policy: one YAML file, validated on load, evaluated by a pure function.

`decide` takes a classification and a policy and returns a decision. It reads no clock,
no randomness and no model, so the same classification and policy always give the same
decision, and the audit verifier can replay it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from control_plane.models import Action, Classification, Decision, Label

DEFAULT_RULE_ID = "default"
DETECTION_FAILED_GUARD_ID = "guard:detection-failed"

_EXTERNAL_ACTIONS = frozenset({Action.ALLOW, Action.REDACT})


class PolicyError(Exception):
    """The policy file is missing, unreadable or invalid."""


class _Strict(BaseModel):
    # A typo in a policy key must be an error, not a silently ignored setting.
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuleCondition(_Strict):
    """A rule matches when every condition it states holds. No conditions: always matches."""

    any_category: tuple[str, ...] = ()
    label: tuple[Label, ...] = ()


class Rule(_Strict):
    id: str = Field(min_length=1)
    description: str = ""
    when: RuleCondition = RuleCondition()
    action: Action


class DetectionThresholds(_Strict):
    # Findings below `min_score` are ignored as noise.
    min_score: float = Field(ge=0.0, le=1.0)
    # A finding at or above `confident_score` is positive evidence. If every counted
    # finding is below it, the classification is `uncertain`.
    confident_score: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.confident_score < self.min_score:
            raise ValueError("confident_score must be greater than or equal to min_score")
        return self


class EgressRules(_Strict):
    # Default deny: an empty list means nothing may leave the boundary.
    allowed_destinations: tuple[str, ...] = ()


class ResponseRules(_Strict):
    # Categories removed from a model's output before it is returned.
    redact_categories: tuple[str, ...] = ()
    # After a `redact` action, put the original values back into the model's answer.
    # This happens inside the boundary; the external model only ever saw placeholders.
    restore_placeholders: bool = True


class PolicyDocument(_Strict):
    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = ""
    # category -> entity types. This is the definition of "private data" for this deployment.
    categories: dict[str, tuple[str, ...]]
    detection: DetectionThresholds
    rules: tuple[Rule, ...]
    default_action: Action = Action.BLOCK
    egress: EgressRules = EgressRules()
    response: ResponseRules = ResponseRules()
    block_message: str = "This request was blocked by the data protection policy."

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        rule_ids = [rule.id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule ids must be unique")

        seen: dict[str, str] = {}
        for category, entity_types in self.categories.items():
            for entity_type in entity_types:
                if entity_type in seen:
                    raise ValueError(
                        f"entity type {entity_type} is mapped to both "
                        f"{seen[entity_type]} and {category}"
                    )
                seen[entity_type] = category

        known = set(self.categories)
        referenced = {c for rule in self.rules for c in rule.when.any_category}
        referenced |= set(self.response.redact_categories)
        if unknown := sorted(referenced - known):
            # A misspelled category would never match, which fails open.
            raise ValueError(f"unknown categories referenced: {', '.join(unknown)}")

        if self.default_action in _EXTERNAL_ACTIONS:
            raise ValueError("default_action must be block or route_sovereign")
        return self


@dataclass(frozen=True)
class Policy:
    document: PolicyDocument
    sha256: str
    raw: bytes

    @property
    def entity_types(self) -> tuple[str, ...]:
        return tuple(sorted(e for types in self.document.categories.values() for e in types))

    def category_of(self, entity_type: str) -> str | None:
        for category, entity_types in self.document.categories.items():
            if entity_type in entity_types:
                return category
        return None


def parse_policy(raw: bytes) -> Policy:
    try:
        data = yaml.safe_load(raw)
        document = PolicyDocument.model_validate(data)
    except (yaml.YAMLError, ValidationError) as exc:
        raise PolicyError(f"invalid policy: {exc}") from exc
    return Policy(document=document, sha256=hashlib.sha256(raw).hexdigest(), raw=raw)


def _matches(condition: RuleCondition, classification: Classification) -> bool:
    if condition.label and classification.label not in condition.label:
        return False
    return not condition.any_category or bool(
        set(condition.any_category) & set(classification.categories)
    )


def decide(classification: Classification, policy: Policy) -> Decision:
    """Return the first matching rule's action, or the default. Pure function."""
    unsure = classification.label in (Label.UNCERTAIN, Label.UNKNOWN_ASSUME_PRIVATE)
    document = policy.document

    for rule in document.rules:
        if not _matches(rule.when, classification):
            continue
        if (
            classification.label is Label.UNKNOWN_ASSUME_PRIVATE
            and rule.action in _EXTERNAL_ACTIONS
        ):
            # The one invariant a policy cannot override: when detection failed,
            # redaction cannot be trusted and nothing may leave the boundary.
            return Decision(
                action=document.default_action,
                rule_id=DETECTION_FAILED_GUARD_ID,
                rationale=(
                    f"Rule '{rule.id}' would send the prompt outside the boundary, but "
                    "detection failed, so the default action applies instead."
                ),
                fail_closed=True,
            )
        return Decision(
            action=rule.action,
            rule_id=rule.id,
            rationale=rule.description or f"Rule '{rule.id}' matched.",
            fail_closed=unsure,
        )

    return Decision(
        action=document.default_action,
        rule_id=DEFAULT_RULE_ID,
        rationale="No rule matched, so the default action applies.",
        fail_closed=True,
    )


class PolicyStore:
    """Loads the policy file and keeps an immutable snapshot of every version seen.

    The file is re-read on every call. It is small, and this means an edit takes effect
    on the next request with no reload step to forget.
    """

    def __init__(self, path: Path, snapshot_dir: Path) -> None:
        self._path = path
        self._snapshot_dir = snapshot_dir
        self._cached: Policy | None = None

    def current(self) -> Policy:
        try:
            raw = self._path.read_bytes()
        except OSError as exc:
            raise PolicyError(f"cannot read policy file: {type(exc).__name__}") from exc

        sha256 = hashlib.sha256(raw).hexdigest()
        if self._cached is not None and self._cached.sha256 == sha256:
            return self._cached

        policy = parse_policy(raw)
        self._snapshot(policy)
        self._cached = policy
        return policy

    def _snapshot(self, policy: Policy) -> None:
        # Content-addressed, so evidence can name the exact policy text it was decided under.
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)
        target = self._snapshot_dir / f"{policy.sha256}.yaml"
        if not target.exists():
            target.write_bytes(policy.raw)
