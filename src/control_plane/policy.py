"""The policy: a validated document, stored by version, evaluated by a pure function.

`decide` takes a classification and a policy and returns a decision. It reads no clock,
no randomness and no model, so the same classification and policy always give the same
decision, and the audit verifier can replay it.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from control_plane.detection.rules import CREDENTIAL_TYPES
from control_plane.models import Action, Classification, Decision, Label

logger = logging.getLogger(__name__)

DEFAULT_RULE_ID = "default"
DETECTION_FAILED_GUARD_ID = "guard:detection-failed"

_EXTERNAL_ACTIONS = frozenset({Action.ALLOW, Action.REDACT})
_SHA256 = re.compile(r"[0-9a-f]{64}")

# Names are checked because a policy can now be typed into a form. A rule id is shown in
# every decision, so it may not take the name of a decision the system makes itself
# ("default", "guard:...", "builtin:...").
RuleId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
CategoryName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
EntityType = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
ShortText = Annotated[str, StringConstraints(max_length=500)]


class PolicyError(Exception):
    """There is no usable policy: it is missing, unreadable, modified or invalid."""


class _Strict(BaseModel):
    # A typo in a policy key must be an error, not a silently ignored setting.
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuleCondition(_Strict):
    """A rule matches when every condition it states holds. No conditions: always matches."""

    any_category: tuple[CategoryName, ...] = ()
    label: tuple[Label, ...] = ()


class Rule(_Strict):
    id: RuleId
    description: ShortText = ""
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
    allowed_destinations: tuple[Annotated[str, StringConstraints(max_length=64)], ...] = ()


class ResponseRules(_Strict):
    # Categories removed from a model's output before it is returned.
    redact_categories: tuple[CategoryName, ...] = ()
    # After a `redact` action, put the original values back into the model's answer.
    # This happens inside the boundary; the external model only ever saw placeholders.
    restore_placeholders: bool = True


class PolicyDocument(_Strict):
    id: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=32)
    description: ShortText = ""
    # category -> entity types. This is the definition of "private data" for this deployment.
    categories: dict[CategoryName, tuple[EntityType, ...]] = Field(max_length=50)
    detection: DetectionThresholds
    rules: tuple[Rule, ...] = Field(max_length=100)
    default_action: Action = Action.BLOCK
    egress: EgressRules = EgressRules()
    response: ResponseRules = ResponseRules()
    block_message: str = Field(
        default="This request was blocked by the data protection policy.",
        min_length=1,
        max_length=1000,
    )

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        rule_ids = [rule.id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule ids must be unique")
        if DEFAULT_RULE_ID in rule_ids:
            raise ValueError(f"'{DEFAULT_RULE_ID}' is the name of the default action, not a rule")

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


def policy_from_document(document: PolicyDocument) -> Policy:
    """The stored form of a policy edited in the UI: YAML, so a snapshot reads like the default.

    The text is parsed back, so the policy in force is exactly what the snapshot says.
    """
    data = document.model_dump(mode="json")
    raw = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100).encode()
    return parse_policy(raw)


def credential_leaks(document: PolicyDocument) -> list[tuple[str, str]]:
    """Each rule that allows a category holding a credential, as (path, message).

    `allow` sends the prompt out unchanged, so such a rule would send the credential too.
    Checked when a policy is saved, not when one is loaded: a policy saved before this
    check still loads, and the decisions made under it still replay.
    """
    leaks: list[tuple[str, str]] = []
    for index, rule in enumerate(document.rules):
        if rule.action is not Action.ALLOW:
            continue
        for category in rule.when.any_category:
            if held := sorted(set(document.categories.get(category, ())) & CREDENTIAL_TYPES):
                leaks.append(
                    (
                        f"rules.{index}.action",
                        f"{rule.id} would send prompts with {category} data out unchanged, "
                        f"and {category} holds credentials ({', '.join(held)}). Choose block, "
                        "route_sovereign or redact.",
                    )
                )
                break
    return leaks


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
            # A policy may choose to send uncertain prompts out. That is its right,
            # but the evidence must not label it as a protective decision.
            fail_closed=unsure and rule.action not in _EXTERNAL_ACTIONS,
        )

    return Decision(
        action=document.default_action,
        rule_id=DEFAULT_RULE_ID,
        rationale="No rule matched, so the default action applies.",
        fail_closed=True,
    )


ACTIVE_POINTER = "active"


class PolicyStore:
    """The policy in force, and every version it has had.

    Each version is a content-addressed snapshot, `<sha256>.yaml`, which is also what the
    audit verifier replays decisions against. The file `active` names the version in
    force. The shipped default policy seeds the store on first use and is what a restore
    goes back to; after that, editing the default file changes nothing.

    Only `ControlPlane.change_policy` changes the active version, so every change is
    audited. The snapshot is read and its hash checked on every call: a snapshot edited
    on disk is detected at the next request, which then fails closed.
    """

    def __init__(self, default_path: Path, snapshot_dir: Path) -> None:
        self._default_path = default_path
        self._dir = snapshot_dir
        self._pointer = snapshot_dir / ACTIVE_POINTER
        self._seed_lock = threading.Lock()
        self._cached: Policy | None = None

    def current(self) -> Policy:
        sha256 = self.active_sha256()
        if sha256 is None:
            return self._seed()
        if not _SHA256.fullmatch(sha256):
            raise PolicyError("the active policy pointer does not name a policy version")
        try:
            raw = (self._dir / f"{sha256}.yaml").read_bytes()
        except OSError as exc:
            raise PolicyError(f"policy version {sha256[:12]} is missing") from exc
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise PolicyError(f"policy version {sha256[:12]} was modified on disk")

        if self._cached is not None and self._cached.sha256 == sha256:
            return self._cached
        policy = parse_policy(raw)
        self._cached = policy
        return policy

    def active_sha256(self) -> str | None:
        """The version in force, as named by the pointer, or None before the first use."""
        try:
            return self._pointer.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError) as exc:
            reason = type(exc).__name__
            raise PolicyError(f"cannot read the active policy pointer: {reason}") from exc

    def default(self) -> Policy:
        try:
            raw = self._default_path.read_bytes()
        except OSError as exc:
            raise PolicyError(f"cannot read the default policy: {type(exc).__name__}") from exc
        policy = parse_policy(raw)
        # The default is put in force on first start and by a restore, so it is held to the
        # rule every saved policy is: no credential leaves unchanged.
        if leaks := credential_leaks(policy.document):
            raise PolicyError(f"the default policy is refused: {leaks[0][1]}")
        return policy

    def save_snapshot(self, policy: Policy) -> None:
        # Content-addressed, so writing one twice is harmless and evidence can name the
        # exact policy text it was decided under.
        target = self._dir / f"{policy.sha256}.yaml"
        try:
            existing = target.read_bytes()
        except FileNotFoundError:
            existing = None
        if existing == policy.raw:
            return
        if existing is not None:
            # Saving that version again, for example restoring the default, repairs it.
            logger.warning("policy version %s did not match its hash; rewritten", policy.sha256)
        _write_atomically(target, policy.raw)

    def set_active(self, sha256: str) -> None:
        if not (self._dir / f"{sha256}.yaml").exists():
            raise PolicyError(f"policy version {sha256[:12]} has no snapshot")
        _write_atomically(self._pointer, sha256.encode("ascii") + b"\n")

    def versions(self) -> dict[str, set[str]]:
        """Each version string ever stored, with the SHA-256 of every text saved under it."""
        versions: dict[str, set[str]] = {}
        for path in self._dir.glob("*.yaml"):
            if not _SHA256.fullmatch(path.stem):
                continue
            try:
                data = yaml.safe_load(path.read_bytes())
            except (OSError, yaml.YAMLError):
                # A damaged snapshot cannot be put back in force, so it holds no version.
                continue
            if isinstance(data, dict) and isinstance(data.get("version"), str):
                versions.setdefault(data["version"], set()).add(path.stem)
        return versions

    def _seed(self) -> Policy:
        with self._seed_lock:
            if self.active_sha256() is None:
                policy = self.default()
                self.save_snapshot(policy)
                self.set_active(policy.sha256)
        return self.current()


def next_free_version(version: str, taken: Collection[str]) -> str:
    """The first version after `version` that is not taken: 1.3.0 -> 1.3.1, beta -> beta.1."""
    match = re.fullmatch(r"(.*?)(\d+)", version)
    prefix, number = (match.group(1), int(match.group(2))) if match else (f"{version}.", 0)
    while True:
        number += 1
        candidate = f"{prefix}{number}"
        if candidate not in taken:
            return candidate


def _write_atomically(path: Path, data: bytes) -> None:
    """Write to a temporary file and rename it, so a reader never sees half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def describe_changes(old: PolicyDocument | None, new: PolicyDocument) -> list[str]:
    """What changed between two policies, one plain sentence per change, for the audit log."""
    if old is None:
        return [f"Replaced a missing or invalid policy with {new.id} v{new.version}."]
    changes: list[str] = []
    for name in ("id", "version", "description", "block_message"):
        before, after = getattr(old, name), getattr(new, name)
        if before != after:
            label = name.replace("_", " ").capitalize()
            changes.append(f"{label} changed from {_quote(before)} to {_quote(after)}.")
    changes += _category_changes(old.categories, new.categories)
    for name in ("min_score", "confident_score"):
        before, after = getattr(old.detection, name), getattr(new.detection, name)
        if before != after:
            changes.append(f"Detection {name.replace('_', ' ')} changed from {before} to {after}.")
    changes += _rule_changes(old.rules, new.rules)
    if old.default_action != new.default_action:
        changes.append(f"Default action changed from {old.default_action} to {new.default_action}.")
    changes += _set_changes(
        "Allowed destination",
        old.egress.allowed_destinations,
        new.egress.allowed_destinations,
    )
    changes += _set_changes(
        "Category removed from answers",
        old.response.redact_categories,
        new.response.redact_categories,
    )
    if old.response.restore_placeholders != new.response.restore_placeholders:
        state = "on" if new.response.restore_placeholders else "off"
        changes.append(f"Restoring redacted values in answers turned {state}.")
    return changes


def _category_changes(
    old: dict[str, tuple[str, ...]], new: dict[str, tuple[str, ...]]
) -> list[str]:
    changes: list[str] = []
    for category in new.keys() - old.keys():
        types = ", ".join(new[category]) or "no entity types"
        changes.append(f"Added category {category} ({types}).")
    for category in old.keys() - new.keys():
        changes.append(f"Removed category {category}.")
    for category in sorted(old.keys() & new.keys()):
        changes += _set_changes(f"Entity type in {category}", old[category], new[category])
    return sorted(changes)


def _rule_changes(old: tuple[Rule, ...], new: tuple[Rule, ...]) -> list[str]:
    before = {rule.id: rule for rule in old}
    after = {rule.id: rule for rule in new}
    changes: list[str] = []
    for position, rule in enumerate(new, start=1):
        if rule.id not in before:
            changes.append(
                f"Added rule {rule.id} at position {position}: {_condition(rule.when)}, "
                f"{rule.action}."
            )
    changes += [f"Removed rule {rule.id}." for rule in old if rule.id not in after]
    for rule in new:
        previous = before.get(rule.id)
        if previous is None:
            continue
        if previous.action != rule.action:
            changes.append(
                f"Rule {rule.id}: action changed from {previous.action} to {rule.action}."
            )
        if previous.when != rule.when:
            changes.append(
                f"Rule {rule.id}: now matches {_condition(rule.when)} "
                f"(was {_condition(previous.when)})."
            )
        if previous.description != rule.description:
            changes.append(f"Rule {rule.id}: description changed.")
    kept_before = [rule.id for rule in old if rule.id in after]
    kept_after = [rule.id for rule in new if rule.id in before]
    if kept_before != kept_after:
        changes.append(f"Rule order changed to: {', '.join(r.id for r in new)}.")
    return changes


def _condition(condition: RuleCondition) -> str:
    parts = []
    if condition.any_category:
        parts.append(f"category {' or '.join(condition.any_category)}")
    if condition.label:
        parts.append(f"label {' or '.join(condition.label)}")
    return " and ".join(parts) if parts else "every request"


def _set_changes(subject: str, old: tuple[str, ...], new: tuple[str, ...]) -> list[str]:
    added = [f"{subject} added: {item}." for item in new if item not in old]
    removed = [f"{subject} removed: {item}." for item in old if item not in new]
    return added + removed


def _quote(value: str) -> str:
    return f'"{value}"' if len(value) <= 80 else f'"{value[:77]}..."'
