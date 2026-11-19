"""Value types shared by detection, policy, enforcement and audit.

They are frozen dataclasses with no behaviour, so the pure functions that consume them
(`classify`, `decide`) can be replayed from audit evidence alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    ROUTE_SOVEREIGN = "route_sovereign"


class Label(StrEnum):
    NO_PRIVATE_DATA = "no_private_data"
    CONTAINS_PRIVATE_DATA = "contains_private_data"
    # Only low-confidence evidence was found.
    UNCERTAIN = "uncertain"
    # Detection itself failed, so nothing can be said about the prompt.
    UNKNOWN_ASSUME_PRIVATE = "unknown_assume_private"
    # The request never reached detection (malformed, oversized).
    INVALID_INPUT = "invalid_input"


class OutcomeStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    WITHHELD = "withheld"


@dataclass(frozen=True)
class Finding:
    """One piece of evidence that a span of text is private data."""

    entity_type: str
    start: int
    end: int
    score: float
    detector: str
    recognizer: str


@dataclass(frozen=True)
class DetectorRun:
    name: str
    version: str
    ok: bool
    # Exception class name only: exception messages can echo the prompt.
    error: str | None = None


@dataclass(frozen=True)
class Signals:
    """Everything detection observed. The only input to classification."""

    findings: tuple[Finding, ...]
    detectors: tuple[DetectorRun, ...]


@dataclass(frozen=True)
class Classification:
    label: Label
    categories: tuple[str, ...]
    # Findings at or above the policy's `min_score` whose entity type the policy maps.
    counted: tuple[Finding, ...]
    rationale: str


@dataclass(frozen=True)
class Decision:
    action: Action
    rule_id: str
    rationale: str
    # True when the action was chosen because of a failure or uncertainty,
    # not because of positive evidence.
    fail_closed: bool = False
