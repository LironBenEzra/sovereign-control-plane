"""Redaction and placeholder restore. Pure functions over text and findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from control_plane.models import Finding


@dataclass(frozen=True)
class Redaction:
    text: str
    # placeholder -> original value. Lives only in memory for the duration of one request.
    placeholders: dict[str, str]
    by_entity: dict[str, int]

    @property
    def span_count(self) -> int:
        return sum(self.by_entity.values())


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    entity_type: str


def redact(text: str, findings: Sequence[Finding]) -> Redaction:
    """Replace every found span with a typed placeholder such as `<EMAIL_ADDRESS_1>`.

    The same value always gets the same placeholder, so the model can still tell that
    two mentions refer to the same thing.
    """
    placeholders: dict[str, str] = {}
    by_value: dict[tuple[str, str], str] = {}
    next_index: Counter[str] = Counter()
    by_entity: Counter[str] = Counter()

    parts: list[str] = []
    cursor = 0
    for span in _merge(findings):
        original = text[span.start : span.end]
        key = (span.entity_type, original)
        if key not in by_value:
            next_index[span.entity_type] += 1
            placeholder = f"<{span.entity_type}_{next_index[span.entity_type]}>"
            by_value[key] = placeholder
            placeholders[placeholder] = original
        parts.append(text[cursor : span.start])
        parts.append(by_value[key])
        by_entity[span.entity_type] += 1
        cursor = span.end
    parts.append(text[cursor:])

    return Redaction("".join(parts), placeholders, dict(sorted(by_entity.items())))


def restore(text: str, placeholders: Mapping[str, str]) -> tuple[str, int]:
    """Put original values back in place of placeholders. Returns the text and the count."""
    restored = 0
    for placeholder, original in placeholders.items():
        restored += text.count(placeholder)
        text = text.replace(placeholder, original)
    return text, restored


def _merge(findings: Sequence[Finding]) -> list[_Span]:
    """Union overlapping findings into disjoint spans.

    Overlaps are merged, not resolved by picking a winner: dropping the loser could leave
    part of its text in the clear. A merged span takes the type of its strongest finding.
    """
    spans: list[_Span] = []
    best: Finding | None = None
    start = end = 0
    for finding in sorted(findings, key=lambda f: (f.start, f.end, f.entity_type)):
        if best is not None and finding.start < end:
            end = max(end, finding.end)
            if _strength(finding) > _strength(best):
                best = finding
            continue
        if best is not None:
            spans.append(_Span(start, end, best.entity_type))
        best, start, end = finding, finding.start, finding.end
    if best is not None:
        spans.append(_Span(start, end, best.entity_type))
    return spans


def _strength(finding: Finding) -> tuple[float, int]:
    return (finding.score, finding.end - finding.start)
