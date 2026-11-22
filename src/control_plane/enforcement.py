"""Redaction and placeholder restore. Pure functions over text and findings."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from control_plane.models import Finding


@dataclass(frozen=True)
class MaskedSpan:
    """Where one placeholder replaced a value: in the original text and in the masked one."""

    start: int
    end: int
    masked_start: int
    masked_end: int


@dataclass(frozen=True)
class Redaction:
    text: str
    # placeholder -> original value. Lives only in memory for the duration of one request.
    placeholders: dict[str, str]
    by_entity: dict[str, int]
    # Every placeholder in `text`, in order.
    masked_spans: tuple[MaskedSpan, ...] = ()

    @property
    def span_count(self) -> int:
        return sum(self.by_entity.values())

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """The span of the original text that `text[start:end]` stands for.

        A span that starts or ends inside a placeholder covers the whole value it replaced.
        """
        return self._original(start, is_end=False), self._original(end, is_end=True)

    def _original(self, position: int, *, is_end: bool) -> int:
        original = position
        for span in self.masked_spans:
            # An end right before a placeholder stops before its value; a start there
            # begins with it.
            if position < span.masked_start or (is_end and position == span.masked_start):
                break
            if position < span.masked_end:
                return span.end if is_end else span.start
            original = span.end + position - span.masked_end
        return original


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
    masked_spans: list[MaskedSpan] = []

    parts: list[str] = []
    masked_length = 0
    cursor = 0
    for span in _merge(findings):
        original = text[span.start : span.end]
        key = (span.entity_type, original)
        if key not in by_value:
            next_index[span.entity_type] += 1
            placeholder = f"<{span.entity_type}_{next_index[span.entity_type]}>"
            by_value[key] = placeholder
            placeholders[placeholder] = original
        placeholder = by_value[key]
        masked_length += span.start - cursor
        masked_spans.append(
            MaskedSpan(span.start, span.end, masked_length, masked_length + len(placeholder))
        )
        masked_length += len(placeholder)
        parts.append(text[cursor : span.start])
        parts.append(placeholder)
        by_entity[span.entity_type] += 1
        cursor = span.end
    parts.append(text[cursor:])

    return Redaction(
        "".join(parts), placeholders, dict(sorted(by_entity.items())), tuple(masked_spans)
    )


def restore(text: str, placeholders: Mapping[str, str]) -> tuple[str, int]:
    """Put original values back in place of placeholders. Returns the text and the count.

    Done in a single pass, so a restored value that happens to look like another
    placeholder is not substituted a second time.
    """
    if not placeholders:
        return text, 0
    pattern = re.compile("|".join(re.escape(placeholder) for placeholder in placeholders))
    return pattern.subn(lambda match: placeholders[match.group()], text)


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
