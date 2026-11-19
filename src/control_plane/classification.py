"""Turn detection signals into an explainable classification. Pure function."""

from __future__ import annotations

from collections import Counter

from control_plane.models import Classification, Finding, Label, Signals
from control_plane.policy import Policy


def classify(signals: Signals, policy: Policy) -> Classification:
    thresholds = policy.document.detection
    kept: list[Finding] = []
    kept_categories: set[str] = set()
    for finding in signals.findings:
        category = policy.category_of(finding.entity_type)
        if category is not None and finding.score >= thresholds.min_score:
            kept.append(finding)
            kept_categories.add(category)
    counted = tuple(kept)
    categories = tuple(sorted(kept_categories))
    found = _describe(counted)

    failed = sorted(run.name for run in signals.detectors if not run.ok)
    if failed or not signals.detectors:
        reason = f"Detector failed: {', '.join(failed)}." if failed else "No detector ran."
        return Classification(
            label=Label.UNKNOWN_ASSUME_PRIVATE,
            categories=categories,
            counted=counted,
            rationale=f"{reason} The prompt is treated as private. {found}".strip(),
        )

    if not counted:
        return Classification(
            label=Label.NO_PRIVATE_DATA,
            categories=(),
            counted=(),
            rationale=f"No finding at or above the minimum score {thresholds.min_score}.",
        )

    if any(f.score >= thresholds.confident_score for f in counted):
        return Classification(
            label=Label.CONTAINS_PRIVATE_DATA,
            categories=categories,
            counted=counted,
            rationale=found,
        )

    return Classification(
        label=Label.UNCERTAIN,
        categories=categories,
        counted=counted,
        rationale=(
            f"{found} Every finding is below the confident score "
            f"{thresholds.confident_score}, so the prompt is treated as private."
        ),
    )


def _describe(counted: tuple[Finding, ...]) -> str:
    if not counted:
        return ""
    counts = Counter(f.entity_type for f in counted)
    parts = ", ".join(f"{entity} x{n}" for entity, n in sorted(counts.items()))
    return f"Found {len(counted)} finding(s): {parts}."
