"""Evidence bodies: what goes into an audit record, and how to read it back.

The decision body holds everything `classify` and `decide` took as input, so the
verifier can re-run both from the record alone. No private value is stored: a finding is
recorded by its type, position and score, never by its value, and the prompt is kept as
a keyed hash and, in the detection record, with every value the policy counts as private
masked.

Records written before 2026-11-20 also carry a `value_hmac` per finding. Nothing read
it, and it showed when the same value appeared in two requests, so it was dropped.
`signals_from_evidence` names the fields it needs, so those records still replay.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from control_plane.models import Classification, Decision, DetectorRun, Finding, Signals
from control_plane.policy import Policy


def signals_to_evidence(signals: Signals) -> dict[str, Any]:
    return {
        "detectors": [
            {"name": run.name, "version": run.version, "ok": run.ok, "error": run.error}
            for run in signals.detectors
        ],
        "findings": [
            {
                "entity_type": f.entity_type,
                "start": f.start,
                "end": f.end,
                "score": f.score,
                "detector": f.detector,
                "recognizer": f.recognizer,
            }
            for f in signals.findings
        ],
    }


def detection_to_evidence(signals: Signals, masked_prompt: str, duration_ms: int) -> dict[str, Any]:
    """The detection step: what ran, whether it worked, what it found and how long it took.

    `findings: 0` with every detector ok is an explicit "nothing detected". Positions and
    scores are in the decision record, which is the one replay reads.

    `masked_prompt` is the prompt with every value the policy counts as private replaced
    by its placeholder, such as `<PERSON_1>`: the same text a `redact` decision sends out.
    A clean prompt has nothing masked. It is not kept when a detector failed, because what
    that detector would have found is not masked.
    """
    failed = any(not run.ok for run in signals.detectors)
    return {
        "detectors": signals_to_evidence(signals)["detectors"],
        "findings": len(signals.findings),
        "by_entity": dict(sorted(Counter(f.entity_type for f in signals.findings).items())),
        "masked_prompt": None if failed else masked_prompt,
        "duration_ms": duration_ms,
    }


def signals_from_evidence(data: Mapping[str, Any]) -> Signals:
    return Signals(
        findings=tuple(
            Finding(
                entity_type=f["entity_type"],
                start=f["start"],
                end=f["end"],
                score=f["score"],
                detector=f["detector"],
                recognizer=f["recognizer"],
            )
            for f in data["findings"]
        ),
        detectors=tuple(
            DetectorRun(name=d["name"], version=d["version"], ok=d["ok"], error=d["error"])
            for d in data["detectors"]
        ),
    )


def classification_to_evidence(classification: Classification) -> dict[str, Any]:
    return {
        "label": classification.label.value,
        "categories": list(classification.categories),
        "counted_findings": len(classification.counted),
        "rationale": classification.rationale,
    }


def policy_to_evidence(policy: Policy | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {
        "id": policy.document.id,
        "version": policy.document.version,
        "sha256": policy.sha256,
    }


def decision_to_evidence(decision: Decision) -> dict[str, Any]:
    return {
        "action": decision.action.value,
        "rule_id": decision.rule_id,
        "rationale": decision.rationale,
        "fail_closed": decision.fail_closed,
    }
