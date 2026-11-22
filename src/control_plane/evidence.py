"""Evidence bodies: what goes into an audit record, and how to read it back.

A request's detection and decision records together hold everything `classify` and
`decide` took as input: the signals in the first, the policy's hash in the second. The
verifier re-runs both from them. No private value is stored: a finding is recorded by its
type, position and score, never by its value, and the prompt is kept as a keyed hash and,
in the detection record, with every value the policy counts as private masked. An answer
from outside the boundary is kept masked the same way, in the `model_reply` record.

Records written before 2026-11-20 also carry a `value_hmac` per finding. Nothing read
it, and it showed when the same value appeared in two requests, so it was dropped.
`signals_from_evidence` names the fields it needs, so those records still replay.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Mapping
from typing import Any

from control_plane.models import Classification, Decision, DetectorRun, Finding, Signals
from control_plane.policy import Policy


def detection_to_evidence(
    signals: Signals,
    counted: Collection[Finding],
    masked_prompt: str,
    duration_ms: int,
) -> dict[str, Any]:
    """The detection step: what ran, whether it worked, what it found and how long it took.

    This is the one record that keeps the signals, and the verifier replays the decision
    from it. Each finding has its type, position and score, the detector and recognizer
    that found it, and `counted`: whether the decision used it, because it scored at least
    the policy's `min_score` and its type is one the policy lists. An empty `findings` with
    every detector ok is an explicit "nothing detected".

    `masked_prompt` is the prompt with every value the policy counts as private replaced
    by its placeholder, such as `<PERSON_1>`: the same text a `redact` decision sends out.
    A clean prompt has nothing masked. It is not kept when a detector failed, because what
    that detector would have found is not masked.
    """
    failed = any(not run.ok for run in signals.detectors)
    return {
        "detectors": _runs_to_evidence(signals),
        "findings": _findings_to_evidence(signals, counted),
        "by_entity": dict(sorted(Counter(f.entity_type for f in signals.findings).items())),
        "masked_prompt": None if failed else masked_prompt,
        "duration_ms": duration_ms,
    }


def reply_to_evidence(
    reply_chars: int,
    signals: Signals,
    counted: Collection[Finding],
    redacted: Mapping[str, int],
    masked_reply: str | None,
) -> dict[str, Any]:
    """The model's answer as it came back, and the output scan run on it.

    `findings` are the scan's, with positions in the answer as it came back. `redacted`
    counts what the policy's response rules took out of the answer before anything else
    happened to it, by entity type. Placeholders are put back after this record is
    written, and the outcome record names them.

    `masked_reply` is the answer with every private value the scan found masked, the way
    `masked_prompt` is. It is kept only for an answer from outside the boundary: an answer
    from inside may repeat what the prompt held in ways the scan does not look for. None
    then, and when a detector failed on the answer.
    """
    return {
        "reply_chars": reply_chars,
        "detectors": _runs_to_evidence(signals),
        "findings": _findings_to_evidence(signals, counted),
        "redacted": dict(redacted),
        "masked_reply": masked_reply,
    }


def _runs_to_evidence(signals: Signals) -> list[dict[str, Any]]:
    return [
        {"name": run.name, "version": run.version, "ok": run.ok, "error": run.error}
        for run in signals.detectors
    ]


def _findings_to_evidence(signals: Signals, counted: Collection[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "entity_type": f.entity_type,
            "start": f.start,
            "end": f.end,
            "score": f.score,
            "detector": f.detector,
            "recognizer": f.recognizer,
            "counted": f in counted,
        }
        for f in signals.findings
    ]


def recorded_signals(
    decision: Mapping[str, Any], detection: Mapping[str, Any] | None
) -> Mapping[str, Any] | None:
    """The body that holds a request's signals, for `signals_from_evidence`.

    That is its detection record. Decision records written before 2026-11-21 kept their
    own copy under `signals`, and theirs is read from there: their detection record has
    only a count of findings. None when neither exists: the request never reached detection.
    """
    return decision.get("signals", detection)


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
