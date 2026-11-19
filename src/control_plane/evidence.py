"""Evidence bodies: what goes into an audit record, and how to read it back.

The decision body holds everything `classify` and `decide` took as input, so the
verifier can re-run both from the record alone. No raw private value is stored: the
prompt and each matched value appear only as keyed hashes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from control_plane.audit.keys import keyed_hash
from control_plane.models import Classification, Decision, DetectorRun, Finding, Signals
from control_plane.policy import Policy


def signals_to_evidence(signals: Signals, text: str, hmac_key: bytes) -> dict[str, Any]:
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
                "value_hmac": keyed_hash(hmac_key, text[f.start : f.end]),
            }
            for f in signals.findings
        ],
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
