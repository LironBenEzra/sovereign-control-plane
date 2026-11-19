"""The request pipeline: inspect, decide, record the decision, enforce, record the outcome.

Two rules shape the order of operations:

* No model is called until the decision record is durably written. If evidence cannot
  be written, nothing happens.
* The outcome record is written from what actually happened, after it happened. The log
  never claims an egress that did not take place, and a decision with no outcome is a
  visible sign of an interrupted request.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import unicodedata
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Any

from control_plane.audit.chain import (
    EVENT_DECISION,
    EVENT_OUTCOME,
    EVENT_POLICY_LOADED,
    INVALID_REQUEST_RULE_ID,
    POLICY_UNAVAILABLE_RULE_ID,
    AuditRecord,
)
from control_plane.audit.keys import keyed_hash
from control_plane.audit.log import AuditLog, AuditWriteError
from control_plane.classification import classify
from control_plane.detection.base import DetectorRunner
from control_plane.egress import EXTERNAL_ACTIONS, EgressDeniedError, EgressGateway
from control_plane.enforcement import Redaction, redact, restore
from control_plane.evidence import (
    classification_to_evidence,
    decision_to_evidence,
    policy_to_evidence,
    signals_to_evidence,
)
from control_plane.models import (
    Action,
    Classification,
    Decision,
    Label,
    OutcomeStatus,
    Signals,
)
from control_plane.policy import Policy, PolicyError, PolicyStore, decide
from control_plane.providers.base import ModelProvider, ModelReply, ProviderError

logger = logging.getLogger(__name__)

SYSTEM_AUDIT_ID = "system"

_NO_POLICY_MESSAGE = (
    "This request was blocked because no valid data protection policy is loaded. "
    "No model was called."
)
_SOVEREIGN_DOWN_MESSAGE = (
    "This request must stay inside the trust boundary, but the sovereign model is "
    "unavailable, so it was blocked. It was not sent to any external model."
)
_EGRESS_DENIED_MESSAGE = (
    "This request was blocked because the policy does not allow sending to the "
    "external model. Nothing left the trust boundary."
)

# Invisible characters that can split a word to slip past pattern matching.
_INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u2060\ufeff"))


def normalize_prompt(prompt: str) -> str:
    """Fold look-alike characters (NFKC) and drop invisible ones before inspection.

    The normalized text is what gets inspected and what gets forwarded, so the model
    never sees anything the detectors did not.
    """
    return unicodedata.normalize("NFKC", prompt).translate(_INVISIBLE)


class EvidenceUnavailableError(Exception):
    """An audit record could not be written, so the request must not be served."""

    def __init__(self, audit_id: str, stage: str) -> None:
        super().__init__(f"could not write the {stage} record for {audit_id}")
        self.audit_id = audit_id
        self.stage = stage


@dataclass(frozen=True)
class Receipt:
    """Proof a caller can keep that a record existed with this content."""

    seq: int
    hash: str
    sig: str
    key_id: str

    @classmethod
    def of(cls, record: AuditRecord) -> Receipt:
        return cls(record["seq"], record["hash"], record["sig"], record["key_id"])


@dataclass(frozen=True)
class ModelUse:
    provider: str
    model: str
    in_boundary: bool
    stub: bool

    @classmethod
    def of(cls, provider: ModelProvider) -> ModelUse:
        return cls(provider.name, provider.model, provider.in_boundary, provider.is_stub)


@dataclass(frozen=True)
class InferenceResult:
    audit_id: str
    signals: Signals
    classification: Classification
    decision: Decision
    policy: Policy | None
    status: OutcomeStatus
    reason: str | None
    model: ModelUse | None
    # Exactly what the model received. None when no model was called.
    forwarded_prompt: str | None
    response: str | None
    decision_receipt: Receipt
    outcome_receipt: Receipt


@dataclass(frozen=True)
class _Enforcement:
    status: OutcomeStatus
    reason: str | None
    evidence: dict[str, Any]
    model: ModelUse | None = None
    forwarded_prompt: str | None = None
    response: str | None = None


@dataclass(frozen=True)
class _Attempt:
    """One model call made for a decision, and the evidence it leaves behind."""

    decision: Decision
    provider: ModelProvider
    payload: str
    redaction: Redaction | None
    started: float

    @property
    def external(self) -> bool:
        return not self.provider.in_boundary

    def outcome(
        self,
        status: OutcomeStatus,
        reason: str | None,
        *,
        sent: bool,
        denied_reason: str | None = None,
        reply: ModelReply | None = None,
        error: str | None = None,
        placeholders_restored: int | None = None,
        response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the outcome record. `sent` is true once the call to the model started."""
        model = {
            **vars(ModelUse.of(self.provider)),
            "called": sent,
            "served_by": reply.served_by if reply else None,
            "note": reply.note if reply else None,
            "error": error,
            "latency_ms": _elapsed_ms(self.started) if sent else None,
        }
        egress = None
        if self.external:
            egress = {
                "destination": self.provider.name,
                # A plain hash on purpose: it can be matched against the provider's own logs.
                "payload_sha256": hashlib.sha256(self.payload.encode()).hexdigest(),
                "payload_chars": len(self.payload),
                "allowed": sent,
                "denied_reason": denied_reason,
                # True even if the call then failed: the payload may have left before
                # the error, and the evidence must not claim otherwise.
                "attempted": sent,
            }
        redaction = None
        if self.redaction is not None:
            redaction = {
                "spans": self.redaction.span_count,
                "by_entity": self.redaction.by_entity,
                "placeholders_restored": placeholders_restored,
            }
        return _outcome(
            self.decision,
            status,
            reason,
            redaction=redaction,
            model=model,
            egress=egress,
            response=response,
        )


class _OutputScanFailedError(Exception):
    pass


class ControlPlane:
    def __init__(
        self,
        *,
        detectors: DetectorRunner,
        policies: PolicyStore,
        audit: AuditLog,
        sovereign: ModelProvider,
        egress: EgressGateway,
        hmac_key: bytes,
    ) -> None:
        self._detectors = detectors
        self._policies = policies
        self._audit = audit
        self._sovereign = sovereign
        self._egress = egress
        self._hmac_key = hmac_key
        self._policy_lock = threading.Lock()
        self._policy_state: str | None = None

    # ------------------------------------------------------------------ entry points

    def handle(self, prompt: str, client_id: str | None = None) -> InferenceResult:
        audit_id = uuid.uuid4().hex
        text = normalize_prompt(prompt)
        request = {
            "prompt_hmac": keyed_hash(self._hmac_key, text),
            "prompt_chars": len(text),
            "normalization_changed": text != prompt,
            # Taken from a header and not authenticated, hence "claimed".
            "client_id_claimed": client_id,
        }

        policy = self._current_policy()
        if policy is None:
            return self._refuse(
                audit_id,
                request,
                label=Label.UNKNOWN_ASSUME_PRIVATE,
                rule_id=POLICY_UNAVAILABLE_RULE_ID,
                rationale="The policy is missing or invalid, so every request is blocked.",
                reason="policy_unavailable",
                response=_NO_POLICY_MESSAGE,
            )

        signals = self._detectors.run(text, policy.entity_types)
        classification = classify(signals, policy)
        decision = decide(classification, policy)

        decision_record = self._append(
            EVENT_DECISION,
            audit_id,
            {
                "request": request,
                "signals": signals_to_evidence(signals, text, self._hmac_key),
                "classification": classification_to_evidence(classification),
                "policy": policy_to_evidence(policy),
                "decision": decision_to_evidence(decision),
            },
        )
        enforcement = self._enforce(text, classification, decision, policy)
        outcome_record = self._append(EVENT_OUTCOME, audit_id, enforcement.evidence)

        return InferenceResult(
            audit_id=audit_id,
            signals=signals,
            classification=classification,
            decision=decision,
            policy=policy,
            status=enforcement.status,
            reason=enforcement.reason,
            model=enforcement.model,
            forwarded_prompt=enforcement.forwarded_prompt,
            response=enforcement.response,
            decision_receipt=Receipt.of(decision_record),
            outcome_receipt=Receipt.of(outcome_record),
        )

    def reject(self, reason: str, client_id: str | None = None) -> InferenceResult:
        """Record a request that was refused at the door (malformed, oversized).

        The body is never inspected or stored: it is untrusted and may be private.
        """
        return self._refuse(
            uuid.uuid4().hex,
            {
                "prompt_hmac": None,
                "prompt_chars": None,
                "normalization_changed": False,
                "client_id_claimed": client_id,
                "rejected": reason,
            },
            label=Label.INVALID_INPUT,
            rule_id=INVALID_REQUEST_RULE_ID,
            rationale=f"The request was rejected before inspection: {reason}.",
            reason=reason,
            response=None,
        )

    # ------------------------------------------------------------------ policy

    def _current_policy(self) -> Policy | None:
        """Load the policy and record every change of policy in the audit log."""
        try:
            policy = self._policies.current()
        except PolicyError as exc:
            policy = None
            error = str(exc).splitlines()[0][:300]
            state = "invalid:" + hashlib.sha256(str(exc).encode()).hexdigest()
            body: dict[str, Any] = {"valid": False, "error": error}
        else:
            state = policy.sha256
            body = {"valid": True, **(policy_to_evidence(policy) or {})}

        with self._policy_lock:
            if state != self._policy_state:
                self._append(EVENT_POLICY_LOADED, SYSTEM_AUDIT_ID, body)
                self._policy_state = state
        return policy

    # ------------------------------------------------------------------ enforcement

    def _enforce(
        self, text: str, classification: Classification, decision: Decision, policy: Policy
    ) -> _Enforcement:
        if decision.action is Action.BLOCK:
            return _Enforcement(
                status=OutcomeStatus.BLOCKED,
                reason="blocked_by_policy",
                evidence=_outcome(decision, OutcomeStatus.BLOCKED, "blocked_by_policy"),
                response=policy.document.block_message,
            )

        external = decision.action in EXTERNAL_ACTIONS
        provider = self._egress.provider if external else self._sovereign
        redaction = (
            redact(text, classification.counted) if decision.action is Action.REDACT else None
        )
        payload = redaction.text if redaction else text
        attempt = _Attempt(decision, provider, payload, redaction, started=time.monotonic())
        used = ModelUse.of(provider)

        try:
            reply = self._call(payload, decision, policy, external)
        except EgressDeniedError as exc:
            status, reason = OutcomeStatus.BLOCKED, f"egress_denied:{exc.reason}"
            return _Enforcement(
                status=status,
                reason=reason,
                evidence=attempt.outcome(status, reason, sent=False, denied_reason=exc.reason),
                response=_EGRESS_DENIED_MESSAGE,
            )
        except ProviderError as exc:
            if external:
                status, reason = OutcomeStatus.FAILED, f"external_model_error:{exc.kind}"
                response = None
            else:
                # Fail closed: a prompt that must stay inside never falls back to outside.
                status, reason = OutcomeStatus.BLOCKED, f"sovereign_model_unavailable:{exc.kind}"
                response = _SOVEREIGN_DOWN_MESSAGE
            return _Enforcement(
                status=status,
                reason=reason,
                evidence=attempt.outcome(status, reason, sent=True, error=exc.kind),
                model=used,
                forwarded_prompt=payload if external else None,
                response=response,
            )

        try:
            output, scan = self._scan_output(reply.text, policy)
        except _OutputScanFailedError:
            status, reason = OutcomeStatus.WITHHELD, "output_scan_failed"
            return _Enforcement(
                status=status,
                reason=reason,
                evidence=attempt.outcome(status, reason, sent=True, reply=reply),
                model=used,
                forwarded_prompt=payload,
            )

        restored = None
        if redaction and policy.document.response.restore_placeholders:
            output, restored = restore(output, redaction.placeholders)

        return _Enforcement(
            status=OutcomeStatus.COMPLETED,
            reason=None,
            evidence=attempt.outcome(
                OutcomeStatus.COMPLETED,
                None,
                sent=True,
                reply=reply,
                placeholders_restored=restored,
                response={"hmac": keyed_hash(self._hmac_key, output), "chars": len(output), **scan},
            ),
            model=used,
            forwarded_prompt=payload,
            response=output,
        )

    def _call(self, payload: str, decision: Decision, policy: Policy, external: bool) -> ModelReply:
        try:
            if external:
                return self._egress.send(payload, decision, policy)
            return self._sovereign.generate(payload)
        except (EgressDeniedError, ProviderError):
            raise
        except Exception as exc:
            # Deliberately broad. A provider SDK raised something it does not document.
            # Treating it as a failed call means the outcome record is still written,
            # and it says the call was attempted.
            logger.error("model call raised an unexpected %s", type(exc).__name__)
            raise ProviderError(f"unexpected_{type(exc).__name__}") from exc

    def _scan_output(self, text: str, policy: Policy) -> tuple[str, dict[str, Any]]:
        """Inspect the model's answer with the same detectors and apply response rules."""
        signals = self._detectors.run(text, policy.entity_types)
        if any(not run.ok for run in signals.detectors):
            raise _OutputScanFailedError

        document = policy.document
        counted = [f for f in signals.findings if f.score >= document.detection.min_score]
        to_redact = [
            f
            for f in counted
            if policy.category_of(f.entity_type) in document.response.redact_categories
        ]
        redaction = redact(text, to_redact)
        return redaction.text, {
            "output_findings": dict(sorted(Counter(f.entity_type for f in counted).items())),
            "output_redactions": redaction.by_entity,
        }

    # ------------------------------------------------------------------ helpers

    def _refuse(
        self,
        audit_id: str,
        request: dict[str, Any],
        *,
        label: Label,
        rule_id: str,
        rationale: str,
        reason: str,
        response: str | None,
    ) -> InferenceResult:
        """Block a request that never reached detection, with full evidence."""
        signals = Signals(findings=(), detectors=())
        classification = Classification(
            label=label, categories=(), counted=(), rationale="Detection did not run."
        )
        decision = Decision(Action.BLOCK, rule_id, rationale, fail_closed=True)

        decision_record = self._append(
            EVENT_DECISION,
            audit_id,
            {
                "request": request,
                "signals": signals_to_evidence(signals, "", self._hmac_key),
                "classification": classification_to_evidence(classification),
                "policy": None,
                "decision": decision_to_evidence(decision),
            },
        )
        outcome_record = self._append(
            EVENT_OUTCOME, audit_id, _outcome(decision, OutcomeStatus.BLOCKED, reason)
        )
        return InferenceResult(
            audit_id=audit_id,
            signals=signals,
            classification=classification,
            decision=decision,
            policy=None,
            status=OutcomeStatus.BLOCKED,
            reason=reason,
            model=None,
            forwarded_prompt=None,
            response=response,
            decision_receipt=Receipt.of(decision_record),
            outcome_receipt=Receipt.of(outcome_record),
        )

    def _append(self, event: str, audit_id: str, body: dict[str, Any]) -> AuditRecord:
        try:
            return self._audit.append(event, audit_id, body)
        except AuditWriteError as exc:
            logger.error("audit write failed (%s) for %s: %s", event, audit_id, exc)
            raise EvidenceUnavailableError(audit_id, event) from exc


def _outcome(
    decision: Decision,
    status: OutcomeStatus,
    reason: str | None,
    *,
    redaction: dict[str, Any] | None = None,
    model: dict[str, Any] | None = None,
    egress: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "action": decision.action.value,
        "status": status.value,
        "reason": reason,
        "redaction": redaction,
        "model": model,
        "egress": egress,
        "response": response,
    }


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)
