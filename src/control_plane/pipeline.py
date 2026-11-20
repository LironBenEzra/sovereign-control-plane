"""The request pipeline: one audit record per step, from arrival to outcome.

A request leaves `received`, `detection`, `decision`, `model_call` (only when a model is
called) and `outcome`, in that order. Three rules shape the order of operations:

* Each step is recorded before the next one starts. No detector runs before `received`
  is durably written, and no model is called before `decision` and `model_call` are.
  If evidence cannot be written, nothing more happens.
* The outcome record is written from what actually happened, after it happened. The log
  never claims an egress that did not take place, and a request with no outcome is a
  visible sign that it was interrupted.
* An unexpected exception ends the request with an `error` record naming the step, in
  place of the outcome, so a failure leaves evidence too.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import traceback
import unicodedata
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from control_plane.audit.chain import (
    EVENT_DECISION,
    EVENT_DETECTION,
    EVENT_ERROR,
    EVENT_MODEL_CALL,
    EVENT_OUTCOME,
    EVENT_POLICY_CHANGED,
    EVENT_POLICY_LOADED,
    EVENT_RECEIVED,
    INVALID_REQUEST_RULE_ID,
    POLICY_UNAVAILABLE_RULE_ID,
    AuditRecord,
)
from control_plane.audit.keys import keyed_hash
from control_plane.audit.log import AuditLog, AuditWriteError
from control_plane.classification import classify
from control_plane.detection.base import DetectorRunner
from control_plane.detection.semantic import DETECTOR_NAME as SEMANTIC_DETECTOR
from control_plane.detection.semantic import ENTITY_TYPES as SEMANTIC_ENTITY_TYPES
from control_plane.detection.semantic import PROMPT_INJECTION as SEMANTIC_INJECTION
from control_plane.egress import EXTERNAL_ACTIONS, EgressDeniedError, EgressGateway
from control_plane.enforcement import Redaction, redact, restore
from control_plane.evidence import (
    classification_to_evidence,
    decision_to_evidence,
    detection_to_evidence,
    policy_to_evidence,
    signals_to_evidence,
)
from control_plane.models import (
    Action,
    Classification,
    Decision,
    Finding,
    Label,
    OutcomeStatus,
    Signals,
)
from control_plane.policy import Policy, PolicyError, PolicyStore, decide, describe_changes
from control_plane.providers.base import ModelProvider, ModelReply, ProviderError

logger = logging.getLogger(__name__)

SYSTEM_AUDIT_ID = "system"

_NO_POLICY_MESSAGE = (
    "This request was blocked because the data protection policy is missing or invalid, "
    "so no decision can be made. No model was called. An administrator must restore a "
    "valid policy. Try again after that."
)
_SOVEREIGN_DOWN_MESSAGE = (
    "This request must stay inside the trust boundary, but the sovereign model is "
    "unavailable, so it was blocked. It was not sent to any external model."
)
_EGRESS_DENIED_MESSAGE = (
    "This request was blocked because the policy does not allow sending to the "
    "external model. Nothing left the trust boundary."
)
_WITHHELD_MESSAGE = (
    "The model answered, but the answer could not be checked for private data because a "
    "detector failed, so it was withheld. Try again later."
)
_EXTERNAL_FAILED_MESSAGE = "The external model did not return an answer. Try again later."

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


class RequestFailedError(Exception):
    """A request failed on an unexpected exception. Its `error` record says at which step."""

    def __init__(self, audit_id: str, stage: str) -> None:
        super().__init__(f"request {audit_id} failed at {stage}")
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
    # The model's answer after the output scan, before placeholders are restored, so a
    # caller can see what came back across the boundary. None when no answer is returned.
    model_reply: str | None
    response: str | None
    # True when there is no answer because a component is unavailable (a detector, a model),
    # not because of a policy decision. Trying again later may succeed.
    retryable: bool
    decision_receipt: Receipt
    outcome_receipt: Receipt


@dataclass(frozen=True)
class _Enforcement:
    status: OutcomeStatus
    reason: str | None
    evidence: dict[str, Any]
    model: ModelUse | None = None
    forwarded_prompt: str | None = None
    model_reply: str | None = None
    response: str | None = None
    retryable: bool = False


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

    @property
    def payload_sha256(self) -> str:
        # A plain hash on purpose: it can be matched against the provider's own logs.
        return hashlib.sha256(self.payload.encode()).hexdigest()

    def call(self) -> dict[str, Any]:
        """The model_call record: which model is about to be called, and with what."""
        return {
            "model": vars(ModelUse.of(self.provider)),
            "payload_chars": len(self.payload),
            # Only for a call outside. A prompt kept inside may hold private data, and a
            # plain hash of a short private value can be reversed by trying every value.
            "payload_sha256": self.payload_sha256 if self.external else None,
            "redaction": (
                {"spans": self.redaction.span_count, "by_entity": self.redaction.by_entity}
                if self.redaction
                else None
            ),
        }

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
                "payload_sha256": self.payload_sha256,
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
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("the output scan failed")
        # Detector name -> error class name, for the outcome record.
        self.errors = errors


class PolicyConflictError(Exception):
    """The policy changed after the editor loaded it, so saving would undo that change."""

    def __init__(self, active_sha256: str | None) -> None:
        super().__init__("the policy changed since it was loaded")
        self.active_sha256 = active_sha256


class PolicyUnchangedError(Exception):
    """The new policy is the one already in force."""


@dataclass(frozen=True)
class PolicyChange:
    policy: Policy
    previous: Policy | None
    changes: tuple[str, ...]
    receipt: Receipt


@dataclass(frozen=True)
class Verdict:
    """What one policy decides for a prompt."""

    policy: Policy
    classification: Classification
    decision: Decision


@dataclass(frozen=True)
class Preview:
    signals: Signals
    # None while there is no usable policy in force.
    current: Verdict | None
    draft: Verdict


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
        # Serializes policy changes, so the version a change replaces is the one checked.
        self._change_lock = threading.Lock()

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
        # First, so a request is on record even if it never gets any further.
        self._append(EVENT_RECEIVED, audit_id, {"request": request})

        stage = "policy"
        try:
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
                    # A broken policy is an outage, not a decision. The policy is loaded on
                    # every request, so a retry succeeds as soon as a valid one is restored.
                    retryable=True,
                )

            stage = "detection"
            started = time.monotonic()
            signals = self._detectors.run(text, policy.entity_types)
            duration_ms = _elapsed_ms(started)
            classification = classify(signals, policy)
            # Masked once, here: the detection record keeps this text, and `redact` sends it.
            masked = redact(text, _private(classification.counted))
            self._append(
                EVENT_DETECTION,
                audit_id,
                detection_to_evidence(signals, masked.text, duration_ms),
            )

            stage = "decision"
            decision = decide(classification, policy)
            decision_record = self._append(
                EVENT_DECISION,
                audit_id,
                {
                    "request": request,
                    "signals": signals_to_evidence(signals),
                    "classification": classification_to_evidence(classification),
                    "policy": policy_to_evidence(policy),
                    "decision": decision_to_evidence(decision),
                },
            )

            stage = "enforcement"
            enforcement = self._enforce(audit_id, text, masked, decision, policy)
        except EvidenceUnavailableError:
            # The log cannot be written, so the failure cannot be recorded in it either.
            raise
        except Exception as exc:
            # Deliberately broad: whatever went wrong, the request must not end unrecorded.
            raise self._failed(audit_id, stage, exc) from exc
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
            model_reply=enforcement.model_reply,
            response=enforcement.response,
            retryable=enforcement.retryable,
            decision_receipt=Receipt.of(decision_record),
            outcome_receipt=Receipt.of(outcome_record),
        )

    def reject(self, reason: str, client_id: str | None = None) -> InferenceResult:
        """Record a request that was refused at the door (malformed, oversized).

        The body is never inspected or stored: it is untrusted and may be private.
        """
        audit_id = uuid.uuid4().hex
        request = {
            "prompt_hmac": None,
            "prompt_chars": None,
            "normalization_changed": False,
            "client_id_claimed": client_id,
            "rejected": reason,
        }
        self._append(EVENT_RECEIVED, audit_id, {"request": request})
        return self._refuse(
            audit_id,
            request,
            label=Label.INVALID_INPUT,
            rule_id=INVALID_REQUEST_RULE_ID,
            rationale=f"The request was rejected before inspection: {reason}.",
            reason=reason,
            response=None,
            retryable=False,
        )

    # ------------------------------------------------------------------ policy

    def change_policy(
        self,
        policy: Policy,
        *,
        base_sha256: str | None,
        note: str,
        changed_by: str,
        restored_default: bool = False,
    ) -> PolicyChange:
        """Put a new policy in force, with a signed record of who changed what and why.

        `base_sha256` is the version the change was made from. If another change came in
        since, this one is refused instead of silently undoing it. The record is written
        before the new version takes effect, so no policy is ever in force unrecorded: if
        the write fails, `EvidenceUnavailableError` is raised and nothing changes.
        """
        with self._change_lock:
            active = self._policies.active_sha256()
            if active != base_sha256:
                raise PolicyConflictError(active)
            try:
                previous: Policy | None = self._policies.current()
            except PolicyError:
                previous = None
            # Saving the version in force again is a no-op, unless it is damaged on disk:
            # then saving it again (as "restore default" does) is the repair.
            if previous is not None and previous.sha256 == policy.sha256:
                raise PolicyUnchangedError
            changes = describe_changes(previous.document if previous else None, policy.document)

            self._policies.save_snapshot(policy)
            record = self._append(
                EVENT_POLICY_CHANGED,
                SYSTEM_AUDIT_ID,
                {
                    "policy": policy_to_evidence(policy),
                    "previous": policy_to_evidence(previous),
                    "changes": changes,
                    "note": note,
                    # Who held the admin token, by its fingerprint. Never the token itself.
                    "changed_by": changed_by,
                    "restored_default": restored_default,
                },
            )
            self._policies.set_active(policy.sha256)
            with self._policy_lock:
                # The change record already says which policy is in force from here on.
                self._policy_state = policy.sha256
            logger.info("policy changed to %s v%s", policy.document.id, policy.document.version)
            return PolicyChange(policy, previous, tuple(changes), Receipt.of(record))

    def preview(self, prompt: str, draft: Policy) -> Preview:
        """What the draft and the current policy would decide for a prompt. Nothing more.

        Detection runs once, for the entity types of both policies; classification
        ignores the types a policy does not list, so each verdict is what that policy
        alone would give. No model is called, nothing is enforced and nothing is recorded:
        this is a what-if for an administrator, not a request.
        """
        text = normalize_prompt(prompt)
        try:
            current: Policy | None = self._policies.current()
        except PolicyError:
            current = None
        entity_types = set(draft.entity_types) | set(current.entity_types if current else ())
        signals = self._detectors.run(text, entity_types)
        return Preview(
            signals=signals,
            current=_verdict(signals, current) if current else None,
            draft=_verdict(signals, draft),
        )

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
                if policy is None:
                    # Logged once per change, so operators see it without a log flood.
                    logger.error("policy unavailable, blocking every request: %s", body["error"])
        return policy

    # ------------------------------------------------------------------ enforcement

    def _enforce(
        self,
        audit_id: str,
        text: str,
        masked: Redaction,
        decision: Decision,
        policy: Policy,
    ) -> _Enforcement:
        """Carry out the decision. `masked` is the prompt as the detection record keeps it."""
        if decision.action is Action.BLOCK:
            return _Enforcement(
                status=OutcomeStatus.BLOCKED,
                reason="blocked_by_policy",
                evidence=_outcome(decision, OutcomeStatus.BLOCKED, "blocked_by_policy"),
                response=policy.document.block_message,
            )

        external = decision.action in EXTERNAL_ACTIONS
        provider = self._egress.provider if external else self._sovereign
        redaction = masked if decision.action is Action.REDACT else None
        payload = redaction.text if redaction else text
        attempt = _Attempt(decision, provider, payload, redaction, started=time.monotonic())
        used = ModelUse.of(provider)

        try:
            if external:
                # Refused calls are not recorded as calls: the outcome says why not.
                self._egress.check(decision, policy)
            self._append(EVENT_MODEL_CALL, audit_id, attempt.call())
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
                response = _EXTERNAL_FAILED_MESSAGE
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
                retryable=True,
            )

        try:
            scanned, scan = self._scan_output(reply.text, policy)
        except _OutputScanFailedError as exc:
            status, reason = OutcomeStatus.WITHHELD, "output_scan_failed"
            return _Enforcement(
                status=status,
                reason=reason,
                evidence=attempt.outcome(
                    status, reason, sent=True, reply=reply, response={"scan_errors": exc.errors}
                ),
                model=used,
                forwarded_prompt=payload,
                response=_WITHHELD_MESSAGE,
                retryable=True,
            )

        output, restored = scanned, None
        if redaction and policy.document.response.restore_placeholders:
            output, restored = restore(scanned, redaction.placeholders)

        return _Enforcement(
            status=OutcomeStatus.COMPLETED,
            reason=None,
            evidence=attempt.outcome(
                OutcomeStatus.COMPLETED,
                None,
                sent=True,
                reply=reply,
                placeholders_restored=restored,
                response={"chars": len(output), **scan},
            ),
            model=used,
            forwarded_prompt=payload,
            model_reply=scanned,
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
        signals = self._detectors.run(text, policy.entity_types, skip=_skipped_on_output(policy))
        if failed := {run.name: run.error or "failed" for run in signals.detectors if not run.ok}:
            raise _OutputScanFailedError(failed)

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
        retryable: bool,
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
                "signals": signals_to_evidence(signals),
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
            model_reply=None,
            response=response,
            retryable=retryable,
            decision_receipt=Receipt.of(decision_record),
            outcome_receipt=Receipt.of(outcome_record),
        )

    def _failed(self, audit_id: str, stage: str, exc: Exception) -> RequestFailedError:
        """Record an unexpected failure as the request's last record."""
        error = type(exc).__name__
        # The stack without the message: an exception message can contain the prompt.
        logger.error(
            "request %s failed at %s with %s\n%s",
            audit_id,
            stage,
            error,
            "".join(traceback.format_tb(exc.__traceback__)),
        )
        self._append(EVENT_ERROR, audit_id, {"stage": stage, "error": error})
        return RequestFailedError(audit_id, stage)

    def _append(self, event: str, audit_id: str, body: dict[str, Any]) -> AuditRecord:
        try:
            return self._audit.append(event, audit_id, body)
        except AuditWriteError as exc:
            logger.error("audit write failed (%s) for %s: %s", event, audit_id, exc)
            raise EvidenceUnavailableError(audit_id, event) from exc


def _verdict(signals: Signals, policy: Policy) -> Verdict:
    classification = classify(signals, policy)
    return Verdict(policy, classification, decide(classification, policy))


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


def _private(findings: Sequence[Finding]) -> list[Finding]:
    """The findings that are private data, the ones masking hides.

    A prompt injection is an attack, not private data: its text stays readable, as evidence
    in the detection record. Private values inside it are found and masked on their own.
    The default policy blocks an injection before any model, so `redact` never sends one.
    """
    return [f for f in findings if f.entity_type != SEMANTIC_INJECTION]


def _skipped_on_output(policy: Policy) -> tuple[str, ...]:
    """Detectors not run on a model's answer.

    Semantic categories decide where a prompt may go, and the answer has already been
    routed. Judging it would cost another model call and add a way for the answer to be
    withheld, so the semantic detector runs on an answer only when a response rule removes
    what it finds.
    """
    document = policy.document
    removed = {e for c in document.response.redact_categories for e in document.categories[c]}
    return () if removed & set(SEMANTIC_ENTITY_TYPES) else (SEMANTIC_DETECTOR,)


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)
