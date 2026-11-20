"""The HTTP edge: untrusted input in, an explainable decision and a receipt out.

Everything about handling untrusted input is in `inference` below, on purpose: the body
is read with a hard size cap, parsed strictly, and any rejection is itself audited.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from control_plane.audit.chain import EVENT_DECISION, EVENT_POLICY_CHANGED, AuditRecord
from control_plane.audit.keys import PUBLIC_KEY_FILE, load_public_key
from control_plane.audit.log import AuditLog
from control_plane.audit.verify import Report, verify_log
from control_plane.config import Settings
from control_plane.detection.base import DetectorRunner
from control_plane.egress import EgressGateway
from control_plane.models import Action, Label, OutcomeStatus
from control_plane.monitoring import ModelState, build_report, live_alerts, summarize_log
from control_plane.pipeline import (
    SYSTEM_AUDIT_ID,
    ControlPlane,
    EvidenceUnavailableError,
    InferenceResult,
    PolicyChange,
    PolicyConflictError,
    PolicyUnchangedError,
    Receipt,
    RequestFailedError,
    Verdict,
)
from control_plane.policy import (
    Policy,
    PolicyDocument,
    PolicyError,
    PolicyStore,
    describe_changes,
    policy_from_document,
)
from control_plane.providers.base import ModelProvider

logger = logging.getLogger(__name__)

_CLIENT_ID = re.compile(r"[A-Za-z0-9._:@-]{1,64}")
# A full audit ID, or its first characters as the UI shows them.
_AUDIT_ID_QUERY = re.compile(r"[0-9a-f]{4,32}")
# Sent with a 503: when a component is down, a client should wait before trying again.
_RETRY_AFTER_S = "30"
_MAX_ALERT_HOURS = 24 * 365
_MAX_AUDIT_PAGE = 100
# A policy is a few kilobytes; the cap keeps an unchecked body from filling memory.
_MAX_POLICY_BODY_BYTES = 256 * 1024
_POLICY_HISTORY = 20
# Labels a rule can match on. `invalid_input` never reaches the policy.
_RULE_LABELS = [label for label in Label if label is not Label.INVALID_INPUT]

# Why a request was refused at the door, and the HTTP status that goes with it.
_REJECTIONS = {
    "body_too_large": 413,
    "prompt_too_long": 413,
    "unsupported_media_type": 415,
    "invalid_request_body": 422,
}


@dataclass(frozen=True)
class Services:
    """Everything the HTTP layer needs, built once in the composition root."""

    settings: Settings
    control_plane: ControlPlane
    audit: AuditLog
    policies: PolicyStore
    sovereign: ModelProvider
    egress: EgressGateway
    detectors: DetectorRunner


class InferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    prompt: str = Field(min_length=1)


class FindingOut(BaseModel):
    entity_type: str
    category: str | None
    start: int
    end: int
    score: float
    detector: str
    recognizer: str
    counted: bool


class ClassificationOut(BaseModel):
    label: Label
    categories: list[str]
    rationale: str
    findings: list[FindingOut]


class PolicyOut(BaseModel):
    id: str
    version: str
    sha256: str


class DecisionOut(BaseModel):
    action: Action
    rule_id: str
    rationale: str
    fail_closed: bool


class ModelOut(BaseModel):
    provider: str
    model: str
    in_boundary: bool
    stub: bool


class ReceiptOut(BaseModel):
    seq: int
    hash: str
    sig: str
    key_id: str


class PolicyCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Validated separately, so its errors come back as a list a form can show.
    document: dict[str, Any]


class PolicySaveRequest(PolicyCheckRequest):
    # The version the edit started from, from GET /v1/policy. Null before any policy exists.
    base_sha256: str | None
    note: str = Field(min_length=1, max_length=500)


class PolicyRestoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_sha256: str | None
    note: str = Field(default="Restored the default policy.", min_length=1, max_length=500)


class PolicyPreviewRequest(PolicyCheckRequest):
    prompt: str = Field(min_length=1)


class InferenceResponse(BaseModel):
    audit_id: str
    decision: DecisionOut
    classification: ClassificationOut
    policy: PolicyOut | None
    outcome: OutcomeStatus
    outcome_reason: str | None
    model: ModelOut | None
    forwarded_prompt: str | None
    model_reply: str | None
    response: str | None
    receipts: dict[str, ReceiptOut]


def create_app(services: Services) -> FastAPI:
    app = FastAPI(
        title="Sovereign Control Plane",
        description="Enforces private-data policy in front of AI models and records evidence.",
        version="0.1.0",
    )
    settings = services.settings
    control_plane = services.control_plane
    verification = _VerificationCache(
        services.audit.path,
        settings.data_dir / "keys" / PUBLIC_KEY_FILE,
        settings.data_dir / "policies",
    )

    @app.post(
        "/v1/inference",
        response_model=InferenceResponse,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": InferenceRequest.model_json_schema()}},
            }
        },
    )
    async def inference(request: Request) -> JSONResponse:
        client_id = _claimed_client_id(request)
        try:
            prompt = await _read_prompt(request, settings)
        except _RejectedError as rejected:
            result = await run_in_threadpool(control_plane.reject, rejected.reason, client_id)
            return _respond(result, status_code=_REJECTIONS[rejected.reason])

        result = await run_in_threadpool(control_plane.handle, prompt, client_id)
        if result.retryable:
            # No answer because a component is down. A 503 tells clients and proxies to
            # retry later, instead of reading an empty answer as success.
            return _respond(result, status_code=503, headers={"Retry-After": _RETRY_AFTER_S})
        return _respond(result)

    @app.exception_handler(ValidationError)
    async def invalid_body(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": _policy_errors(exc)})

    @app.exception_handler(EvidenceUnavailableError)
    async def evidence_unavailable(_: Request, exc: EvidenceUnavailableError) -> JSONResponse:
        # Fail closed: with no evidence there is no answer, even if a model already replied.
        return JSONResponse(
            status_code=503,
            content={
                "error": "audit_unavailable",
                "detail": "Audit evidence could not be written, so no response is returned.",
                "audit_id": exc.audit_id,
                "stage": exc.stage,
            },
        )

    @app.exception_handler(RequestFailedError)
    async def request_failed(_: Request, exc: RequestFailedError) -> JSONResponse:
        # The failure is in the audit log; the audit ID finds its records.
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "detail": "The request failed on an internal error, so no response is "
                "returned. The audit log records the step that failed.",
                "audit_id": exc.audit_id,
                "stage": exc.stage,
            },
        )

    _add_audit_routes(app, services)
    _add_policy_routes(app, services)

    @app.get("/v1/alerts")
    def alerts(hours: int = 24) -> dict[str, Any]:
        """What needs an admin's attention now and in the last `hours`, with metrics.

        Read-only and derived: from live status and the audit log, never from prompt text.
        """
        if not 1 <= hours <= _MAX_ALERT_HOURS:
            raise HTTPException(
                status_code=422, detail=f"hours must be between 1 and {_MAX_ALERT_HOURS}"
            )
        return _alerts_report(services, verification, hours)

    @app.get("/healthz")
    def health() -> JSONResponse:
        sovereign = services.sovereign
        external = services.egress.provider
        failing = services.detectors.failing()
        policy_error = _load_policy(services.policies)[1]
        # While a detector is failing or the policy is broken, every answer is withheld
        # or blocked, so monitoring, load balancers and the UI must see it as not healthy.
        degraded = bool(failing) or policy_error is not None
        body: dict[str, Any] = {
            "status": "degraded" if degraded else "ok",
            "policy": {"valid": policy_error is None, "error": policy_error},
            "detectors": services.detectors.versions(),
            "failing_detectors": failing,
            "sovereign_model": {
                "provider": sovereign.name,
                "model": sovereign.model,
                "stub": sovereign.is_stub,
                **vars(sovereign.status()),
            },
            "external_model": {
                "provider": external.name,
                "model": external.model,
                "stub": external.is_stub,
                **vars(external.status()),
            },
        }
        return JSONResponse(status_code=503 if degraded else 200, content=body)

    if settings.ui_dir.is_dir():
        app.mount("/", StaticFiles(directory=settings.ui_dir, html=True), name="ui")

    return app


def _add_audit_routes(app: FastAPI, services: Services) -> None:
    """Read-only views of the audit log. Open to anyone, like GET /v1/policy."""
    settings = services.settings

    @app.get("/v1/audit")
    def list_audit(limit: int = 100, audit_id: str | None = None) -> dict[str, Any]:
        """Newest records first. `audit_id` keeps the requests whose ID starts with it."""
        records = services.audit.read()
        if audit_id is not None:
            prefix = _audit_id_prefix(audit_id)
            records = [r for r in records if r["audit_id"].startswith(prefix)]
        newest_first = records[::-1][: max(1, min(limit, 1000))]
        return {"total": len(records), "records": newest_first}

    @app.get("/v1/audit/requests")
    def list_audit_requests(
        *,
        limit: int = 25,
        before: int | None = None,
        audit_id: str | None = None,
        action: Action | None = None,
        rule_id: str | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        """The log one request at a time, newest first, each with its records in order.

        A policy record belongs to no request, so it is an entry of its own. Entries are
        ordered by their first record. For the next page, pass the previous page's
        `next_before`; a page never splits a request. `audit_id` keeps the requests whose
        ID starts with it. `action`, `rule_id` and `category` keep the requests whose
        decision has them; `options` lists the rules and categories in the whole log.
        """
        entries = _group_by_request(services.audit.read())
        decisions = [d for e in entries if (d := _decision_body(e))]
        options = {
            "rules": sorted({d["decision"]["rule_id"] for d in decisions}),
            "categories": sorted({c for d in decisions for c in d["classification"]["categories"]}),
        }
        if audit_id is not None:
            prefix = _audit_id_prefix(audit_id)
            entries = [e for e in entries if e[0]["audit_id"].startswith(prefix)]
        if action is not None or rule_id is not None or category is not None:
            entries = [e for e in entries if _decision_matches(e, action, rule_id, category)]
        newest_first = entries[::-1]
        if before is not None:
            newest_first = [e for e in newest_first if e[0]["seq"] < before]
        page = newest_first[: max(1, min(limit, _MAX_AUDIT_PAGE))]
        return {
            "total": len(entries),
            "entries": [{"audit_id": e[0]["audit_id"], "records": e} for e in page],
            "next_before": page[-1][0]["seq"] if len(newest_first) > len(page) else None,
            "options": options,
        }

    @app.get("/v1/audit/verify")
    def verify_audit() -> dict[str, Any]:
        public_key = load_public_key(settings.data_dir / "keys" / PUBLIC_KEY_FILE)
        report = verify_log(services.audit.path, public_key, settings.data_dir / "policies")
        return report.to_dict()

    @app.get("/v1/audit/{audit_id}")
    def get_audit(audit_id: str) -> dict[str, Any]:
        records = [r for r in services.audit.read() if r["audit_id"] == audit_id]
        if not records:
            raise HTTPException(status_code=404, detail="no audit records for this id")
        return {"audit_id": audit_id, "records": records}


def _add_policy_routes(app: FastAPI, services: Services) -> None:
    """Reading the policy is open. Changing it, or previewing a draft, needs the admin token."""
    settings = services.settings
    control_plane = services.control_plane

    @app.get("/v1/policy")
    def get_policy() -> dict[str, Any]:
        """The policy in force, what the editor can offer, and the recorded changes."""
        policy, error = _load_policy(services.policies)
        default, _ = _default_policy(services.policies)
        body: dict[str, Any] = {
            "valid": policy is not None,
            "error": error,
            # What a save must name as its starting point, even while the policy is broken.
            "base_sha256": _active_sha256(services.policies),
            "editable": settings.admin_token_value is not None,
            "is_default": policy is not None
            and default is not None
            and policy.sha256 == default.sha256,
            "catalog": {
                "entity_types": services.detectors.catalog(),
                "labels": [label.value for label in _RULE_LABELS],
                "actions": [action.value for action in Action],
                "destinations": sorted(
                    {services.egress.provider.name}
                    | set(policy.document.egress.allowed_destinations if policy else ())
                ),
            },
            "history": _policy_history(services.audit),
            "text": policy.raw.decode("utf-8") if policy else None,
            "document": policy.document.model_dump(mode="json") if policy else None,
        }
        if policy is not None:
            body |= {
                "id": policy.document.id,
                "version": policy.document.version,
                "sha256": policy.sha256,
            }
        return body

    @app.post("/v1/policy/check")
    async def check_policy(request: Request) -> dict[str, Any]:
        """Validate a draft and say what saving it would change. Changes nothing.

        Open to anyone, like GET /v1/policy: it runs no detector and no model.
        """
        draft = PolicyCheckRequest.model_validate(await _read_json(request))
        try:
            document = PolicyDocument.model_validate(draft.document)
        except ValidationError as exc:
            return {"valid": False, "errors": _policy_errors(exc), "changes": []}
        current, _ = _load_policy(services.policies)
        changes = describe_changes(current.document if current else None, document)
        return {"valid": True, "errors": [], "changes": changes}

    @app.put("/v1/policy")
    async def save_policy(request: Request) -> dict[str, Any]:
        changed_by = _require_admin(request, settings)
        save = PolicySaveRequest.model_validate(await _read_json(request))
        policy = _policy_or_422(save.document)
        change = await run_in_threadpool(
            _change_policy,
            control_plane,
            policy,
            base_sha256=save.base_sha256,
            note=save.note,
            changed_by=changed_by,
        )
        return _change_out(change)

    @app.post("/v1/policy/restore-default")
    async def restore_default_policy(request: Request) -> dict[str, Any]:
        changed_by = _require_admin(request, settings)
        restore = PolicyRestoreRequest.model_validate(await _read_json(request))
        default, error = _default_policy(services.policies)
        if default is None:
            raise HTTPException(status_code=500, detail=f"The default policy is unusable: {error}")
        change = await run_in_threadpool(
            _change_policy,
            control_plane,
            default,
            base_sha256=restore.base_sha256,
            note=restore.note,
            changed_by=changed_by,
            restored_default=True,
        )
        return _change_out(change)

    @app.post("/v1/policy/preview")
    async def preview_policy(request: Request) -> dict[str, Any]:
        """What a draft would decide for one prompt, next to the policy in force.

        Admin only: it runs the detectors, including the local model, on any text.
        """
        _require_admin(request, settings)
        preview = PolicyPreviewRequest.model_validate(await _read_json(request))
        if len(preview.prompt) > settings.max_prompt_chars:
            raise HTTPException(status_code=413, detail="The prompt is too long.")
        draft = _policy_or_422(preview.document)
        result = await run_in_threadpool(control_plane.preview, preview.prompt, draft)
        current = _verdict_out(result.current) if result.current else None
        proposed = _verdict_out(result.draft)
        return {
            "current": current,
            "draft": proposed,
            "changed": current is None
            or (current["action"], current["rule_id"]) != (proposed["action"], proposed["rule_id"]),
        }


class _RejectedError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def _read_prompt(request: Request, settings: Settings) -> str:
    """Read and validate the request body, never trusting its size or shape."""
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != "application/json":
        raise _RejectedError("unsupported_media_type")

    limit = settings.max_body_bytes
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise _RejectedError("body_too_large")

    # Content-Length can be absent or wrong, so the stream is counted as it arrives.
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise _RejectedError("body_too_large")

    try:
        parsed = InferenceRequest.model_validate_json(bytes(body))
    except ValidationError as exc:
        raise _RejectedError("invalid_request_body") from exc
    if len(parsed.prompt) > settings.max_prompt_chars:
        raise _RejectedError("prompt_too_long")
    return parsed.prompt


def _claimed_client_id(request: Request) -> str | None:
    value = request.headers.get("x-client-id", "")
    return value if _CLIENT_ID.fullmatch(value) else None


def _load_policy(policies: PolicyStore) -> tuple[Policy | None, str | None]:
    """The policy in force, or the first line of the reason there is none."""
    try:
        return policies.current(), None
    except PolicyError as exc:
        return None, str(exc).splitlines()[0]


def _alerts_report(
    services: Services, verification: _VerificationCache, hours: int
) -> dict[str, Any]:
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    policy, policy_error = _load_policy(services.policies)
    live = live_alerts(
        policy_error=policy_error,
        failing_detectors=services.detectors.failing(),
        sovereign=_model_state(services.sovereign),
        external=_model_state(services.egress.provider),
        verification=verification.report(),
    )
    rule_ids = [rule.id for rule in policy.document.rules] if policy else []
    summary = summarize_log(services.audit.read(), since=since, now=now, rule_ids=rule_ids)
    return build_report(live, summary, hours=hours, since=since, now=now)


def _model_state(provider: ModelProvider) -> ModelState:
    return ModelState(name=provider.name, stub=provider.is_stub, status=provider.status())


class _VerificationCache:
    """Verifies the audit log again only when the file has changed since the last check.

    The Alerts tab polls, and verification checks every signature and replays every
    decision, so repeating it for an unchanged log would be wasted work.
    """

    def __init__(self, log_path: Path, public_key_path: Path, policy_dir: Path) -> None:
        self._log_path = log_path
        self._public_key_path = public_key_path
        self._policy_dir = policy_dir
        self._lock = threading.Lock()
        self._stamp: tuple[int, int] | None = None
        self._report: Report | None = None

    def report(self) -> Report:
        try:
            stat = self._log_path.stat()
            stamp: tuple[int, int] | None = (stat.st_size, stat.st_mtime_ns)
        except FileNotFoundError:
            stamp = None
        with self._lock:
            if self._report is None or stamp != self._stamp:
                public_key = load_public_key(self._public_key_path)
                self._report = verify_log(self._log_path, public_key, self._policy_dir)
                self._stamp = stamp
            return self._report


# ---------------------------------------------------------------------- policy editing


def _require_admin(request: Request, settings: Settings) -> str:
    """Check the admin token before the body is read. Returns who acted, for the audit log.

    The audit log records a fingerprint of the token, never the token: enough to tell a
    rotated token from the old one.
    """
    token = settings.admin_token_value
    if token is None:
        raise HTTPException(
            status_code=403,
            detail="Policy editing is turned off on this server: SCP_ADMIN_TOKEN is not set.",
        )
    scheme, _, presented = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        presented.strip().encode(), token.encode()
    ):
        logger.warning("policy change refused: the admin token was missing or wrong")
        raise HTTPException(
            status_code=401,
            detail="The admin token is missing or wrong.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "admin-token:" + hashlib.sha256(token.encode()).hexdigest()[:8]


async def _read_json(request: Request) -> Any:
    """Read a JSON body with a hard size cap, counted as it streams."""
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != "application/json":
        raise HTTPException(status_code=415, detail="Send application/json.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_POLICY_BODY_BYTES:
            raise HTTPException(status_code=413, detail="The request body is too large.")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="The body is not valid JSON.") from exc


def _policy_or_422(document: dict[str, Any]) -> Policy:
    try:
        return policy_from_document(PolicyDocument.model_validate(document))
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"message": "The policy is not valid.", "errors": _policy_errors(exc)},
        ) from exc
    except PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc).splitlines()[0]) from exc


def _policy_errors(exc: ValidationError) -> list[dict[str, str]]:
    """Each problem with the path to the field it is about, such as `rules.2.action`."""
    return [
        {
            "path": ".".join(str(part) for part in error["loc"]),
            "message": error["msg"].removeprefix("Value error, "),
        }
        for error in exc.errors(include_url=False, include_input=False)
    ]


def _change_policy(
    control_plane: ControlPlane,
    policy: Policy,
    *,
    base_sha256: str | None,
    note: str,
    changed_by: str,
    restored_default: bool = False,
) -> PolicyChange:
    try:
        return control_plane.change_policy(
            policy,
            base_sha256=base_sha256,
            note=note,
            changed_by=changed_by,
            restored_default=restored_default,
        )
    except PolicyConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail="The policy was changed by someone else after you loaded it. Reload it, "
            "then make your change again.",
        ) from exc
    except PolicyUnchangedError as exc:
        raise HTTPException(
            status_code=422, detail="This is already the policy in force: nothing to save."
        ) from exc


def _change_out(change: PolicyChange) -> dict[str, Any]:
    document = change.policy.document
    return {
        "policy": {"id": document.id, "version": document.version, "sha256": change.policy.sha256},
        "changes": list(change.changes),
        "receipt": vars(change.receipt),
    }


def _verdict_out(verdict: Verdict) -> dict[str, Any]:
    classification = verdict.classification
    counted = set(classification.counted)
    return {
        "policy_version": verdict.policy.document.version,
        "label": classification.label.value,
        "categories": list(classification.categories),
        "action": verdict.decision.action.value,
        "rule_id": verdict.decision.rule_id,
        "rationale": verdict.decision.rationale,
        "fail_closed": verdict.decision.fail_closed,
        # What was found and how it counted under this policy, never the matched text.
        "findings": sorted(
            {f.entity_type for f in counted if verdict.policy.category_of(f.entity_type)}
        ),
    }


def _audit_id_prefix(value: str) -> str:
    prefix = value.strip().lower()
    if not _AUDIT_ID_QUERY.fullmatch(prefix):
        raise HTTPException(
            status_code=422, detail="audit_id must be 4 to 32 hexadecimal characters"
        )
    return prefix


def _decision_body(records: Sequence[AuditRecord]) -> dict[str, Any] | None:
    """A request's decision record body. None for a request with no decision."""
    return next((r["body"] for r in records if r["event"] == EVENT_DECISION), None)


def _decision_matches(
    records: Sequence[AuditRecord],
    action: Action | None,
    rule_id: str | None,
    category: str | None,
) -> bool:
    decision = _decision_body(records)
    if decision is None:
        return False
    return (
        (action is None or decision["decision"]["action"] == action)
        and (rule_id is None or decision["decision"]["rule_id"] == rule_id)
        and (category is None or category in decision["classification"]["categories"])
    )


def _group_by_request(records: Sequence[AuditRecord]) -> list[list[AuditRecord]]:
    """Each request's records together, in the order the requests arrived.

    Requests can overlap in the log, so a request's records are not always next to each
    other. A record that belongs to no request (a policy load or change) is a group of its own.
    """
    by_request: dict[str, list[AuditRecord]] = {}
    groups: list[list[AuditRecord]] = []
    for record in records:
        if record["audit_id"] == SYSTEM_AUDIT_ID:
            groups.append([record])
            continue
        group = by_request.get(record["audit_id"])
        if group is None:
            group = by_request[record["audit_id"]] = []
            groups.append(group)
        group.append(record)
    return groups


def _policy_history(audit: AuditLog) -> list[dict[str, Any]]:
    """The most recent policy changes, newest first, straight from the signed log."""
    changes = [r for r in audit.read() if r["event"] == EVENT_POLICY_CHANGED]
    return [
        {"seq": r["seq"], "ts": r["ts"], **r["body"]} for r in reversed(changes[-_POLICY_HISTORY:])
    ]


def _default_policy(policies: PolicyStore) -> tuple[Policy | None, str | None]:
    try:
        return policies.default(), None
    except PolicyError as exc:
        return None, str(exc).splitlines()[0]


def _active_sha256(policies: PolicyStore) -> str | None:
    try:
        return policies.active_sha256()
    except PolicyError:
        return None


def _respond(
    result: InferenceResult, status_code: int = 200, headers: dict[str, str] | None = None
) -> JSONResponse:
    policy = result.policy
    counted = set(result.classification.counted)
    body = InferenceResponse(
        audit_id=result.audit_id,
        decision=DecisionOut(**vars(result.decision)),
        classification=ClassificationOut(
            label=result.classification.label,
            categories=list(result.classification.categories),
            rationale=result.classification.rationale,
            findings=[
                FindingOut(
                    **vars(finding),
                    category=policy.category_of(finding.entity_type) if policy else None,
                    counted=finding in counted,
                )
                for finding in result.signals.findings
            ],
        ),
        policy=(
            PolicyOut(id=policy.document.id, version=policy.document.version, sha256=policy.sha256)
            if policy
            else None
        ),
        outcome=result.status,
        outcome_reason=result.reason,
        model=ModelOut(**vars(result.model)) if result.model else None,
        forwarded_prompt=result.forwarded_prompt,
        model_reply=result.model_reply,
        response=result.response,
        receipts={
            "decision": _receipt(result.decision_receipt),
            "outcome": _receipt(result.outcome_receipt),
        },
    )
    return JSONResponse(
        status_code=status_code, content=body.model_dump(mode="json"), headers=headers
    )


def _receipt(receipt: Receipt) -> ReceiptOut:
    return ReceiptOut(**vars(receipt))
