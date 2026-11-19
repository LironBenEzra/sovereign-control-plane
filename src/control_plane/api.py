"""The HTTP edge: untrusted input in, an explainable decision and a receipt out.

Everything about handling untrusted input is in `inference` below, on purpose: the body
is read with a hard size cap, parsed strictly, and any rejection is itself audited.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from control_plane.audit.keys import PUBLIC_KEY_FILE, load_public_key
from control_plane.audit.log import AuditLog
from control_plane.audit.verify import verify_log
from control_plane.config import Settings
from control_plane.egress import EgressGateway
from control_plane.models import Action, Label, OutcomeStatus
from control_plane.pipeline import (
    ControlPlane,
    EvidenceUnavailableError,
    InferenceResult,
    Receipt,
)
from control_plane.policy import PolicyError, PolicyStore
from control_plane.providers.base import ModelProvider

_CLIENT_ID = re.compile(r"[A-Za-z0-9._:@-]{1,64}")

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
    detector_versions: dict[str, str]


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


class InferenceResponse(BaseModel):
    audit_id: str
    decision: DecisionOut
    classification: ClassificationOut
    policy: PolicyOut | None
    outcome: OutcomeStatus
    outcome_reason: str | None
    model: ModelOut | None
    forwarded_prompt: str | None
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
        return _respond(result)

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

    @app.get("/v1/audit")
    def list_audit(limit: int = 100) -> dict[str, Any]:
        records = services.audit.read()
        newest_first = records[::-1][: max(1, min(limit, 1000))]
        return {"total": len(records), "records": newest_first}

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

    @app.get("/v1/policy")
    def get_policy() -> dict[str, Any]:
        text = _read_text(settings.policy_path)
        try:
            policy = services.policies.current()
        except PolicyError as exc:
            return {"valid": False, "error": str(exc).splitlines()[0], "text": text}
        return {
            "valid": True,
            "id": policy.document.id,
            "version": policy.document.version,
            "sha256": policy.sha256,
            "text": text,
        }

    @app.get("/healthz")
    def health() -> dict[str, Any]:
        sovereign = services.sovereign
        external = services.egress.provider
        return {
            "status": "ok",
            "detectors": services.detector_versions,
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

    if settings.ui_dir.is_dir():
        app.mount("/", StaticFiles(directory=settings.ui_dir, html=True), name="ui")

    return app


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


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _respond(result: InferenceResult, status_code: int = 200) -> JSONResponse:
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
        response=result.response,
        receipts={
            "decision": _receipt(result.decision_receipt),
            "outcome": _receipt(result.outcome_receipt),
        },
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def _receipt(receipt: Receipt) -> ReceiptOut:
    return ReceiptOut(**vars(receipt))
