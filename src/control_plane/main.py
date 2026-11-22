"""Composition root: build every component once and wire them together.

Run with:  uvicorn control_plane.main:create_app --factory
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from pydantic import SecretStr

from control_plane import aws_kms, aws_secrets
from control_plane.api import Services
from control_plane.api import create_app as create_api
from control_plane.audit.keys import (
    load_or_create_hmac_key,
    load_or_create_signing_key,
    write_public_key,
)
from control_plane.audit.log import AuditLog
from control_plane.audit.signing import LocalSigner, Signer
from control_plane.config import Settings
from control_plane.detection.base import Detector, DetectorRunner
from control_plane.detection.presidio import DETECTOR_NAME as PRESIDIO
from control_plane.detection.presidio import PresidioDetector, UnavailableDetector
from control_plane.detection.rules import RuleDetector
from control_plane.detection.semantic import SemanticDetector
from control_plane.egress import EgressGateway
from control_plane.pipeline import ControlPlane
from control_plane.policy import PolicyStore
from control_plane.providers.anthropic import AnthropicProvider
from control_plane.providers.base import ModelProvider
from control_plane.providers.ollama import OllamaProvider
from control_plane.providers.stub import StubProvider

logger = logging.getLogger(__name__)

STUB_SOVEREIGN = "stub-sovereign"

# Run once at startup, so /healthz reports a broken detector before the first request.
# One entity type per detector, so each does real work.
_SELF_CHECK_TEXT = "Startup self-check."
_SELF_CHECK_TYPES = ("AWS_ACCESS_KEY", "PERSON")


def build_services(settings: Settings) -> Services:
    settings, signer, hmac_key = _secrets(settings)
    audit = AuditLog(settings.data_dir / "audit" / "audit.jsonl", signer)
    policies = PolicyStore(settings.policy_path, settings.data_dir / "policies")
    runner = DetectorRunner(
        [RuleDetector(), _presidio(settings)],
        settings.detection_timeout_s,
        masked_text_detectors=_semantic(settings),
    )
    runner.run(_SELF_CHECK_TEXT, _SELF_CHECK_TYPES)
    if failing := runner.failing():
        logger.error("detectors failing at startup: %s", failing)
    sovereign = _sovereign(settings)
    egress = EgressGateway(_external(settings))

    control_plane = ControlPlane(
        detectors=runner,
        policies=policies,
        audit=audit,
        sovereign=sovereign,
        egress=egress,
        hmac_key=hmac_key,
    )
    return Services(
        settings=settings,
        control_plane=control_plane,
        audit=audit,
        policies=policies,
        sovereign=sovereign,
        egress=egress,
        detectors=runner,
    )


def _secrets(settings: Settings) -> tuple[Settings, Signer, bytes]:
    """The audit signer and HMAC key, and the settings with the secrets in force.

    With a Secrets Manager prefix, every secret comes from there and none is read from the
    environment or written to disk. With a KMS key, the signing key is not read at all.
    Either way only the public key is written, for the verifier.
    """
    key_dir = settings.data_dir / "keys"
    prefix = settings.aws_secrets_prefix
    kms_key = settings.audit_kms_key_id
    secrets_client = aws_secrets.client() if prefix else None

    signer: Signer
    if kms_key:
        signer = aws_kms.KmsSigner(aws_kms.client(), kms_key)
        logger.info("audit records are signed in AWS KMS with %s", kms_key)
    elif secrets_client and prefix:
        signer = LocalSigner(aws_secrets.load_signing_key(secrets_client, prefix))
    else:
        signer = LocalSigner(load_or_create_signing_key(key_dir))
    write_public_key(key_dir, signer.public_key)

    if not (secrets_client and prefix):
        return settings, signer, load_or_create_hmac_key(key_dir)

    found = aws_secrets.load(secrets_client, prefix)
    logger.info("secrets read from AWS Secrets Manager under %s", prefix)
    settings = settings.model_copy(
        update={
            "admin_token": SecretStr(found.admin_token) if found.admin_token else None,
            "anthropic_api_key": (
                SecretStr(found.anthropic_api_key) if found.anthropic_api_key else None
            ),
        }
    )
    return settings, signer, found.hmac_key


def _semantic(settings: Settings) -> list[Detector]:
    if settings.sovereign_provider == "stub":
        # Not in the list at all, so every audit record shows it did not run.
        logger.warning(
            "semantic detection is off: it needs Ollama, and the sovereign model is the stub"
        )
        return []
    # Its HTTP timeout matches the detection budget, so a call the runner has given up on
    # does not keep a worker thread busy for longer.
    return [
        SemanticDetector(
            settings.ollama_url, settings.sovereign_model, settings.detection_timeout_s
        )
    ]


def _presidio(settings: Settings) -> Detector:
    try:
        return PresidioDetector(settings.spacy_model)
    except (Exception, SystemExit) as exc:
        # Deliberately broad. If the NER model cannot load, the service must still
        # start and fail closed on every request, not crash and not run without it.
        # SystemExit is included because spaCy calls sys.exit when a model download fails.
        logger.error("Presidio could not be loaded (%s); failing closed", type(exc).__name__)
        return UnavailableDetector(PRESIDIO, type(exc).__name__)


def _sovereign(settings: Settings) -> ModelProvider:
    if settings.sovereign_provider == "stub":
        return StubProvider(STUB_SOVEREIGN, in_boundary=True)
    return OllamaProvider(settings.ollama_url, settings.sovereign_model, settings.model_timeout_s)


def _external(settings: Settings) -> ModelProvider:
    # An empty variable (as Compose passes when no key is set) means no key.
    secret = settings.anthropic_api_key
    key = (secret.get_secret_value() if secret else "") or None
    if not key:
        logger.warning("no ANTHROPIC_API_KEY: prompts the policy lets out are refused")
    return AnthropicProvider(
        model=settings.external_model,
        timeout_s=settings.model_timeout_s,
        refusal_fallback=settings.external_refusal_fallback,
        api_key=key,
    )


def create_app() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return create_api(build_services(Settings()))
