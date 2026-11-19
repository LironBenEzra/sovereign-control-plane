"""Composition root: build every component once and wire them together.

Run with:  uvicorn control_plane.main:create_app --factory
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from control_plane.api import Services
from control_plane.api import create_app as create_api
from control_plane.audit.keys import load_or_create_hmac_key, load_or_create_signing_key
from control_plane.audit.log import AuditLog
from control_plane.config import Settings
from control_plane.detection.base import Detector, DetectorRunner
from control_plane.detection.presidio import DETECTOR_NAME as PRESIDIO
from control_plane.detection.presidio import PresidioDetector, UnavailableDetector
from control_plane.detection.rules import RuleDetector
from control_plane.egress import EgressGateway
from control_plane.pipeline import ControlPlane
from control_plane.policy import PolicyStore
from control_plane.providers.anthropic import AnthropicProvider
from control_plane.providers.base import ModelProvider
from control_plane.providers.ollama import OllamaProvider
from control_plane.providers.stub import StubProvider

logger = logging.getLogger(__name__)

STUB_SOVEREIGN = "stub-sovereign"
STUB_EXTERNAL = "stub-external"


def build_services(settings: Settings) -> Services:
    key_dir = settings.data_dir / "keys"
    audit = AuditLog(
        settings.data_dir / "audit" / "audit.jsonl", load_or_create_signing_key(key_dir)
    )
    policies = PolicyStore(settings.policy_path, settings.data_dir / "policies")
    detectors: list[Detector] = [RuleDetector(), _presidio(settings)]
    sovereign = _sovereign(settings)
    egress = EgressGateway(_external(settings))

    control_plane = ControlPlane(
        detectors=DetectorRunner(detectors, settings.detection_timeout_s),
        policies=policies,
        audit=audit,
        sovereign=sovereign,
        egress=egress,
        hmac_key=load_or_create_hmac_key(key_dir),
    )
    return Services(
        settings=settings,
        control_plane=control_plane,
        audit=audit,
        policies=policies,
        sovereign=sovereign,
        egress=egress,
        detector_versions={d.name: d.version for d in detectors},
    )


def _presidio(settings: Settings) -> Detector:
    try:
        return PresidioDetector(settings.spacy_model)
    except Exception as exc:
        # Deliberately broad. If the NER model cannot load, the service must still
        # start and fail closed on every request, not crash and not run without it.
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
    use_anthropic = settings.external_provider == "anthropic" or (
        settings.external_provider == "auto" and key
    )
    if not use_anthropic:
        return StubProvider(STUB_EXTERNAL, in_boundary=False)
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
