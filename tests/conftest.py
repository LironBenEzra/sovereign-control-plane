"""Shared fakes and a harness that builds a real control plane around them.

Only the two real boundaries are faked: detectors and model providers. Policy, audit,
classification and enforcement are always the real code.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from control_plane.audit.chain import AuditRecord
from control_plane.audit.keys import (
    PUBLIC_KEY_FILE,
    load_or_create_hmac_key,
    load_or_create_signing_key,
    load_public_key,
)
from control_plane.audit.log import AuditLog, AuditWriteError
from control_plane.audit.verify import Report, verify_log
from control_plane.detection.base import Detector, DetectorRunner
from control_plane.detection.rules import RuleDetector
from control_plane.egress import EgressGateway
from control_plane.models import Finding
from control_plane.pipeline import ControlPlane, PolicyChange
from control_plane.policy import Policy, PolicyStore, parse_policy
from control_plane.providers.base import ModelReply, ProviderError, ProviderStatus

DEFAULT_POLICY_PATH = Path(__file__).parent.parent / "policy" / "policy.yaml"

EMAIL = "dana.levi@example.com"
PERSON = "Dana Levi"
SSN = "536-90-4399"
WEAK_PHONE = "212-555-0123"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# What the fake PII detector "knows". Scores mirror what Presidio gives these types.
KNOWN_PII: dict[str, tuple[str, float]] = {
    EMAIL: ("EMAIL_ADDRESS", 1.0),
    PERSON: ("PERSON", 0.85),
    SSN: ("US_SSN", 0.85),
    WEAK_PHONE: ("PHONE_NUMBER", 0.4),
}


class KeywordDetector:
    """Finds fixed strings. Stands in for Presidio so tests do not load a model."""

    version = "test"

    def __init__(
        self,
        known: Mapping[str, tuple[str, float]] = KNOWN_PII,
        name: str = "fake-pii",
        error: Exception | None = None,
        delay_s: float = 0.0,
        fail_when: Callable[[str], bool] | None = None,
    ) -> None:
        self.name = name
        self._known = known
        self.entity_types = frozenset(entity_type for entity_type, _ in known.values())
        self.error = error
        self._fail_when = fail_when
        self._delay_s = delay_s
        self.calls: list[str] = []

    def detect(self, text: str, entity_types: Collection[str]) -> list[Finding]:
        self.calls.append(text)
        if self._delay_s:
            time.sleep(self._delay_s)
        if self.error is not None:
            raise self.error
        if self._fail_when is not None and self._fail_when(text):
            raise RuntimeError("detector failed on this text")
        findings = []
        for needle, (entity_type, score) in self._known.items():
            start = text.find(needle)
            while start != -1 and entity_type in entity_types:
                findings.append(
                    Finding(entity_type, start, start + len(needle), score, self.name, "keyword")
                )
                start = text.find(needle, start + 1)
        return findings


class FakeProvider:
    is_stub = False
    model = "fake-model"

    def __init__(
        self,
        name: str,
        in_boundary: bool,
        reply: str | Callable[[str], str] | None = None,
        error: str | None = None,
    ) -> None:
        self.name = name
        self.in_boundary = in_boundary
        self._reply = reply
        self.error = error
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> ModelReply:
        self.prompts.append(prompt)
        if self.error:
            raise ProviderError(self.error)
        if callable(self._reply):
            text = self._reply(prompt)
        else:
            text = self._reply if self._reply is not None else f"echo: {prompt}"
        return ModelReply(text=text, served_by=self.model)

    def status(self) -> ProviderStatus:
        return ProviderStatus(ready=True, detail="fake")


class FlakyAuditLog(AuditLog):
    """A real audit log that can be told to fail on chosen event types."""

    fail_on: frozenset[str] = frozenset()

    def append(self, event: str, audit_id: str, body: Mapping[str, Any]) -> AuditRecord:
        if event in self.fail_on:
            raise AuditWriteError("disk full")
        return super().append(event, audit_id, body)


@dataclass
class Harness:
    plane: ControlPlane
    audit: FlakyAuditLog
    policies: PolicyStore
    egress: EgressGateway
    sovereign: FakeProvider
    external: FakeProvider
    detectors: Sequence[Detector]
    runner: DetectorRunner
    data_dir: Path
    policy_path: Path

    def records(self, event: str | None = None) -> list[AuditRecord]:
        return [r for r in self.audit.read() if event is None or r["event"] == event]

    def verify(self) -> Report:
        public_key = load_public_key(self.data_dir / "keys" / PUBLIC_KEY_FILE)
        return verify_log(self.audit.path, public_key, self.data_dir / "policies")

    def log_text(self) -> str:
        return self.audit.path.read_text(encoding="utf-8")

    def change_policy(self, text: str, note: str = "test change") -> PolicyChange:
        """Put a policy in force the way an administrator does: through the control plane."""
        return self.plane.change_policy(
            parse_policy(text.encode()),
            base_sha256=self.policies.active_sha256(),
            note=note,
            changed_by="admin-token:test",
        )

    def corrupt_policy(self) -> None:
        """Damage the stored version in force, as a disk fault or someone with disk access would."""
        sha256 = self.policies.current().sha256
        snapshot = self.data_dir / "policies" / f"{sha256}.yaml"
        snapshot.write_text("rules: this is not a valid policy")


HarnessFactory = Callable[..., Harness]


@pytest.fixture
def default_policy() -> Policy:
    return parse_policy(DEFAULT_POLICY_PATH.read_bytes())


@pytest.fixture
def make_harness(tmp_path: Path) -> HarnessFactory:
    def build(
        *,
        policy_text: str | None = None,
        detectors: Sequence[Detector] | None = None,
        sovereign: FakeProvider | None = None,
        external: FakeProvider | None = None,
        detection_timeout_s: float = 5.0,
    ) -> Harness:
        data_dir = tmp_path / "data"
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            policy_text if policy_text is not None else DEFAULT_POLICY_PATH.read_text()
        )
        key_dir = data_dir / "keys"
        audit = FlakyAuditLog(
            data_dir / "audit" / "audit.jsonl", load_or_create_signing_key(key_dir)
        )
        sovereign = sovereign or FakeProvider("ollama", in_boundary=True)
        external = external or FakeProvider("anthropic", in_boundary=False)
        detectors = detectors if detectors is not None else [RuleDetector(), KeywordDetector()]
        policies = PolicyStore(policy_path, data_dir / "policies")
        egress = EgressGateway(external)
        runner = DetectorRunner(detectors, detection_timeout_s)
        plane = ControlPlane(
            detectors=runner,
            policies=policies,
            audit=audit,
            sovereign=sovereign,
            egress=egress,
            hmac_key=load_or_create_hmac_key(key_dir),
        )
        return Harness(
            plane,
            audit,
            policies,
            egress,
            sovereign,
            external,
            detectors,
            runner,
            data_dir,
            policy_path,
        )

    return build
