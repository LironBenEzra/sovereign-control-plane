"""Signing the audit log in AWS KMS, with a fake client in place of boto3."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from control_plane import aws_kms, aws_secrets
from control_plane.audit.keys import (
    HMAC_KEY_FILE,
    PUBLIC_KEY_FILE,
    SIGNING_KEY_FILE,
    key_id,
    load_public_key,
)
from control_plane.audit.log import AuditLog, AuditWriteError
from control_plane.audit.verify import verify_chain
from control_plane.aws_kms import KmsSigner, KmsUnavailableError
from control_plane.config import Settings
from control_plane.main import build_services
from tests.conftest import DEFAULT_POLICY_PATH
from tests.test_aws_secrets import PREFIX, ClientError, FakeSecretsManager, every_secret

ALIAS = "alias/scp-demo-audit"
ARN = "arn:aws:kms:eu-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"


class FakeKms:
    """Signs with a real Ed25519 key, as KMS does with an ECC_NIST_EDWARDS25519 key."""

    def __init__(self, key_spec: str = aws_kms.KEY_SPEC) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.key_spec = key_spec
        self.errors: dict[str, str] = {}
        self.signature: bytes | None = None
        self.sign_calls: list[dict[str, str]] = []

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        if code := self.errors.get("get_public_key"):
            raise ClientError(code)
        edwards = self.key_spec == aws_kms.KEY_SPEC
        return {
            "KeyId": ARN,
            "KeySpec": self.key_spec,
            "SigningAlgorithms": ["ED25519_SHA_512", "ED25519_PH_SHA_512"]
            if edwards
            else ["ECDSA_SHA_256"],
            "PublicKey": self.key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        }

    def sign(
        self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> dict[str, Any]:
        self.sign_calls.append(
            {"KeyId": KeyId, "MessageType": MessageType, "SigningAlgorithm": SigningAlgorithm}
        )
        if code := self.errors.get("sign"):
            raise ClientError(code)
        return {"KeyId": KeyId, "Signature": self.signature or self.key.sign(Message)}


def lines(path: Path) -> list[str]:
    return path.read_text().splitlines()


def test_records_signed_in_kms_verify_like_records_signed_locally(tmp_path: Path) -> None:
    kms = FakeKms()
    log = AuditLog(tmp_path / "audit.jsonl", KmsSigner(kms, ALIAS))

    log.append("note", "id-0", {"n": 0})
    log.append("note", "id-1", {"n": 1})

    records = [dict(r) for r in log.read()]
    assert verify_chain(records, kms.key.public_key()).ok
    assert {r["key_id"] for r in records} == {key_id(kms.key.public_key())}


def test_an_unreadable_kms_key_stops_startup() -> None:
    kms = FakeKms()
    kms.errors["get_public_key"] = "AccessDeniedException"

    with pytest.raises(KmsUnavailableError, match=f"{ALIAS} could not be read: AccessDenied"):
        KmsSigner(kms, ALIAS)


def test_a_kms_failure_fails_the_write_and_the_chain_continues_after_it(tmp_path: Path) -> None:
    kms = FakeKms()
    log = AuditLog(tmp_path / "audit.jsonl", KmsSigner(kms, ALIAS))
    log.append("note", "id-0", {"n": 0})

    kms.errors["sign"] = "KMSInvalidStateException"
    with pytest.raises(AuditWriteError, match="KMSInvalidStateException"):
        log.append("note", "id-1", {"n": 1})
    assert len(lines(log.path)) == 1

    del kms.errors["sign"]
    log.append("note", "id-1", {"n": 1})
    records = [dict(r) for r in log.read()]
    assert [r["seq"] for r in records] == [0, 1]
    assert verify_chain(records, kms.key.public_key()).ok


def test_a_signature_that_does_not_verify_is_never_written(tmp_path: Path) -> None:
    kms = FakeKms()
    log = AuditLog(tmp_path / "audit.jsonl", KmsSigner(kms, ALIAS))
    kms.signature = bytes(64)

    with pytest.raises(AuditWriteError, match="does not verify"):
        log.append("note", "id-0", {"n": 0})
    assert not log.path.exists() or lines(log.path) == []


def test_with_a_kms_key_the_signing_secret_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = every_secret()
    del secrets["audit-signing-key"]
    secrets_manager = FakeSecretsManager(secrets)
    kms = FakeKms()
    monkeypatch.setattr(aws_secrets, "client", lambda: secrets_manager)
    monkeypatch.setattr(aws_kms, "client", lambda: kms)
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        policy_path=DEFAULT_POLICY_PATH,
        ui_dir=tmp_path / "no-ui",
        spacy_model="not_an_installed_model",  # keeps the test fast; Presidio is not needed
        sovereign_provider="stub",
        aws_secrets_prefix=PREFIX,
        audit_kms_key_id=ALIAS,
    )

    build_services(settings)

    assert f"{PREFIX}audit-signing-key" not in secrets_manager.asked
    key_dir = tmp_path / "data" / "keys"
    assert not (key_dir / SIGNING_KEY_FILE).exists()
    assert not (key_dir / HMAC_KEY_FILE).exists()
    # The verifier's public key is the one in KMS.
    assert key_id(load_public_key(key_dir / PUBLIC_KEY_FILE)) == key_id(kms.key.public_key())
