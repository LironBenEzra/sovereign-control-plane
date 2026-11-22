"""Secrets from AWS Secrets Manager, with a fake client in place of boto3."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from control_plane import aws_secrets
from control_plane.audit.keys import (
    HMAC_KEY_FILE,
    PUBLIC_KEY_FILE,
    SIGNING_KEY_FILE,
    export_key,
    key_id,
    load_or_create_hmac_key,
    load_or_create_signing_key,
    load_public_key,
    signing_key_from_pem,
    signing_key_to_pem,
)
from control_plane.aws_secrets import SecretsUnavailableError
from control_plane.config import Settings
from control_plane.main import build_services
from tests.conftest import DEFAULT_POLICY_PATH

PREFIX = "scp-demo/"
SIGNING_KEY = Ed25519PrivateKey.generate()
HMAC_KEY = bytes(range(32))


class ClientError(Exception):
    """Shaped like botocore's: the service's error code is in `response`."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeSecretsManager:
    def __init__(self, secrets: Mapping[str, str], errors: Mapping[str, str] | None = None):
        self._secrets = secrets
        self._errors = errors or {}
        self.asked: list[str] = []

    def get_secret_value(self, *, SecretId: str) -> Mapping[str, Any]:
        self.asked.append(SecretId)
        name = SecretId.removeprefix(PREFIX)
        if name in self._errors:
            raise ClientError(self._errors[name])
        if name not in self._secrets:
            raise ClientError("ResourceNotFoundException")
        return {"SecretString": self._secrets[name]}


def every_secret() -> dict[str, str]:
    return {
        "audit-signing-key": signing_key_to_pem(SIGNING_KEY).decode(),
        "evidence-hmac-key": base64.b64encode(HMAC_KEY).decode(),
        "admin-token": "token-from-secrets-manager",
        "anthropic-api-key": "sk-ant-from-secrets-manager",
    }


def test_every_secret_is_read_under_the_prefix() -> None:
    client = FakeSecretsManager(every_secret())

    found = aws_secrets.load(client, PREFIX)
    signing_key = aws_secrets.load_signing_key(client, PREFIX)

    assert key_id(signing_key.public_key()) == key_id(SIGNING_KEY.public_key())
    assert found.hmac_key == HMAC_KEY
    assert found.admin_token == "token-from-secrets-manager"
    assert found.anthropic_api_key == "sk-ant-from-secrets-manager"
    assert all(name.startswith(PREFIX) for name in client.asked)


def test_the_admin_token_and_the_api_key_are_optional() -> None:
    secrets = every_secret()
    del secrets["admin-token"], secrets["anthropic-api-key"]

    found = aws_secrets.load(FakeSecretsManager(secrets), PREFIX)

    assert (found.admin_token, found.anthropic_api_key) == (None, None)


LOADERS = {
    "audit-signing-key": aws_secrets.load_signing_key,
    "evidence-hmac-key": aws_secrets.load,
}


@pytest.mark.parametrize("missing", sorted(LOADERS))
def test_without_an_audit_key_the_control_plane_does_not_start(missing: str) -> None:
    secrets = every_secret()
    del secrets[missing]

    with pytest.raises(SecretsUnavailableError, match=f"{PREFIX}{missing}"):
        LOADERS[missing](FakeSecretsManager(secrets), PREFIX)


def test_access_denied_is_not_mistaken_for_a_missing_secret() -> None:
    # Treating it as missing would quietly turn policy editing off.
    client = FakeSecretsManager(every_secret(), errors={"admin-token": "AccessDeniedException"})

    with pytest.raises(SecretsUnavailableError, match="AccessDeniedException"):
        aws_secrets.load(client, PREFIX)


@pytest.mark.parametrize("malformed", sorted(LOADERS))
def test_a_malformed_audit_key_stops_startup(malformed: str) -> None:
    secrets = every_secret() | {malformed: "not base64 and not PEM!"}

    with pytest.raises(SecretsUnavailableError, match=f"{PREFIX}{malformed} is malformed"):
        LOADERS[malformed](FakeSecretsManager(secrets), PREFIX)


def test_with_a_prefix_every_secret_comes_from_secrets_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(aws_secrets, "client", lambda: FakeSecretsManager(every_secret()))
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        policy_path=DEFAULT_POLICY_PATH,
        ui_dir=tmp_path / "no-ui",
        spacy_model="not_an_installed_model",  # keeps the test fast; Presidio is not needed
        sovereign_provider="stub",
        aws_secrets_prefix=PREFIX,
    )

    services = build_services(settings)

    key_dir = tmp_path / "data" / "keys"
    # Only the public key is written, for the verifier. No private key on disk.
    assert not (key_dir / SIGNING_KEY_FILE).exists()
    assert not (key_dir / HMAC_KEY_FILE).exists()
    public = load_public_key(key_dir / PUBLIC_KEY_FILE)
    assert key_id(public) == key_id(SIGNING_KEY.public_key())
    assert services.settings.admin_token_value == "token-from-secrets-manager"
    assert services.egress.provider.name == "anthropic"


def test_export_hands_over_the_keys_on_the_data_volume(tmp_path: Path) -> None:
    signing = load_or_create_signing_key(tmp_path)
    hmac_key = load_or_create_hmac_key(tmp_path)

    exported = signing_key_from_pem(export_key("signing", tmp_path).encode())

    assert key_id(exported.public_key()) == key_id(signing.public_key())
    assert base64.b64decode(export_key("hmac", tmp_path)) == hmac_key


def test_export_makes_new_keys_without_writing_them(tmp_path: Path) -> None:
    signing_key_from_pem(export_key("signing", tmp_path).encode())
    assert len(base64.b64decode(export_key("hmac", tmp_path))) == 32
    assert list(tmp_path.iterdir()) == []
