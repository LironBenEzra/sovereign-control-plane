"""Secrets from AWS Secrets Manager, for a deployment that keeps none on its disk.

With `SCP_AWS_SECRETS_PREFIX` set (the hosted demo uses `scp-demo/`), the control plane
reads these at startup, and every one of its secrets comes from here:

* `<prefix>audit-signing-key`: the Ed25519 private key, PEM. Required, unless the key is
  in AWS KMS (`SCP_AUDIT_KMS_KEY_ID`); then it is never read.
* `<prefix>evidence-hmac-key`: the HMAC key, base64. Required.
* `<prefix>admin-token`: optional; without it, policy editing is off.
* `<prefix>anthropic-api-key`: optional; without it, the external model is not ready and
  outside calls are refused.

Credentials come from the usual AWS chain: on EC2, the instance role, which can only
read these secrets. Without the prefix nothing here runs, and the keys are files on the
data volume, as when running locally.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from control_plane.audit.keys import signing_key_from_pem

SIGNING_KEY = "audit-signing-key"
HMAC_KEY = "evidence-hmac-key"
ADMIN_TOKEN = "admin-token"
ANTHROPIC_API_KEY = "anthropic-api-key"

_NOT_FOUND = "ResourceNotFoundException"


class SecretsUnavailableError(Exception):
    """A secret the control plane needs could not be read. It does not start without it."""


class SecretsClient(Protocol):
    """The one call this module makes, as boto3's Secrets Manager client provides it."""

    def get_secret_value(self, *, SecretId: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class DeploymentSecrets:
    hmac_key: bytes
    admin_token: str | None
    anthropic_api_key: str | None


def load(client: SecretsClient, prefix: str) -> DeploymentSecrets:
    """Read every secret but the signing key, or raise SecretsUnavailableError naming it."""
    hmac_text = _read(client, prefix, HMAC_KEY, required=True) or ""
    try:
        hmac_key = base64.b64decode(hmac_text, validate=True)
    except binascii.Error as exc:
        raise SecretsUnavailableError(f"secret {prefix}{HMAC_KEY} is malformed") from exc
    if not hmac_key:
        raise SecretsUnavailableError(f"secret {prefix}{HMAC_KEY} is empty")
    return DeploymentSecrets(
        hmac_key=hmac_key,
        admin_token=_read(client, prefix, ADMIN_TOKEN, required=False) or None,
        anthropic_api_key=_read(client, prefix, ANTHROPIC_API_KEY, required=False) or None,
    )


def load_signing_key(client: SecretsClient, prefix: str) -> Ed25519PrivateKey:
    """The audit signing key, for a deployment that does not sign with AWS KMS."""
    pem = _read(client, prefix, SIGNING_KEY, required=True) or ""
    try:
        return signing_key_from_pem(pem.encode("ascii"))
    except ValueError as exc:
        raise SecretsUnavailableError(f"secret {prefix}{SIGNING_KEY} is malformed") from exc


def client() -> SecretsClient:
    """A Secrets Manager client. Its region comes from AWS_DEFAULT_REGION."""
    import boto3  # noqa: PLC0415 - installed only where secrets come from AWS

    # boto3's own hints know a client's methods only with per-service stub packages.
    return cast(SecretsClient, boto3.client("secretsmanager"))


def error_code(exc: Exception) -> str | None:
    """The AWS error code of a botocore ClientError, such as `AccessDeniedException`."""
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            code = error.get("Code")
            return str(code) if code else None
    return None


def _read(client: SecretsClient, prefix: str, name: str, *, required: bool) -> str | None:
    try:
        return str(client.get_secret_value(SecretId=prefix + name)["SecretString"])
    except Exception as exc:
        # Deliberately broad: whatever the client raised, the secret is unavailable.
        # Only an optional secret that does not exist is not an error; access denied
        # or no credentials must not quietly turn a feature off.
        code = error_code(exc)
        if code == _NOT_FOUND and not required:
            return None
        raise SecretsUnavailableError(
            f"secret {prefix}{name} could not be read: {code or type(exc).__name__}"
        ) from exc
