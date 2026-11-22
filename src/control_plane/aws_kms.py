"""Signing audit records with a key that never leaves AWS KMS.

With `SCP_AUDIT_KMS_KEY_ID` set (the hosted demo uses `alias/scp-demo-audit`), the
server never holds the audit signing key: it sends each record's hash to KMS and writes
back the signature. The key is an Ed25519 key (`ECC_NIST_EDWARDS25519`), so records
look and verify exactly as when the key is a local file. Only the public key is read,
once at startup, for the verifier and for `key_id`.

The cost is a network call per record, made while the audit log holds its write lock.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any, Protocol, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from control_plane.aws_secrets import error_code

KEY_SPEC = "ECC_NIST_EDWARDS25519"
# Pure Ed25519, the same signature a local key makes. It requires MessageType RAW; the
# other Ed25519 algorithm, ED25519_PH_SHA_512, is Ed25519ph and would not verify.
SIGNING_ALGORITHM = "ED25519_SHA_512"


class KmsUnavailableError(Exception):
    """The KMS key cannot be used to sign the audit log. The server does not start."""


class KmsSigningError(Exception):
    """KMS did not sign a record. Carries the error code, never the record."""


class KmsClient(Protocol):
    """The two calls this module makes, as boto3's KMS client provides them."""

    def get_public_key(self, *, KeyId: str) -> Mapping[str, Any]: ...

    def sign(
        self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> Mapping[str, Any]: ...


class KmsSigner:
    def __init__(self, client: KmsClient, key_id: str) -> None:
        try:
            found = client.get_public_key(KeyId=key_id)
        except Exception as exc:
            # Deliberately broad: whatever the client raised, the key cannot be used.
            reason = error_code(exc) or type(exc).__name__
            raise KmsUnavailableError(f"KMS key {key_id} could not be read: {reason}") from exc
        if found.get("KeySpec") != KEY_SPEC or SIGNING_ALGORITHM not in found.get(
            "SigningAlgorithms", ()
        ):
            raise KmsUnavailableError(f"KMS key {key_id} is not an Ed25519 signing key")
        public_key = serialization.load_der_public_key(found["PublicKey"])
        if not isinstance(public_key, Ed25519PublicKey):
            raise KmsUnavailableError(f"KMS key {key_id} is not an Ed25519 signing key")

        self._client = client
        # The ARN, not the alias: every record of this run is signed by the key whose
        # public half was just read, even if the alias is moved to another key.
        self._key_arn = str(found["KeyId"])
        self._public_key = public_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def sign(self, digest_hex: str) -> str:
        try:
            response = self._client.sign(
                KeyId=self._key_arn,
                Message=bytes.fromhex(digest_hex),
                MessageType="RAW",
                SigningAlgorithm=SIGNING_ALGORITHM,
            )
        except Exception as exc:
            # Deliberately broad, like the read above. The caller fails closed.
            raise KmsSigningError(error_code(exc) or type(exc).__name__) from exc
        return base64.b64encode(response["Signature"]).decode("ascii")


def client() -> KmsClient:
    """A KMS client. Its region comes from AWS_DEFAULT_REGION."""
    import boto3  # noqa: PLC0415 - installed only where the key is in AWS

    # boto3's own hints know a client's methods only with per-service stub packages.
    return cast(KmsClient, boto3.client("kms"))
