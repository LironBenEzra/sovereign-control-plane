"""What signs audit records: a key in this process, or one held elsewhere (AWS KMS).

`AuditLog` depends only on `Signer`. Every implementation makes the same Ed25519
signature over a record's hash, so the verifier never needs to know which one signed.
"""

from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from control_plane.audit.keys import sign_digest


class Signer(Protocol):
    @property
    def public_key(self) -> Ed25519PublicKey: ...

    def sign(self, digest_hex: str) -> str:
        """Base64 Ed25519 signature over the bytes of `digest_hex`. May raise."""
        ...


class LocalSigner:
    """A private key in memory: a file on the data volume, or read from Secrets Manager."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign(self, digest_hex: str) -> str:
        return sign_digest(self._private_key, digest_hex)
