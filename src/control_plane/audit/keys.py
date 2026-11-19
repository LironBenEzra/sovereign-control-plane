"""Key material for the audit log.

Two keys, both generated on first run and kept inside the trust boundary:

* an Ed25519 signing key. Its public half is all a reviewer needs to verify the log.
* an HMAC key used to store private values as keyed hashes. A plain SHA-256 of a phone
  number or SSN can be brute-forced; a keyed hash cannot without this key.

In production both would live in an HSM or KMS, not on the data volume.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNING_KEY_FILE = "audit_signing.key"
PUBLIC_KEY_FILE = "audit_signing.pub"
HMAC_KEY_FILE = "evidence_hmac.key"


def load_or_create_signing_key(key_dir: Path) -> Ed25519PrivateKey:
    private_path = key_dir / SIGNING_KEY_FILE
    if private_path.exists():
        key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{private_path} is not an Ed25519 private key")
        return key

    key = Ed25519PrivateKey.generate()
    _write_private(
        private_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    (key_dir / PUBLIC_KEY_FILE).write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def sign_digest(key: Ed25519PrivateKey, digest_hex: str) -> str:
    return base64.b64encode(key.sign(bytes.fromhex(digest_hex))).decode("ascii")


def signature_is_valid(public_key: Ed25519PublicKey, digest_hex: str, signature: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature, validate=True), bytes.fromhex(digest_hex))
    except (InvalidSignature, ValueError):
        return False
    return True


def load_or_create_hmac_key(key_dir: Path) -> bytes:
    path = key_dir / HMAC_KEY_FILE
    if path.exists():
        return path.read_bytes()
    key = secrets.token_bytes(32)
    _write_private(path, key)
    return key


def keyed_hash(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
