"""The hash chain primitives shared by the audit writer and the verifier."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, TypedDict

GENESIS_HASH = "0" * 64

EVENT_DECISION = "decision"
EVENT_OUTCOME = "outcome"
EVENT_POLICY_LOADED = "policy_loaded"

# Decisions taken before classification exists (bad request, no usable policy).
# There is nothing to replay for them, but they must always be a block.
BUILTIN_RULE_PREFIX = "builtin:"
INVALID_REQUEST_RULE_ID = BUILTIN_RULE_PREFIX + "invalid-request"
POLICY_UNAVAILABLE_RULE_ID = BUILTIN_RULE_PREFIX + "policy-unavailable"

# The fields a record's hash covers. `hash`, `sig` and `key_id` are derived from them.
HASHED_FIELDS = ("seq", "ts", "event", "audit_id", "body", "prev_hash")


class AuditRecord(TypedDict):
    seq: int
    ts: str
    event: str
    audit_id: str
    body: dict[str, Any]
    prev_hash: str
    hash: str
    sig: str
    key_id: str


def canonical_json(value: Any) -> bytes:
    """One byte representation per value, so a hash can be recomputed by anyone."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def record_digest(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json({k: record[k] for k in HASHED_FIELDS})).hexdigest()
