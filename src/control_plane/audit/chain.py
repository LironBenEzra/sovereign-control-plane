"""The hash chain primitives shared by the audit writer and the verifier."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, TypedDict

GENESIS_HASH = "0" * 64

# A request's records, in the order they are written. Every request starts with
# `received` and ends with exactly one `outcome` or `error`.
EVENT_RECEIVED = "received"
EVENT_DETECTION = "detection"
EVENT_DECISION = "decision"
# Written just before a model is called, so a crash during the call still shows it.
EVENT_MODEL_CALL = "model_call"
EVENT_OUTCOME = "outcome"
# The request failed on an unexpected exception. Takes the place of the outcome.
EVENT_ERROR = "error"
EVENT_POLICY_LOADED = "policy_loaded"
# An administrator changed the policy. Written before the new version takes effect.
EVENT_POLICY_CHANGED = "policy_changed"

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
