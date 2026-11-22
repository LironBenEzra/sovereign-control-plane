"""The append-only, hash-chained, signed audit log.

One JSON object per line. Each record names the hash of the record before it, so
changing, inserting, deleting or reordering any record breaks every hash after it.
Each hash is signed, so someone who can write the file but does not hold the key
cannot repair the chain. The key is a `Signer`: a key in memory, or one in AWS KMS.

Single writer by design: one process owns the file and serialises appends with a lock.
Running several instances would need a shared sequencer (a database or a log service).
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from control_plane.audit.chain import GENESIS_HASH, AuditRecord, canonical_json, record_digest
from control_plane.audit.keys import key_id, signature_is_valid
from control_plane.audit.signing import Signer
from control_plane.audit.verify import parse_lines, verify_chain


class AuditWriteError(Exception):
    """A record could not be durably written. Callers must fail closed."""


class AuditIntegrityError(Exception):
    """The existing log does not verify. Appending to it would hide the damage."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditLog:
    def __init__(
        self,
        path: Path,
        signer: Signer,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._path = path
        self._signer = signer
        self._public_key = signer.public_key
        self._key_id = key_id(self._public_key)
        self._clock = clock
        self._lock = threading.Lock()
        self._next_seq, self._head_hash = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Find the chain head, refusing to continue a log that does not verify."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            return 0, GENESIS_HASH

        records, problems = parse_lines(self._path.read_text(encoding="utf-8").splitlines())
        report = verify_chain(records, self._public_key)
        problems = [*report.chain_problems, *problems]
        if problems:
            first = problems[0]
            raise AuditIntegrityError(
                f"audit log {self._path} failed verification at record {first.seq}: {first.reason}"
            )
        return report.records, report.head_hash or GENESIS_HASH

    def append(self, event: str, audit_id: str, body: Mapping[str, Any]) -> AuditRecord:
        """Write one record and fsync it before returning."""
        with self._lock:
            seq = self._next_seq
            ts = self._clock().isoformat(timespec="microseconds")
            content = dict(body)
            digest = record_digest(
                {
                    "seq": seq,
                    "ts": ts,
                    "event": event,
                    "audit_id": audit_id,
                    "body": content,
                    "prev_hash": self._head_hash,
                }
            )
            try:
                signature = self._signer.sign(digest)
            except Exception as exc:
                # Deliberately broad: a remote signer can fail in many ways, and every one
                # of them means this record cannot be written.
                raise AuditWriteError(f"signing failed: {type(exc).__name__}: {exc}") from exc
            if not signature_is_valid(self._public_key, digest, signature):
                # A record that does not verify would break the chain for good, and the log
                # could not be reopened. Refuse it instead.
                raise AuditWriteError("the signer returned a signature that does not verify")
            record: AuditRecord = {
                "seq": seq,
                "ts": ts,
                "event": event,
                "audit_id": audit_id,
                "body": content,
                "prev_hash": self._head_hash,
                "hash": digest,
                "sig": signature,
                "key_id": self._key_id,
            }
            try:
                with self._path.open("ab") as handle:
                    handle.write(canonical_json(record) + b"\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise AuditWriteError(type(exc).__name__) from exc

            self._next_seq += 1
            self._head_hash = digest
            return record

    def read(self) -> list[AuditRecord]:
        if not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    @property
    def path(self) -> Path:
        return self._path
