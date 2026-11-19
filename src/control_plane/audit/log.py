"""The append-only, hash-chained, signed audit log.

One JSON object per line. Each record names the hash of the record before it, so
changing, inserting, deleting or reordering any record breaks every hash after it.
Each hash is signed, so someone who can write the file but does not hold the key
cannot repair the chain.

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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from control_plane.audit.chain import GENESIS_HASH, AuditRecord, canonical_json, record_digest
from control_plane.audit.keys import key_id, sign_digest
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
        signing_key: Ed25519PrivateKey,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._path = path
        self._key = signing_key
        self._key_id = key_id(signing_key.public_key())
        self._clock = clock
        self._lock = threading.Lock()
        self._next_seq, self._head_hash = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Find the chain head, refusing to continue a log that does not verify."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            return 0, GENESIS_HASH

        records, problems = parse_lines(self._path.read_text(encoding="utf-8").splitlines())
        report = verify_chain(records, self._key.public_key())
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
            unsigned = {
                "seq": self._next_seq,
                "ts": self._clock().isoformat(timespec="microseconds"),
                "event": event,
                "audit_id": audit_id,
                "body": dict(body),
                "prev_hash": self._head_hash,
            }
            digest = record_digest(unsigned)
            record: AuditRecord = {
                **unsigned,  # type: ignore[typeddict-item]
                "hash": digest,
                "sig": sign_digest(self._key, digest),
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
