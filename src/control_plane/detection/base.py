"""The detector boundary, and the runner that turns any detector failure into a signal."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Collection, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from control_plane.models import DetectorRun, Finding, Signals

logger = logging.getLogger(__name__)


class Detector(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def entity_types(self) -> frozenset[str]:
        """Every entity type this detector can find, for the policy editor to offer."""
        ...

    def detect(self, text: str, entity_types: Collection[str]) -> list[Finding]:
        """Return findings for the requested entity types. May raise on failure."""
        ...


class InvalidSpanError(Exception):
    """A detector returned a span outside the text it was given."""


class DetectorRunner:
    """Runs every detector under one time budget and never lets a failure pass silently.

    Detectors are independent: if one raises or times out, the findings of the others
    still count, and the failed one is recorded so classification can fail closed.

    A detector that times out keeps running in its worker thread (Python cannot kill
    it) and its late result is discarded. If enough of them hang, later runs time out
    waiting for a worker, which again fails closed.
    """

    def __init__(self, detectors: Sequence[Detector], timeout_s: float) -> None:
        self._detectors = tuple(detectors)
        self._timeout_s = timeout_s
        self._pool = ThreadPoolExecutor(
            max_workers=max(4, len(self._detectors) * 4), thread_name_prefix="detector"
        )
        self._lock = threading.Lock()
        # Detector name -> error of its most recent run, for detectors whose last run failed.
        self._failing: dict[str, str] = {}

    def versions(self) -> dict[str, str]:
        return {d.name: d.version for d in self._detectors}

    def catalog(self) -> dict[str, list[str]]:
        """Entity type -> the detectors that can find it."""
        found: dict[str, list[str]] = {}
        for detector in self._detectors:
            for entity_type in detector.entity_types:
                found.setdefault(entity_type, []).append(detector.name)
        return dict(sorted(found.items()))

    def failing(self) -> dict[str, str]:
        """Detectors whose most recent run failed, with the error class name."""
        with self._lock:
            return dict(self._failing)

    def run(self, text: str, entity_types: Collection[str], skip: Collection[str] = ()) -> Signals:
        """Run every detector except those named in `skip`.

        A skipped detector is not called and not recorded, so its failure state is left
        as it was: a run that did no work must not clear a failure /healthz reports.
        """
        wanted = tuple(sorted(entity_types))
        deadline = time.monotonic() + self._timeout_s
        pending = [
            (d, self._pool.submit(d.detect, text, wanted))
            for d in self._detectors
            if d.name not in skip
        ]

        findings: list[Finding] = []
        runs: list[DetectorRun] = []
        for detector, future in pending:
            try:
                found = future.result(timeout=max(0.0, deadline - time.monotonic()))
                _check_spans(found, len(text))
            except Exception as exc:
                # Deliberately broad: whatever went wrong, the safe reading is
                # "this detector told us nothing". Only the class name is kept,
                # because exception messages can contain the prompt.
                future.cancel()
                logger.warning("detector %s failed: %s", detector.name, type(exc).__name__)
                runs.append(
                    DetectorRun(detector.name, detector.version, ok=False, error=type(exc).__name__)
                )
                continue
            findings.extend(found)
            runs.append(DetectorRun(detector.name, detector.version, ok=True))

        with self._lock:
            for run in runs:
                if run.ok:
                    self._failing.pop(run.name, None)
                else:
                    self._failing[run.name] = run.error or "failed"

        findings.sort(key=lambda f: (f.start, f.end, f.entity_type, f.detector, f.recognizer))
        return Signals(findings=tuple(findings), detectors=tuple(runs))


def _check_spans(findings: Sequence[Finding], text_length: int) -> None:
    for finding in findings:
        if not 0 <= finding.start < finding.end <= text_length:
            raise InvalidSpanError(finding.entity_type)
