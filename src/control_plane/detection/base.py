"""The detector boundary, and the runner that turns any detector failure into a signal."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Collection, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Protocol

from control_plane.enforcement import Redaction, redact
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

    Detectors run in two stages. The value detectors (patterns, NER) run first, in
    parallel, on the text. Then the masked-text detectors (the semantic one, a model) read
    the text with every value the first stage found replaced by its placeholder, as a
    `redact` decision would send it, so a model never reads a value the policy keeps from
    models. Their findings are mapped back to positions in the text.

    Detectors are independent: if one raises or times out, the findings of the others
    still count, and the failed one is recorded so classification can fail closed. If a
    value detector fails, the second stage does not run, because a value it would have
    found is not masked. The masked-text detectors are then neither called nor recorded,
    as if skipped, and the classification fails closed on the failure.

    A detector that times out keeps running in its worker thread (Python cannot kill
    it) and its late result is discarded. If enough of them hang, later runs time out
    waiting for a worker, which again fails closed.
    """

    def __init__(
        self,
        detectors: Sequence[Detector],
        timeout_s: float,
        *,
        masked_text_detectors: Sequence[Detector] = (),
    ) -> None:
        self._detectors = tuple(detectors)
        self._masked_text_detectors = tuple(masked_text_detectors)
        self._all = (*self._detectors, *self._masked_text_detectors)
        self._timeout_s = timeout_s
        self._pool = ThreadPoolExecutor(
            max_workers=max(4, len(self._all) * 4), thread_name_prefix="detector"
        )
        self._lock = threading.Lock()
        # Detector name -> error of its most recent run, for detectors whose last run failed.
        self._failing: dict[str, str] = {}

    def versions(self) -> dict[str, str]:
        return {d.name: d.version for d in self._all}

    def catalog(self) -> dict[str, list[str]]:
        """Entity type -> the detectors that can find it."""
        found: dict[str, list[str]] = {}
        for detector in self._all:
            for entity_type in detector.entity_types:
                found.setdefault(entity_type, []).append(detector.name)
        return dict(sorted(found.items()))

    def failing(self) -> dict[str, str]:
        """Detectors whose most recent run failed, with the error class name."""
        with self._lock:
            return dict(self._failing)

    def run(
        self,
        text: str,
        entity_types: Collection[str],
        skip: Collection[str] = (),
        *,
        mask_min_score: float = 0.0,
    ) -> Signals:
        """Run every detector except those named in `skip`.

        Value findings scoring at least `mask_min_score`, the policy's `min_score`, are
        masked before the masked-text detectors read the text. The default masks every one.

        A skipped detector is not called and not recorded, so its failure state is left
        as it was: a run that did no work must not clear a failure /healthz reports.
        """
        wanted = tuple(sorted(entity_types))
        deadline = time.monotonic() + self._timeout_s
        values = [d for d in self._detectors if d.name not in skip]
        findings, runs = self._run_stage(values, text, wanted, deadline)

        readers = [d for d in self._masked_text_detectors if d.name not in skip]
        if readers and all(run.ok for run in runs):
            masked = redact(text, [f for f in findings if f.score >= mask_min_score])
            found, reader_runs = self._run_stage(readers, masked.text, wanted, deadline)
            findings.extend(_unmasked(f, masked) for f in found)
            runs.extend(reader_runs)

        with self._lock:
            for run in runs:
                if run.ok:
                    self._failing.pop(run.name, None)
                else:
                    self._failing[run.name] = run.error or "failed"

        findings.sort(key=lambda f: (f.start, f.end, f.entity_type, f.detector, f.recognizer))
        return Signals(findings=tuple(findings), detectors=tuple(runs))

    def _run_stage(
        self, detectors: Sequence[Detector], text: str, wanted: tuple[str, ...], deadline: float
    ) -> tuple[list[Finding], list[DetectorRun]]:
        """Run detectors in parallel on one text until the deadline."""
        pending = [(d, self._pool.submit(d.detect, text, wanted)) for d in detectors]

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
        return findings, runs


def _unmasked(finding: Finding, masked: Redaction) -> Finding:
    """A finding in the masked text, moved to the span of the original text it covers."""
    start, end = masked.original_span(finding.start, finding.end)
    return replace(finding, start=start, end=end)


def _check_spans(findings: Sequence[Finding], text_length: int) -> None:
    for finding in findings:
        if not 0 <= finding.start < finding.end <= text_length:
            raise InvalidSpanError(finding.entity_type)
