"""PII detection with Microsoft Presidio, running entirely in this process.

Presidio combines a spaCy NER model (names) with pattern recognizers that validate
checksums (cards, IBANs) and raise scores when context words are nearby. Nothing is
sent over the network. For a pinned model and library version it is deterministic, and
both versions are recorded in every audit record.
"""

from __future__ import annotations

from collections.abc import Collection
from importlib.metadata import version

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider

from control_plane.models import Finding

DETECTOR_NAME = "presidio"
_LANGUAGE = "en"


class PresidioDetector:
    name = DETECTOR_NAME

    def __init__(self, spacy_model: str) -> None:
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": _LANGUAGE, "model_name": spacy_model}],
            }
        )
        self._analyzer = AnalyzerEngine(
            nlp_engine=provider.create_engine(), supported_languages=[_LANGUAGE]
        )
        self._supported = frozenset(self._analyzer.get_supported_entities(_LANGUAGE))
        self.version = (
            f"presidio-analyzer {version('presidio-analyzer')} / "
            f"{spacy_model} {version(spacy_model)}"
        )

    def detect(self, text: str, entity_types: Collection[str]) -> list[Finding]:
        wanted = sorted(set(entity_types) & self._supported)
        if not wanted:
            return []
        results = self._analyzer.analyze(text=text, language=_LANGUAGE, entities=wanted)
        return [
            Finding(
                entity_type=result.entity_type,
                start=result.start,
                end=result.end,
                score=round(float(result.score), 2),
                detector=self.name,
                recognizer=_recognizer_name(result),
            )
            for result in results
        ]


def _recognizer_name(result: RecognizerResult) -> str:
    metadata = result.recognition_metadata or {}
    return str(metadata.get(RecognizerResult.RECOGNIZER_NAME_KEY, "unknown"))


class UnavailableDetector:
    """Stands in for a detector that could not be loaded.

    It always raises, so every request is classified `unknown_assume_private` and stays
    inside the boundary. The service keeps running and the cause is visible in the audit
    log, instead of the process refusing to start or, worse, running with less detection.
    """

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.version = f"unavailable ({reason})"

    def detect(self, text: str, entity_types: Collection[str]) -> list[Finding]:
        raise DetectorUnavailableError(self.name)


class DetectorUnavailableError(Exception):
    pass
