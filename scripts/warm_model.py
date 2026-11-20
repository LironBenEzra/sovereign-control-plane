"""Load the Ollama model into memory before the first request.

On a slow CPU, loading the model takes longer than the detection time budget, so the first
prompt after a start would be treated as private. Run this once the stack is up; with
OLLAMA_KEEP_ALIVE=-1 (set for the hosted demo) the model then stays loaded. It waits while
the model is still downloading.

    docker compose exec control-plane python scripts/warm_model.py
"""

from __future__ import annotations

import sys
import time

import httpx

from control_plane.config import Settings
from control_plane.detection.semantic import ENTITY_TYPES, SemanticDetector

_GIVE_UP_AFTER_S = 900
_LOAD_TIMEOUT_S = 600


def main() -> None:
    settings = Settings()
    detector = SemanticDetector(
        settings.ollama_url, settings.sovereign_model, timeout_s=_LOAD_TIMEOUT_S
    )
    deadline = time.monotonic() + _GIVE_UP_AFTER_S
    while True:
        try:
            # A real detection loads the model and puts the few-shot prompt in its cache.
            detector.detect("Warm-up.", ENTITY_TYPES)
        except httpx.HTTPError as exc:
            # Most often a 404: the model is still downloading.
            if time.monotonic() > deadline:
                sys.exit(f"the model did not load: {type(exc).__name__}")
            time.sleep(10)
            continue
        print(f"loaded {settings.sovereign_model}")
        return


if __name__ == "__main__":
    main()
