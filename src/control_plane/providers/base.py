"""The model provider boundary: the one place a prompt is handed to a model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ProviderError(Exception):
    """A model call failed. `kind` is a short code; it never contains prompt text."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass(frozen=True)
class ModelReply:
    text: str
    # The model that actually produced the text. It can differ from the configured
    # model (for example after a provider-side fallback), so it is recorded as evidence.
    served_by: str
    note: str | None = None


@dataclass(frozen=True)
class ProviderStatus:
    ready: bool
    detail: str


class ModelProvider(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def in_boundary(self) -> bool:
        """True when the model runs inside the trust boundary."""
        ...

    @property
    def is_stub(self) -> bool:
        """True for the stand-in that makes no real model call."""
        ...

    def generate(self, prompt: str) -> ModelReply:
        """Return the model's answer. Raises ProviderError on any failure."""
        ...

    def status(self) -> ProviderStatus: ...
