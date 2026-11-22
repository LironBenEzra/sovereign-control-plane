"""A stand-in for the sovereign model, for running without Ollama.

It makes no network call and says so: `is_stub` is true and the provider name starts
with `stub-`, and both are written to the audit record. Evidence must never claim a
real model answered when none did.
"""

from __future__ import annotations

from control_plane.providers.base import ModelReply, ProviderStatus

_PREVIEW_CHARS = 400


class StubProvider:
    is_stub = True
    model = "stub-echo"

    def __init__(self, name: str, in_boundary: bool) -> None:
        self.name = name
        self.in_boundary = in_boundary

    def generate(self, prompt: str) -> ModelReply:
        # Echoing the input makes it visible what the "model" actually received,
        # which is the point when demonstrating redaction.
        preview = prompt[:_PREVIEW_CHARS] + ("..." if len(prompt) > _PREVIEW_CHARS else "")
        return ModelReply(
            text=f"[{self.name}: no real model was called] I received: {preview}",
            served_by=self.model,
        )

    def status(self) -> ProviderStatus:
        return ProviderStatus(ready=True, detail="stub, no real model")
