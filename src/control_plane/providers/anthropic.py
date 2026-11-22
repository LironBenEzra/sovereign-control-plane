"""The external model: Anthropic's Claude API, outside the trust boundary.

This provider is only ever reached through the egress gateway.
"""

from __future__ import annotations

import anthropic
from anthropic.types import Message
from anthropic.types.beta import BetaMessage

from control_plane.providers.base import ModelReply, ProviderError, ProviderStatus

_MAX_TOKENS = 16000
_EFFORT = "medium"
_FALLBACK_BETA = "server-side-fallback-2026-07-01"
_REFUSAL_TEXT = "The external model declined to answer this request."


class AnthropicProvider:
    name = "anthropic"
    in_boundary = False
    is_stub = False

    def __init__(
        self,
        model: str,
        timeout_s: float,
        refusal_fallback: bool,
        api_key: str | None = None,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        self.model = model
        self._refusal_fallback = refusal_fallback
        # Without a key there is no external model: it reports not ready and every call
        # fails closed before anything is sent. "" stops the SDK reading the environment
        # itself, so the key in the settings is the only one used.
        self._has_key = client is not None or bool(api_key)
        self._client = client or anthropic.Anthropic(
            api_key=api_key or "", timeout=timeout_s, max_retries=2
        )

    def generate(self, prompt: str) -> ModelReply:
        if not self._has_key:
            raise ProviderError("no_api_key")
        try:
            response = self._create(prompt)
        except anthropic.APIConnectionError as exc:  # includes timeouts
            raise ProviderError("connection") from exc
        except anthropic.RateLimitError as exc:
            raise ProviderError("rate_limited") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"http_{exc.status_code}") from exc
        except anthropic.APIError as exc:
            raise ProviderError("api_error") from exc

        if response.stop_reason == "refusal":
            return ModelReply(text=_REFUSAL_TEXT, served_by=response.model, note="refusal")

        text = "".join(block.text for block in response.content if block.type == "text")
        note = "truncated" if response.stop_reason == "max_tokens" else None
        return ModelReply(text=text, served_by=response.model, note=note)

    def _create(self, prompt: str) -> Message | BetaMessage:
        if not self._refusal_fallback:
            return self._client.messages.create(
                model=self.model,
                max_tokens=_MAX_TOKENS,
                output_config={"effort": _EFFORT},
                messages=[{"role": "user", "content": prompt}],
            )
        # If a safety classifier declines the request, Anthropic re-runs it on a
        # fallback model inside the same call. The destination does not change, and
        # `response.model` (recorded as evidence) says which model answered.
        return self._client.beta.messages.create(
            model=self.model,
            max_tokens=_MAX_TOKENS,
            output_config={"effort": _EFFORT},
            betas=[_FALLBACK_BETA],
            fallbacks="default",
            messages=[{"role": "user", "content": prompt}],
        )

    def status(self) -> ProviderStatus:
        if not self._has_key:
            return ProviderStatus(ready=False, detail="No ANTHROPIC_API_KEY is set")
        # No probe call: a health check must not send anything outside the boundary.
        return ProviderStatus(ready=True, detail=f"configured for {self.model}, not probed")
