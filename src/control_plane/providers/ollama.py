"""The sovereign model: a local model served by Ollama inside the trust boundary."""

from __future__ import annotations

import httpx

from control_plane.providers.base import ModelReply, ProviderError, ProviderStatus


class OllamaProvider:
    name = "ollama"
    in_boundary = True
    is_stub = False

    def __init__(
        self, base_url: str, model: str, timeout_s: float, client: httpx.Client | None = None
    ) -> None:
        self.model = model
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout_s)

    def generate(self, prompt: str) -> ModelReply:
        try:
            response = self._client.post(
                "/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0},
                },
            )
            response.raise_for_status()
            body = response.json()
            return ModelReply(text=str(body["response"]), served_by=str(body["model"]))
        except httpx.TimeoutException as exc:
            raise ProviderError("timeout") from exc
        except httpx.HTTPStatusError as exc:
            # 404 here means the model has not been pulled yet.
            raise ProviderError(f"http_{exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise ProviderError("connection") from exc
        except (KeyError, ValueError) as exc:
            raise ProviderError("bad_response") from exc

    def status(self) -> ProviderStatus:
        try:
            response = self._client.get("/api/tags", timeout=3.0)
            response.raise_for_status()
            available = {m.get("name") for m in response.json().get("models", [])}
        except (httpx.HTTPError, ValueError):
            return ProviderStatus(ready=False, detail="Ollama is not reachable")
        if self.model not in available:
            return ProviderStatus(ready=False, detail=f"model {self.model} is not pulled yet")
        return ProviderStatus(ready=True, detail=f"{self.model} is loaded")
