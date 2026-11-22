from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import anthropic
import httpx
import httpx2
import pytest

from control_plane.egress import EgressDeniedError, EgressGateway
from control_plane.models import Action, Decision
from control_plane.policy import Policy
from control_plane.providers.anthropic import AnthropicProvider
from control_plane.providers.base import ProviderError, ProviderStatus
from control_plane.providers.ollama import OllamaProvider
from tests.conftest import FakeProvider

# ---------------------------------------------------------------- egress gateway


def decision(action: Action) -> Decision:
    return Decision(action, "rule", "because")


@pytest.mark.parametrize("action", [Action.BLOCK, Action.ROUTE_SOVEREIGN])
def test_gateway_refuses_actions_that_must_stay_inside(
    action: Action, default_policy: Policy
) -> None:
    provider = FakeProvider("anthropic", in_boundary=False)

    with pytest.raises(EgressDeniedError, match="action_does_not_permit_egress"):
        EgressGateway(provider).send("payload", decision(action), default_policy)

    assert provider.prompts == []


def test_gateway_refuses_destinations_that_are_not_allowlisted(default_policy: Policy) -> None:
    provider = FakeProvider("unknown-cloud", in_boundary=False)

    with pytest.raises(EgressDeniedError, match="destination_not_allowlisted"):
        EgressGateway(provider).send("payload", decision(Action.ALLOW), default_policy)

    assert provider.prompts == []


def test_gateway_cannot_front_an_in_boundary_provider() -> None:
    with pytest.raises(ValueError, match="external"):
        EgressGateway(FakeProvider("ollama", in_boundary=True))


# ---------------------------------------------------------------- anthropic


class FakeMessages:
    def __init__(self, response: Any = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._response = response
        self._error = error

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self._error:
            raise self._error
        return self._response


def fake_client(messages: FakeMessages) -> anthropic.Anthropic:
    return cast(
        anthropic.Anthropic,
        SimpleNamespace(messages=messages, beta=SimpleNamespace(messages=messages)),
    )


def message(text: str = "hi", stop_reason: str = "end_turn", model: str = "claude-opus-5-5") -> Any:
    return SimpleNamespace(
        stop_reason=stop_reason,
        model=model,
        content=[
            SimpleNamespace(type="thinking", thinking=""),
            SimpleNamespace(type="text", text=text),
        ],
    )


def provider(messages: FakeMessages, refusal_fallback: bool = True) -> AnthropicProvider:
    return AnthropicProvider(
        model="claude-opus-5-5",
        timeout_s=5,
        refusal_fallback=refusal_fallback,
        client=fake_client(messages),
    )


def test_anthropic_sends_one_user_message_and_returns_the_text() -> None:
    messages = FakeMessages(message("the answer"))

    reply = provider(messages).generate("the prompt")

    assert (reply.text, reply.served_by, reply.note) == ("the answer", "claude-opus-5-5", None)
    (call,) = messages.calls
    assert call["model"] == "claude-opus-5-5"
    assert call["messages"] == [{"role": "user", "content": "the prompt"}]
    assert call["fallbacks"] == "default"
    assert "temperature" not in call


def test_anthropic_without_a_key_is_not_ready_and_never_sends() -> None:
    no_key = AnthropicProvider(model="claude-haiku-5-5", timeout_s=5, refusal_fallback=False)

    assert no_key.status() == ProviderStatus(ready=False, detail="No ANTHROPIC_API_KEY is set")
    with pytest.raises(ProviderError) as raised:
        no_key.generate("p")
    assert raised.value.kind == "no_api_key"


def _status_error(cls: type[anthropic.APIStatusError], status: int) -> anthropic.APIStatusError:
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls("boom", response=httpx2.Response(status, request=request), body=None)


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (
            anthropic.APIConnectionError(
                request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
            ),
            "connection",
        ),
        (_status_error(anthropic.AuthenticationError, 401), "http_401"),
    ],
)
def test_anthropic_errors_become_short_codes(error: Exception, kind: str) -> None:
    with pytest.raises(ProviderError) as raised:
        provider(FakeMessages(error=error)).generate("p")

    assert raised.value.kind == kind


# ---------------------------------------------------------------- ollama


def ollama(handler: Any) -> OllamaProvider:
    client = httpx.Client(base_url="http://ollama.test", transport=httpx.MockTransport(handler))
    return OllamaProvider("http://ollama.test", "llama3.2:1b", timeout_s=5, client=client)


def test_ollama_returns_the_answer_and_asks_for_deterministic_sampling() -> None:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"model": "llama3.2:1b", "response": "local answer"})

    reply = ollama(handler).generate("the prompt")

    assert (reply.text, reply.served_by) == ("local answer", "llama3.2:1b")
    assert seen[0]["options"] == {"temperature": 0}
    assert seen[0]["stream"] is False


def test_ollama_connection_failure() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ProviderError) as raised:
        ollama(refuse).generate("p")

    assert raised.value.kind == "connection"
