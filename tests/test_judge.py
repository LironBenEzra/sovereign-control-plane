"""The LLM judge for the semantic detector's evaluation, with a fake client in place of Claude."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from control_plane.detection.semantic import (
    CATEGORY_INSTRUCTIONS,
    INJECTION_INSTRUCTIONS,
    NONE,
)
from control_plane.evaluation.judge import (
    JUDGE_MODEL,
    Labels,
    SemanticJudge,
    agreement,
)

TEXT = "Summarize the notes from the board meeting: the CFO steps down in June."


class FakeMessages:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def parse(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.response


def fake_client(stop_reason: str = "end_turn", parsed: Any = None, model: str = JUDGE_MODEL):
    messages = FakeMessages(
        SimpleNamespace(stop_reason=stop_reason, parsed_output=parsed, model=model)
    )
    return SimpleNamespace(beta=SimpleNamespace(messages=messages)), messages


def label(category: str = "INTERNAL_MEETING", injection: bool = False) -> Any:
    return SimpleNamespace(category=category, injection=injection, reason="Board minutes.")


def test_the_judge_labels_with_the_detectors_definitions_and_sees_only_the_text() -> None:
    client, messages = fake_client(parsed=label())

    verdict = SemanticJudge(client).judge(TEXT)  # type: ignore[arg-type]

    assert (verdict.category, verdict.injection, verdict.model) == (
        "INTERNAL_MEETING",
        False,
        JUDGE_MODEL,
    )
    (call,) = messages.calls
    assert CATEGORY_INSTRUCTIONS in call["system"] and INJECTION_INSTRUCTIONS in call["system"]
    # Only the text: the detector's answer is never shown to the judge.
    assert call["messages"] == [{"role": "user", "content": f"<text>\n{TEXT}\n</text>"}]
    assert (call["model"], call["fallbacks"]) == (JUDGE_MODEL, "default")


def test_agreement_scores_confidential_as_yes_or_no_and_injection_separately() -> None:
    meeting = Labels("INTERNAL_MEETING", False)
    financial = Labels("NONPUBLIC_FINANCIAL", False)
    injection_only = Labels(NONE, True)

    result = agreement([(meeting, financial), (meeting, injection_only)])

    # Two confidential categories agree: they get the same policy action.
    assert (result.confidential, result.injection, result.total) == (1, 1, 2)
