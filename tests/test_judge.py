"""The LLM judge for the semantic detector's evaluation, with a fake client in place of Claude."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pydantic
import pytest

from control_plane.detection.semantic import (
    CATEGORIES,
    CATEGORY_INSTRUCTIONS,
    INJECTION_INSTRUCTIONS,
    NONE,
)
from control_plane.evaluation.judge import (
    JUDGE_MODEL,
    JudgeUnavailableError,
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


def test_the_judge_may_only_answer_what_the_detector_can() -> None:
    client, messages = fake_client(parsed=label())
    SemanticJudge(client).judge(TEXT)  # type: ignore[arg-type]
    schema_model = messages.calls[0]["output_format"]

    assert schema_model.model_json_schema()["properties"]["category"]["enum"] == [
        *CATEGORIES,
        NONE,
    ]
    with pytest.raises(pydantic.ValidationError):
        schema_model.model_validate({"category": "SECRET", "injection": False, "reason": "x"})


@pytest.mark.parametrize(
    ("stop_reason", "parsed"), [("refusal", None), ("max_tokens", None), ("refusal", label())]
)
def test_no_label_when_the_judge_declines_or_is_cut_off(stop_reason: str, parsed: Any) -> None:
    client, _ = fake_client(stop_reason=stop_reason, parsed=parsed)

    with pytest.raises(JudgeUnavailableError, match=stop_reason):
        SemanticJudge(client).judge(TEXT)  # type: ignore[arg-type]


def test_the_verdict_names_a_fallback_model_that_answered() -> None:
    client, _ = fake_client(parsed=label(), model="claude-opus-4-8")

    assert SemanticJudge(client).judge(TEXT).model == "claude-opus-4-8"  # type: ignore[arg-type]


def test_agreement_scores_confidential_as_yes_or_no_and_injection_separately() -> None:
    meeting = Labels("INTERNAL_MEETING", False)
    financial = Labels("NONPUBLIC_FINANCIAL", False)
    injection_only = Labels(NONE, True)

    result = agreement([(meeting, financial), (meeting, injection_only)])

    # Two confidential categories agree: they get the same policy action.
    assert (result.confidential, result.injection, result.total) == (1, 1, 2)
