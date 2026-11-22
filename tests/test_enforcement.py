from __future__ import annotations

from control_plane.enforcement import redact, restore
from control_plane.models import Finding


def finding(text: str, value: str, entity_type: str, score: float = 1.0) -> Finding:
    start = text.index(value)
    return Finding(entity_type, start, start + len(value), score, "fake", "test")


def test_redact_replaces_each_span_with_a_typed_placeholder() -> None:
    text = "Mail a@x.io or call Dana."
    findings = [finding(text, "a@x.io", "EMAIL_ADDRESS"), finding(text, "Dana", "PERSON")]

    result = redact(text, findings)

    assert result.text == "Mail <EMAIL_ADDRESS_1> or call <PERSON_1>."
    assert result.placeholders == {"<EMAIL_ADDRESS_1>": "a@x.io", "<PERSON_1>": "Dana"}
    assert result.by_entity == {"EMAIL_ADDRESS": 1, "PERSON": 1}


def test_the_same_value_gets_the_same_placeholder() -> None:
    text = "Dana met Omar. Dana left."
    findings = [
        Finding("PERSON", 0, 4, 0.85, "fake", "test"),
        finding(text, "Omar", "PERSON"),
        Finding("PERSON", 15, 19, 0.85, "fake", "test"),
    ]

    result = redact(text, findings)

    assert result.text == "<PERSON_1> met <PERSON_2>. <PERSON_1> left."
    assert result.span_count == 3


def test_overlapping_findings_are_merged_so_nothing_stays_in_the_clear() -> None:
    text = "password=dana@example.com!"
    findings = [
        Finding("CREDENTIAL_ASSIGNMENT", 0, 25, 0.8, "rules", "credential-assignment"),
        Finding("EMAIL_ADDRESS", 9, 25, 1.0, "fake", "test"),
        Finding("URL", 14, 26, 0.5, "fake", "test"),
    ]

    result = redact(text, findings)

    # One span from 0 to 26, named after the strongest finding inside it.
    assert result.text == "<EMAIL_ADDRESS_1>"
    assert result.placeholders == {"<EMAIL_ADDRESS_1>": text}


def test_a_span_of_the_masked_text_maps_back_to_the_original() -> None:
    text = "Mail a@x.io or call Dana today."
    result = redact(
        text, [finding(text, "a@x.io", "EMAIL_ADDRESS"), finding(text, "Dana", "PERSON")]
    )
    masked = result.text  # "Mail <EMAIL_ADDRESS_1> or call <PERSON_1> today."

    def original(masked_part: str) -> str:
        start = masked.index(masked_part)
        mapped_start, mapped_end = result.original_span(start, start + len(masked_part))
        return text[mapped_start:mapped_end]

    assert original(masked) == text
    assert original("Mail") == "Mail"
    assert original(" or call ") == " or call "
    assert original(" today.") == " today."
    assert original("<PERSON_1>") == "Dana"
    # A span that starts or ends inside a placeholder covers the whole value.
    assert original("ADDRESS_1> or") == "a@x.io or"
    assert original("call <PERS") == "call Dana"


def test_redact_without_findings_returns_the_text_unchanged() -> None:
    result = redact("nothing here", [])

    assert result.text == "nothing here"
    assert result.placeholders == {}


def test_restore_puts_originals_back_and_counts_them() -> None:
    text = "Write to dana@example.com about Dana."
    findings = [finding(text, "dana@example.com", "EMAIL_ADDRESS"), finding(text, "Dana", "PERSON")]
    redaction = redact(text, findings)
    model_answer = "Sure. <PERSON_1> can be reached at <EMAIL_ADDRESS_1>. Bye <PERSON_1>."

    restored, count = restore(model_answer, redaction.placeholders)

    assert restored == "Sure. Dana can be reached at dana@example.com. Bye Dana."
    assert count == 3


def test_restore_is_a_single_pass() -> None:
    # A restored value that looks like another placeholder must not be replaced again.
    placeholders = {"<PERSON_1>": "<PERSON_2>", "<PERSON_2>": "Omar"}

    restored, count = restore("<PERSON_1> met <PERSON_2>", placeholders)

    assert restored == "<PERSON_2> met Omar"
    assert count == 2
