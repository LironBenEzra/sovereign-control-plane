from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from control_plane.api import Services, create_app
from control_plane.config import Settings
from tests.conftest import AWS_KEY, EMAIL, PERSON, Harness, HarnessFactory

MAX_PROMPT_CHARS = 200


@pytest.fixture
def harness(make_harness: HarnessFactory) -> Harness:
    return make_harness()


@pytest.fixture
def client(harness: Harness, tmp_path: Path) -> TestClient:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=harness.data_dir,
        policy_path=harness.policy_path,
        ui_dir=tmp_path / "no-ui",
        max_prompt_chars=MAX_PROMPT_CHARS,
    )
    services = Services(
        settings=settings,
        control_plane=harness.plane,
        audit=harness.audit,
        policies=harness.policies,
        sovereign=harness.sovereign,
        egress=harness.egress,
        detector_versions={d.name: d.version for d in harness.detectors},
    )
    return TestClient(create_app(services))


def test_a_clean_prompt_returns_the_decision_the_answer_and_receipts(client: TestClient) -> None:
    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})

    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["action"] == "allow"
    assert body["decision"]["rule_id"] == "allow-clean"
    assert body["classification"]["label"] == "no_private_data"
    assert body["outcome"] == "completed"
    assert body["model"] == {
        "provider": "anthropic",
        "model": "fake-model",
        "in_boundary": False,
        "stub": False,
    }
    assert body["response"] == "echo: What is a hash chain?"
    assert set(body["receipts"]) == {"decision", "outcome"}
    assert body["receipts"]["outcome"]["seq"] == body["receipts"]["decision"]["seq"] + 1


def test_findings_are_explained_in_the_response(client: TestClient) -> None:
    prompt = f"Reply to {PERSON} at {EMAIL}."

    body = client.post("/v1/inference", json={"prompt": prompt}).json()

    assert body["decision"]["action"] == "redact"
    findings = {f["entity_type"]: f for f in body["classification"]["findings"]}
    assert set(findings) == {"PERSON", "EMAIL_ADDRESS"}
    email = findings["EMAIL_ADDRESS"]
    assert prompt[email["start"] : email["end"]] == EMAIL
    assert (email["category"], email["counted"], email["score"]) == ("pii", True, 1.0)
    assert body["forwarded_prompt"] == "Reply to <PERSON_1> at <EMAIL_ADDRESS_1>."


def test_a_blocked_prompt_returns_no_model(client: TestClient) -> None:
    body = client.post("/v1/inference", json={"prompt": f"key {AWS_KEY}"}).json()

    assert body["decision"]["action"] == "block"
    assert body["outcome"] == "blocked"
    assert body["model"] is None and body["forwarded_prompt"] is None


@pytest.mark.parametrize(
    ("kwargs", "status", "reason"),
    [
        ({"content": b"{not json", "headers": {"content-type": "application/json"}}, 422, None),
        ({"json": {"prompt": "hi", "extra": 1}}, 422, None),
        ({"json": {"prompt": 42}}, 422, None),
        ({"json": {"prompt": ""}}, 422, None),
        ({"json": {}}, 422, None),
        ({"json": ["a", "list"]}, 422, None),
        ({"json": {"prompt": "x" * (MAX_PROMPT_CHARS + 1)}}, 413, "prompt_too_long"),
        ({"json": {"prompt": "x" * 5000}}, 413, "body_too_large"),
        ({"content": b"prompt=hi", "headers": {"content-type": "text/plain"}}, 415, None),
    ],
)
def test_bad_requests_are_rejected_and_audited(
    client: TestClient, harness: Harness, kwargs: dict, status: int, reason: str | None
) -> None:
    response = client.post("/v1/inference", **kwargs)

    assert response.status_code == status
    body = response.json()
    assert body["decision"]["action"] == "block"
    assert body["classification"]["label"] == "invalid_input"
    if reason:
        assert body["outcome_reason"] == reason
    # The rejection is in the log, and no model was called.
    assert [r["event"] for r in harness.records()] == ["decision", "outcome"]
    assert harness.external.prompts == harness.sovereign.prompts == []


def test_audit_failure_returns_503_and_no_answer(client: TestClient, harness: Harness) -> None:
    client.post("/v1/inference", json={"prompt": "warm up"})
    harness.audit.fail_on = frozenset({"decision"})

    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})

    assert response.status_code == 503
    assert response.json()["error"] == "audit_unavailable"
    assert "response" not in response.json()


def test_audit_endpoints_expose_the_evidence(client: TestClient) -> None:
    first = client.post("/v1/inference", json={"prompt": "one"}).json()
    client.post("/v1/inference", json={"prompt": "two"})

    listing = client.get("/v1/audit", params={"limit": 2}).json()
    assert listing["total"] == 5  # policy_loaded + 2 x (decision, outcome)
    assert [r["seq"] for r in listing["records"]] == [4, 3]

    detail = client.get(f"/v1/audit/{first['audit_id']}").json()
    assert [r["event"] for r in detail["records"]] == ["decision", "outcome"]
    assert detail["records"][0]["hash"] == first["receipts"]["decision"]["hash"]

    assert client.get("/v1/audit/does-not-exist").status_code == 404


def test_verify_endpoint_reports_an_intact_chain(client: TestClient) -> None:
    client.post("/v1/inference", json={"prompt": "one"})

    report = client.get("/v1/audit/verify").json()

    assert report["ok"] is True
    assert (report["records"], report["decisions_replayed"]) == (3, 1)


def test_verify_endpoint_reports_tampering(client: TestClient, harness: Harness) -> None:
    client.post("/v1/inference", json={"prompt": "one"})
    path = harness.audit.path
    path.write_text(path.read_text().replace('"action":"allow"', '"action":"block"', 1))

    report = client.get("/v1/audit/verify").json()

    assert report["ok"] is False
    assert report["chain_problems"][0]["reason"] == "content does not match its hash"


def test_policy_endpoint_shows_the_active_policy(client: TestClient, harness: Harness) -> None:
    body = client.get("/v1/policy").json()

    assert body["valid"] is True
    assert body["id"] == "default-sovereign-policy"
    assert body["text"] == harness.policy_path.read_text()

    harness.policy_path.write_text("broken: true")
    assert client.get("/v1/policy").json()["valid"] is False


def test_health_reports_components_without_calling_models(
    client: TestClient, harness: Harness
) -> None:
    body = client.get("/healthz").json()

    assert body["status"] == "ok"
    assert body["sovereign_model"]["provider"] == "ollama"
    assert body["external_model"]["provider"] == "anthropic"
    assert harness.external.prompts == harness.sovereign.prompts == []


def test_client_id_header_is_recorded_only_when_well_formed(
    client: TestClient, harness: Harness
) -> None:
    client.post("/v1/inference", json={"prompt": "one"}, headers={"x-client-id": "billing-app"})
    client.post(
        "/v1/inference", json={"prompt": "two"}, headers={"x-client-id": "bad id\twith junk"}
    )

    claimed = [r["body"]["request"]["client_id_claimed"] for r in harness.records("decision")]
    assert claimed == ["billing-app", None]
