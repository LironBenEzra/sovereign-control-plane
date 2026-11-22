from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from control_plane.api import Services, create_app
from control_plane.config import Settings
from control_plane.main import build_services
from tests.conftest import (
    AWS_KEY,
    DEFAULT_POLICY_PATH,
    SSN,
    FakeProvider,
    Harness,
    HarnessFactory,
)

MAX_PROMPT_CHARS = 200
ADMIN_TOKEN = "test-admin-token-0123456789"
ADMIN = {"authorization": f"Bearer {ADMIN_TOKEN}"}
# The records of one request that was answered by a model.
LIFECYCLE = ["received", "detection", "decision", "model_call", "model_reply", "outcome"]


@pytest.fixture
def harness(make_harness: HarnessFactory) -> Harness:
    return make_harness()


@pytest.fixture
def client(harness: Harness, tmp_path: Path) -> TestClient:
    return make_client(harness, tmp_path)


def make_client(
    harness: Harness, tmp_path: Path, admin_token: str | None = ADMIN_TOKEN
) -> TestClient:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=harness.data_dir,
        policy_path=harness.policy_path,
        ui_dir=tmp_path / "no-ui",
        max_prompt_chars=MAX_PROMPT_CHARS,
        admin_token=admin_token,
    )
    services = Services(
        settings=settings,
        control_plane=harness.plane,
        audit=harness.audit,
        policies=harness.policies,
        sovereign=harness.sovereign,
        egress=harness.egress,
        detectors=harness.runner,
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
    assert body["model"]["provider"] == "anthropic"
    assert body["response"] == "echo: What is a hash chain?"
    # Receipts let a caller prove later that the log still holds its request.
    assert set(body["receipts"]) == {"decision", "outcome"}


def test_a_policy_block_is_an_answer_not_an_outage(client: TestClient) -> None:
    response = client.post("/v1/inference", json={"prompt": f"key {AWS_KEY}"})

    assert response.status_code == 200
    assert "retry-after" not in response.headers
    body = response.json()
    assert (body["decision"]["action"], body["outcome"]) == ("block", "blocked")
    assert body["model"] is None and body["forwarded_prompt"] is None


def test_sovereign_model_down_returns_503_and_says_why(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    harness = make_harness(sovereign=FakeProvider("ollama", in_boundary=True, error="connection"))

    response = make_client(harness, tmp_path).post(
        "/v1/inference", json={"prompt": f"My SSN is {SSN}"}
    )

    assert response.status_code == 503
    assert response.json()["outcome"] == "blocked"
    assert "unavailable" in response.json()["response"]
    assert SSN not in response.json()["response"]


def test_a_missing_ner_model_starts_degraded_and_never_answers(tmp_path: Path) -> None:
    # The real composition root. Before the fix, Presidio tried to download the model
    # and the process exited instead of starting.
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        policy_path=DEFAULT_POLICY_PATH,
        ui_dir=tmp_path / "no-ui",
        spacy_model="not_an_installed_model",
        sovereign_provider="stub",
    )
    client = TestClient(create_app(build_services(settings)))

    health = client.get("/healthz")
    assert health.status_code == 503
    assert health.json()["failing_detectors"] == {"presidio": "DetectorUnavailableError"}

    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    assert (response.json()["outcome"], response.json()["outcome_reason"]) == (
        "blocked",
        "detection_failed",
    )


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"content": b"{not json", "headers": {"content-type": "application/json"}}, 422),
        ({"json": {"prompt": "x" * (MAX_PROMPT_CHARS + 1)}}, 413),
        ({"content": b"prompt=hi", "headers": {"content-type": "text/plain"}}, 415),
    ],
)
def test_bad_requests_are_rejected_and_audited(
    client: TestClient, harness: Harness, kwargs: dict, status: int
) -> None:
    response = client.post("/v1/inference", **kwargs)

    assert response.status_code == status
    body = response.json()
    assert body["decision"]["action"] == "block"
    assert body["classification"]["label"] == "invalid_input"
    # The rejection is in the log, and no model was called.
    assert [r["event"] for r in harness.records()] == ["received", "decision", "outcome"]
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
    assert listing["total"] == 13  # policy_loaded + 2 x 6 steps
    assert [r["seq"] for r in listing["records"]] == [12, 11]

    detail = client.get(f"/v1/audit/{first['audit_id']}").json()
    assert [r["event"] for r in detail["records"]] == LIFECYCLE
    assert detail["records"][2]["hash"] == first["receipts"]["decision"]["hash"]

    assert client.get("/v1/audit/does-not-exist").status_code == 404


def test_verify_endpoint_reports_an_intact_chain_and_then_tampering(
    client: TestClient, harness: Harness
) -> None:
    client.post("/v1/inference", json={"prompt": "one"})
    assert client.get("/v1/audit/verify").json()["ok"] is True

    path = harness.audit.path
    path.write_text(path.read_text().replace('"action":"allow"', '"action":"block"', 1))
    report = client.get("/v1/audit/verify").json()

    assert report["ok"] is False
    assert report["chain_problems"][0]["reason"] == "content does not match its hash"


def restore_default(client: TestClient) -> None:
    base = client.get("/v1/policy").json()["base_sha256"]
    response = client.post("/v1/policy/restore-default", json={"base_sha256": base}, headers=ADMIN)
    assert response.status_code == 200, response.text


def test_an_invalid_policy_returns_503_says_why_and_recovers_without_restart(
    client: TestClient, harness: Harness
) -> None:
    harness.corrupt_policy()

    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})
    health = client.get("/healthz")

    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    assert response.json()["outcome_reason"] == "policy_unavailable"
    assert health.status_code == 503
    assert "modified on disk" in health.json()["policy"]["error"]
    assert harness.external.prompts == harness.sovereign.prompts == []

    restore_default(client)

    assert client.post("/v1/inference", json={"prompt": "hi"}).status_code == 200
    assert client.get("/healthz").status_code == 200


def verification_alert(client: TestClient) -> dict[str, Any] | None:
    alerts = client.get("/v1/alerts").json()["alerts"]
    return next((a for a in alerts if a["id"] == "audit_verification_failed"), None)


def test_alerts_see_a_log_edit_that_keeps_its_size_and_modification_time(
    client: TestClient, harness: Harness
) -> None:
    client.post("/v1/inference", json={"prompt": "one"})
    assert verification_alert(client) is None

    log = harness.audit.path
    before = log.stat()
    log.write_text(log.read_text().replace('"action":"allow"', '"action":"block"', 1))
    os.utime(log, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert (log.stat().st_size, log.stat().st_mtime_ns) == (before.st_size, before.st_mtime_ns)

    alert = verification_alert(client)
    assert alert is not None
    assert "content does not match its hash" in alert["detail"]


# ---------------------------------------------------------------- policy editing


def stricter_draft(client: TestClient) -> dict[str, Any]:
    """The policy in force, with clean prompts kept inside instead of sent out."""
    info = client.get("/v1/policy").json()
    document = info["document"]
    document["version"] = info["next_version"]
    for rule in document["rules"]:
        if rule["id"] == "allow-clean":
            rule["action"] = "route_sovereign"
    return document


def test_changing_the_policy_needs_the_admin_token(harness: Harness, tmp_path: Path) -> None:
    locked = make_client(harness, tmp_path, admin_token=None)
    client = make_client(harness, tmp_path)
    draft = stricter_draft(client)
    base = client.get("/v1/policy").json()["base_sha256"]
    save = {"document": draft, "base_sha256": base, "note": "try"}

    assert locked.get("/v1/policy").json()["editable"] is False
    assert locked.put("/v1/policy", json=save, headers=ADMIN).status_code == 403
    for headers in ({}, {"authorization": "Bearer wrong"}, {"authorization": ADMIN_TOKEN}):
        assert client.put("/v1/policy", json=save, headers=headers).status_code == 401
        restore = client.post(
            "/v1/policy/restore-default", json={"base_sha256": base}, headers=headers
        )
        assert restore.status_code == 401
    assert harness.records("policy_changed") == []
    assert client.post("/v1/inference", json={"prompt": "hi"}).json()["decision"]["action"] == (
        "allow"
    )


def test_a_saved_policy_is_in_force_audited_and_in_the_history(
    client: TestClient, harness: Harness
) -> None:
    before = client.get("/v1/policy").json()

    saved = client.put(
        "/v1/policy",
        json={
            "document": stricter_draft(client),
            "base_sha256": before["base_sha256"],
            "note": "Audit week",
        },
        headers=ADMIN,
    )

    assert saved.status_code == 200
    body = saved.json()
    answer = client.post("/v1/inference", json={"prompt": "What is a hash chain?"}).json()
    assert answer["decision"]["action"] == "route_sovereign"
    assert answer["policy"]["sha256"] == body["policy"]["sha256"]

    (entry,) = client.get("/v1/policy").json()["history"]
    assert (entry["seq"], entry["note"]) == (body["receipt"]["seq"], "Audit week")
    assert entry["changed_by"].startswith("admin-token:")
    assert ADMIN_TOKEN not in harness.log_text()
    assert client.get("/v1/audit/verify").json()["ok"] is True


def test_a_save_that_keeps_the_version_is_refused_and_names_a_free_one(
    client: TestClient,
) -> None:
    info = client.get("/v1/policy").json()
    draft = stricter_draft(client)
    draft["version"] = info["version"]

    refused = client.put(
        "/v1/policy",
        json={"document": draft, "base_sha256": info["base_sha256"], "note": "x"},
        headers=ADMIN,
    )

    assert refused.status_code == 422
    assert info["next_version"] in refused.json()["detail"]
    assert client.get("/v1/policy").json()["sha256"] == info["sha256"]


def test_a_policy_that_would_send_credentials_out_is_refused_and_says_where(
    client: TestClient,
) -> None:
    info = client.get("/v1/policy").json()
    draft = stricter_draft(client)
    draft["rules"][0]["action"] = "allow"

    checked = client.post("/v1/policy/check", json={"document": draft}).json()
    refused = client.put(
        "/v1/policy",
        json={"document": draft, "base_sha256": info["base_sha256"], "note": "x"},
        headers=ADMIN,
    )

    assert checked["valid"] is False
    assert [e["path"] for e in checked["errors"]] == ["rules.0.action"]
    assert refused.status_code == 422
    assert client.get("/v1/policy").json()["sha256"] == info["sha256"]


def test_a_save_from_an_out_of_date_version_is_refused(client: TestClient) -> None:
    base = client.get("/v1/policy").json()["base_sha256"]
    draft = stricter_draft(client)
    first = client.put(
        "/v1/policy", json={"document": draft, "base_sha256": base, "note": "one"}, headers=ADMIN
    )
    draft["detection"]["min_score"] = 0.4

    second = client.put(
        "/v1/policy", json={"document": draft, "base_sha256": base, "note": "two"}, headers=ADMIN
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert "Reload" in second.json()["detail"]


def test_anyone_can_preview_a_draft_without_changing_anything(
    client: TestClient, harness: Harness
) -> None:
    # No token is sent: trying a draft is open to anyone, while saving it is not.
    draft = stricter_draft(client)
    recorded = len(harness.records())

    preview = client.post(
        "/v1/policy/preview", json={"document": draft, "prompt": "What is a hash chain?"}
    ).json()

    assert (preview["current"]["action"], preview["draft"]["action"]) == (
        "allow",
        "route_sovereign",
    )
    assert len(harness.records()) == recorded
    assert harness.external.prompts == harness.sovereign.prompts == []
    assert client.get("/v1/policy").json()["is_default"] is True
