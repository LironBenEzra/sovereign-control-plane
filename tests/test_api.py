from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from control_plane.api import Services, create_app
from control_plane.audit.keys import write_public_key
from control_plane.config import Settings
from control_plane.detection.rules import RuleDetector
from control_plane.main import build_services
from tests.conftest import (
    AWS_KEY,
    DEFAULT_POLICY_PATH,
    EMAIL,
    PERSON,
    SSN,
    FakeProvider,
    Harness,
    HarnessFactory,
    KeywordDetector,
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
    harness: Harness,
    tmp_path: Path,
    admin_token: str | None = ADMIN_TOKEN,
    open_editing: bool = False,
    ui_dir: Path | None = None,
) -> TestClient:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=harness.data_dir,
        policy_path=harness.policy_path,
        ui_dir=ui_dir or tmp_path / "no-ui",
        max_prompt_chars=MAX_PROMPT_CHARS,
        admin_token=admin_token,
        open_policy_editing=open_editing,
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
    assert body["model"] == {
        "provider": "anthropic",
        "model": "fake-model",
        "in_boundary": False,
        "stub": False,
    }
    assert body["response"] == "echo: What is a hash chain?"
    assert set(body["receipts"]) == {"decision", "outcome"}
    # The model_call and model_reply records sit between them.
    assert body["receipts"]["outcome"]["seq"] == body["receipts"]["decision"]["seq"] + 3


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
    assert body["model_reply"] == "echo: Reply to <PERSON_1> at <EMAIL_ADDRESS_1>."
    assert body["response"] == f"echo: {prompt}"


def test_a_blocked_prompt_returns_no_model(client: TestClient) -> None:
    body = client.post("/v1/inference", json={"prompt": f"key {AWS_KEY}"}).json()

    assert body["decision"]["action"] == "block"
    assert body["outcome"] == "blocked"
    assert body["model"] is None and body["forwarded_prompt"] is None
    assert body["model_reply"] is None


def test_a_policy_block_is_an_answer_not_an_outage(client: TestClient) -> None:
    response = client.post("/v1/inference", json={"prompt": f"key {AWS_KEY}"})

    assert response.status_code == 200
    assert "retry-after" not in response.headers


def test_no_answer_because_a_detector_failed_returns_503_and_says_why(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    # The detector works on the prompt and fails on the model's answer.
    detector = KeywordDetector(fail_when=lambda text: text.startswith("echo:"))
    client = make_client(make_harness(detectors=[detector]), tmp_path)

    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})

    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    body = response.json()
    assert body["outcome"] == "withheld"
    assert "withheld" in body["response"] and "echo:" not in body["response"]
    assert body["model_reply"] is None


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
    assert [r["event"] for r in harness.records()] == ["received", "decision", "outcome"]
    assert harness.external.prompts == harness.sovereign.prompts == []


def test_audit_failure_returns_503_and_no_answer(client: TestClient, harness: Harness) -> None:
    client.post("/v1/inference", json={"prompt": "warm up"})
    harness.audit.fail_on = frozenset({"decision"})

    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})

    assert response.status_code == 503
    assert response.json()["error"] == "audit_unavailable"
    assert "response" not in response.json()


def test_an_internal_error_returns_500_and_the_audit_id_of_its_record(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError

    monkeypatch.setattr("control_plane.pipeline.decide", explode)

    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})

    assert response.status_code == 500
    body = response.json()
    assert (body["error"], body["stage"]) == ("internal_error", "decision")
    records = client.get(f"/v1/audit/{body['audit_id']}").json()["records"]
    assert [r["event"] for r in records] == ["received", "detection", "error"]


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


def test_audit_requests_list_each_request_once_with_its_records_in_order(
    client: TestClient,
) -> None:
    first = client.post("/v1/inference", json={"prompt": "one"}).json()
    second = client.post("/v1/inference", json={"prompt": "two"}).json()

    page = client.get("/v1/audit/requests").json()

    assert page["total"] == 3
    assert page["next_before"] is None
    # Newest first; the policy load belongs to no request, so it is an entry of its own.
    assert [e["audit_id"] for e in page["entries"]] == [
        second["audit_id"],
        "system",
        first["audit_id"],
    ]
    assert [r["event"] for r in page["entries"][0]["records"]] == LIFECYCLE
    assert [r["event"] for r in page["entries"][1]["records"]] == ["policy_loaded"]


def test_audit_requests_page_by_request_and_never_split_one(client: TestClient) -> None:
    for prompt in ("one", "two", "three"):
        client.post("/v1/inference", json={"prompt": prompt})
    seen: list[dict] = []
    before = None

    while True:
        params = {"limit": 2} | ({"before": before} if before is not None else {})
        page = client.get("/v1/audit/requests", params=params).json()
        seen.extend(page["entries"])
        before = page["next_before"]
        if before is None:
            break

    assert len(seen) == 4  # three requests and the policy load
    assert sorted(r["seq"] for e in seen for r in e["records"]) == list(range(19))
    assert all(
        [r["event"] for r in e["records"]] == LIFECYCLE for e in seen if e["audit_id"] != "system"
    )


def test_audit_requests_can_be_filtered_by_decision_rule_and_category(
    client: TestClient,
) -> None:
    allowed = client.post("/v1/inference", json={"prompt": "What is a hash chain?"}).json()
    blocked = client.post("/v1/inference", json={"prompt": f"aws_key={AWS_KEY}"}).json()
    redacted = client.post("/v1/inference", json={"prompt": f"Mail {EMAIL}"}).json()

    def ids(**params: str) -> list[str]:
        page = client.get("/v1/audit/requests", params=params).json()
        return [e["audit_id"] for e in page["entries"]]

    assert ids(action="block") == [blocked["audit_id"]]
    # The policy load has no decision, so a filter leaves it out.
    assert ids(action="allow") == [allowed["audit_id"]]
    assert ids(action="route_sovereign") == []
    assert ids(rule_id="redact-pii") == [redacted["audit_id"]]
    assert ids(category="secret") == [blocked["audit_id"]]
    # Filters combine.
    assert ids(action="redact", category="pii") == [redacted["audit_id"]]
    assert ids(action="redact", category="secret") == []
    assert client.get("/v1/audit/requests", params={"action": "maybe"}).status_code == 422
    # What the filters can offer: the rules and categories in the log, whatever is shown.
    options = client.get("/v1/audit/requests", params={"action": "block"}).json()["options"]
    assert options == {
        "rules": ["allow-clean", "block-secrets", "redact-pii"],
        "categories": ["pii", "secret"],
    }


def test_audit_requests_can_be_searched_by_the_start_of_an_audit_id(client: TestClient) -> None:
    first = client.post("/v1/inference", json={"prompt": "one"}).json()
    client.post("/v1/inference", json={"prompt": "two"})

    found = client.get("/v1/audit/requests", params={"audit_id": first["audit_id"][:8]}).json()

    assert found["total"] == 1
    assert found["entries"][0]["audit_id"] == first["audit_id"]
    bad = client.get("/v1/audit/requests", params={"audit_id": "not-hex"})
    assert bad.status_code == 422


def test_audit_search_finds_one_request_by_its_id_or_the_start_of_it(
    client: TestClient,
) -> None:
    first = client.post("/v1/inference", json={"prompt": "one"}).json()
    client.post("/v1/inference", json={"prompt": "two"})

    for query in (first["audit_id"], first["audit_id"][:8].upper()):
        found = client.get("/v1/audit", params={"audit_id": query}).json()
        assert found["total"] == len(LIFECYCLE)
        assert {r["audit_id"] for r in found["records"]} == {first["audit_id"]}
        assert [r["event"] for r in found["records"]] == LIFECYCLE[::-1]


@pytest.mark.parametrize("query", ["abc", "not-hex!", "a" * 33])
def test_audit_search_rejects_a_malformed_id(client: TestClient, query: str) -> None:
    assert client.get("/v1/audit", params={"audit_id": query}).status_code == 422


def test_verify_endpoint_reports_an_intact_chain(client: TestClient) -> None:
    client.post("/v1/inference", json={"prompt": "one"})

    report = client.get("/v1/audit/verify").json()

    assert report["ok"] is True
    assert (report["records"], report["decisions_replayed"]) == (7, 1)


def test_verify_endpoint_reports_tampering(client: TestClient, harness: Harness) -> None:
    client.post("/v1/inference", json={"prompt": "one"})
    path = harness.audit.path
    path.write_text(path.read_text().replace('"action":"allow"', '"action":"block"', 1))

    report = client.get("/v1/audit/verify").json()

    assert report["ok"] is False
    assert report["chain_problems"][0]["reason"] == "content does not match its hash"


def test_policy_endpoint_shows_the_policy_and_what_the_editor_can_offer(
    client: TestClient, harness: Harness
) -> None:
    body = client.get("/v1/policy").json()

    assert body["valid"] is True
    assert body["id"] == "default-sovereign-policy"
    assert body["text"] == harness.policy_path.read_text()
    assert body["document"]["rules"][0]["id"] == "block-secrets"
    assert body["base_sha256"] == body["sha256"]
    assert (body["is_default"], body["editable"], body["history"]) == (True, True, [])
    assert body["catalog"]["entity_types"]["EMAIL_ADDRESS"] == ["fake-pii"]
    assert body["catalog"]["entity_types"]["AWS_ACCESS_KEY"] == ["rules"]
    assert "invalid_input" not in body["catalog"]["labels"]

    harness.corrupt_policy()
    broken = client.get("/v1/policy").json()
    assert broken["valid"] is False
    assert "modified on disk" in broken["error"]
    # Still named, so "restore default" can say which version it replaces.
    assert broken["base_sha256"] == body["sha256"]


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
    body = response.json()
    assert (body["outcome"], body["outcome_reason"]) == ("blocked", "policy_unavailable")
    assert "policy" in body["response"] and "Try again" in body["response"]
    assert health.status_code == 503
    assert health.json()["status"] == "degraded"
    assert health.json()["policy"]["valid"] is False
    assert "modified on disk" in health.json()["policy"]["error"]
    assert harness.external.prompts == harness.sovereign.prompts == []

    restore_default(client)

    assert client.post("/v1/inference", json={"prompt": "hi"}).status_code == 200
    assert client.get("/healthz").json()["policy"] == {"valid": True, "error": None}


def test_alerts_report_a_broken_policy_now_and_the_requests_it_blocked(
    client: TestClient, harness: Harness
) -> None:
    harness.corrupt_policy()
    client.post("/v1/inference", json={"prompt": "What is a hash chain?"})

    broken = client.get("/v1/alerts").json()

    assert broken["status"] == "critical"
    assert broken["alerts"][0]["id"] == "policy_invalid"
    assert "blocked_policy_unavailable" in {a["id"] for a in broken["alerts"]}
    assert broken["window"] == {**broken["window"], "hours": 24, "requests": 1}

    restore_default(client)
    fixed = client.get("/v1/alerts").json()

    # The live alert clears; the requests it blocked stay in the period.
    assert {a["id"] for a in fixed["alerts"]} == {"blocked_policy_unavailable"}
    assert fixed["status"] == "warning"


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


def test_alerts_see_a_replaced_public_key(client: TestClient, harness: Harness) -> None:
    client.post("/v1/inference", json={"prompt": "one"})
    assert verification_alert(client) is None

    write_public_key(harness.data_dir / "keys", Ed25519PrivateKey.generate().public_key())

    alert = verification_alert(client)
    assert alert is not None
    assert "signed by key" in alert["detail"]


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
    assert body["policy"]["version"] == before["next_version"]
    assert body["changes"] == [
        f'Version changed from "{before["version"]}" to "{before["next_version"]}".',
        "Rule allow-clean: action changed from allow to route_sovereign.",
    ]
    answer = client.post("/v1/inference", json={"prompt": "What is a hash chain?"}).json()
    assert answer["decision"]["action"] == "route_sovereign"
    assert answer["policy"]["sha256"] == body["policy"]["sha256"]

    policy = client.get("/v1/policy").json()
    assert policy["is_default"] is False
    (entry,) = policy["history"]
    assert (entry["seq"], entry["note"]) == (body["receipt"]["seq"], "Audit week")
    assert entry["changes"] == body["changes"]
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
    assert refused.json()["detail"] == (
        f"Version {info['version']} already names another policy, so this change needs "
        f"its own version, such as {info['next_version']}."
    )
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
    assert refused.json()["detail"]["errors"] == checked["errors"]
    assert checked["errors"][0]["message"].startswith("block-secrets would send prompts with")
    assert client.get("/v1/policy").json()["sha256"] == info["sha256"]


def test_the_next_version_offered_skips_versions_already_used(client: TestClient) -> None:
    first = client.get("/v1/policy").json()
    draft = stricter_draft(client)
    client.put(
        "/v1/policy",
        json={"document": draft, "base_sha256": first["base_sha256"], "note": "x"},
        headers=ADMIN,
    )
    base = client.get("/v1/policy").json()["base_sha256"]
    client.post("/v1/policy/restore-default", json={"base_sha256": base}, headers=ADMIN)

    restored = client.get("/v1/policy").json()

    assert restored["version"] == first["version"]
    assert restored["next_version"] not in {first["version"], draft["version"]}


def test_with_open_editing_anyone_changes_the_policy_as_a_visitor(
    harness: Harness, tmp_path: Path
) -> None:
    client = make_client(harness, tmp_path, admin_token=None, open_editing=True)
    info = client.get("/v1/policy").json()
    assert (info["editable"], info["open_editing"]) == (True, True)

    saved = client.put(
        "/v1/policy",
        json={"document": stricter_draft(client), "base_sha256": info["base_sha256"], "note": "x"},
    )
    assert saved.status_code == 200
    assert client.get("/v1/policy").json()["history"][0]["changed_by"] == "visitor"

    # Anyone can also go back to the original policy.
    base = client.get("/v1/policy").json()["base_sha256"]
    restored = client.post("/v1/policy/restore-default", json={"base_sha256": base})
    assert restored.status_code == 200
    after = client.get("/v1/policy").json()
    assert after["is_default"] is True
    assert after["history"][0]["changed_by"] == "visitor"
    assert client.get("/v1/audit/verify").json()["ok"] is True


def test_open_editing_still_names_the_admin_and_refuses_a_wrong_token(
    harness: Harness, tmp_path: Path
) -> None:
    client = make_client(harness, tmp_path, open_editing=True)
    draft = stricter_draft(client)
    base = client.get("/v1/policy").json()["base_sha256"]
    save = {"document": draft, "base_sha256": base, "note": "x"}

    wrong = client.put("/v1/policy", json=save, headers={"authorization": "Bearer wrong"})
    assert wrong.status_code == 401

    assert client.put("/v1/policy", json=save, headers=ADMIN).status_code == 200
    assert client.get("/v1/policy").json()["history"][0]["changed_by"].startswith("admin-token:")


def test_without_open_editing_the_policy_reports_it_is_closed(client: TestClient) -> None:
    assert client.get("/v1/policy").json()["open_editing"] is False


def test_an_invalid_draft_is_refused_and_says_which_field_is_wrong(
    client: TestClient, harness: Harness
) -> None:
    draft = stricter_draft(client)
    draft["rules"][0]["action"] = "maybe"
    draft["rules"][1]["when"]["any_category"] = ["no_such_category"]
    base = client.get("/v1/policy").json()["base_sha256"]

    checked = client.post("/v1/policy/check", json={"document": draft}).json()
    saved = client.put(
        "/v1/policy", json={"document": draft, "base_sha256": base, "note": "x"}, headers=ADMIN
    )

    assert checked["valid"] is False
    assert [error["path"] for error in checked["errors"]] == ["rules.0.action"]
    assert saved.status_code == 422
    assert saved.json()["detail"]["errors"] == checked["errors"]

    draft["rules"][0]["action"] = "block"
    unknown = client.post("/v1/policy/check", json={"document": draft}).json()
    assert unknown["errors"] == [
        {"path": "", "message": "unknown categories referenced: no_such_category"}
    ]
    assert harness.records("policy_changed") == []


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


@pytest.mark.parametrize("admin_token", [ADMIN_TOKEN, None])
def test_anyone_can_preview_a_draft_without_changing_anything(
    harness: Harness, tmp_path: Path, admin_token: str | None
) -> None:
    # No token is sent, and with None the server has no token at all: trying a draft is
    # open to anyone, while saving it is not.
    client = make_client(harness, tmp_path, admin_token=admin_token)
    draft = stricter_draft(client)
    recorded = len(harness.records())

    preview = client.post(
        "/v1/policy/preview", json={"document": draft, "prompt": "What is a hash chain?"}
    ).json()

    assert (preview["current"]["action"], preview["draft"]["action"]) == (
        "allow",
        "route_sovereign",
    )
    assert preview["changed"] is True
    assert len(harness.records()) == recorded
    assert harness.external.prompts == harness.sovereign.prompts == []
    assert client.get("/v1/policy").json()["is_default"] is True


def test_a_preview_still_refuses_an_oversized_prompt(client: TestClient) -> None:
    draft = stricter_draft(client)
    too_long = "x" * (MAX_PROMPT_CHARS + 1)

    preview = client.post("/v1/policy/preview", json={"document": draft, "prompt": too_long})

    assert preview.status_code == 413


def test_an_oversized_policy_body_is_refused(client: TestClient) -> None:
    response = client.put(
        "/v1/policy",
        content=b'{"note": "' + b"x" * 300_000 + b'"}',
        headers={**ADMIN, "content-type": "application/json"},
    )

    assert response.status_code == 413


@pytest.mark.parametrize("hours", [0, -1, 24 * 365 + 1])
def test_alerts_reject_a_window_out_of_range(client: TestClient, hours: int) -> None:
    assert client.get(f"/v1/alerts?hours={hours}").status_code == 422


def test_health_reports_components_without_calling_models(
    client: TestClient, harness: Harness
) -> None:
    health = client.get("/healthz")
    body = health.json()

    assert health.status_code == 200
    assert body["status"] == "ok"
    assert body["policy"] == {"valid": True, "error": None}
    assert body["failing_detectors"] == {}
    assert body["sovereign_model"]["provider"] == "ollama"
    assert body["external_model"]["provider"] == "anthropic"
    assert harness.external.prompts == harness.sovereign.prompts == []


def test_health_is_degraded_while_a_detector_is_failing(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    broken = KeywordDetector(name="presidio", error=RuntimeError("model crashed"))
    client = make_client(make_harness(detectors=[RuleDetector(), broken]), tmp_path)

    client.post("/v1/inference", json={"prompt": "hello"})
    health = client.get("/healthz")

    assert health.status_code == 503
    assert health.json()["status"] == "degraded"
    assert health.json()["failing_detectors"] == {"presidio": "RuntimeError"}


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
    assert health.json()["detectors"]["presidio"] == "unavailable (ModelNotInstalledError)"

    response = client.post("/v1/inference", json={"prompt": "What is a hash chain?"})
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    assert response.json()["decision"]["fail_closed"] is True
    assert (response.json()["outcome"], response.json()["outcome_reason"]) == (
        "blocked",
        "detection_failed",
    )

    # Both alerts: the detector failing now, and the request it could not check.
    alerts = {a["id"]: a for a in client.get("/v1/alerts").json()["alerts"]}
    assert alerts["detector_failing:presidio"]["severity"] == "critical"
    assert alerts["detection_failures"]["count"] == 1


def test_without_an_api_key_the_external_model_is_anthropic_and_not_ready(
    tmp_path: Path,
) -> None:
    # There is no stand-in outside the boundary: without a key, nothing can leave.
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        policy_path=DEFAULT_POLICY_PATH,
        ui_dir=tmp_path / "no-ui",
        spacy_model="not_an_installed_model",
        sovereign_provider="stub",
        anthropic_api_key=None,
    )
    client = TestClient(create_app(build_services(settings)))

    assert client.get("/healthz").json()["external_model"] == {
        "provider": "anthropic",
        "model": "claude-haiku-5-5",
        "stub": False,
        "ready": False,
        "detail": "No ANTHROPIC_API_KEY is set",
    }


def test_client_id_header_is_recorded_only_when_well_formed(
    client: TestClient, harness: Harness
) -> None:
    client.post("/v1/inference", json={"prompt": "one"}, headers={"x-client-id": "billing-app"})
    client.post(
        "/v1/inference", json={"prompt": "two"}, headers={"x-client-id": "bad id\twith junk"}
    )

    claimed = [r["body"]["request"]["client_id_claimed"] for r in harness.records("decision")]
    assert claimed == ["billing-app", None]


def test_the_ui_page_is_revalidated_and_its_hashed_assets_are_not(
    harness: Harness, tmp_path: Path
) -> None:
    ui = tmp_path / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text('<script src="/assets/index-abc123.js"></script>')
    (ui / "assets" / "index-abc123.js").write_text("console.log(1)")
    client = make_client(harness, tmp_path, ui_dir=ui)

    page = client.get("/")
    script = client.get("/assets/index-abc123.js")

    assert (page.status_code, page.headers["cache-control"]) == (200, "no-cache")
    assert script.status_code == 200
    assert "cache-control" not in script.headers
