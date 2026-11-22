"""Alerts and metrics for the admin, derived from live status and the audit log.

Nothing here is stored. Every alert is computed from evidence that already exists, so it
clears when its cause is fixed or falls out of the time window. No prompt text is
involved, not even the masked prompt in the detection record: an alert points to its
requests by audit ID, label, categories and finding types.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from control_plane.audit.chain import (
    EVENT_DECISION,
    EVENT_DETECTION,
    EVENT_ERROR,
    EVENT_OUTCOME,
    EVENT_POLICY_CHANGED,
    EVENT_POLICY_LOADED,
    EVENT_RECEIVED,
    INVALID_REQUEST_RULE_ID,
    POLICY_UNAVAILABLE_RULE_ID,
)
from control_plane.audit.verify import Report
from control_plane.evidence import recorded_signals
from control_plane.models import Label
from control_plane.policy import DEFAULT_RULE_ID
from control_plane.providers.base import ProviderStatus

EXAMPLES_PER_ALERT = 5
# Warn when at least this share of judged prompts was only "uncertain"...
UNCERTAIN_SHARE_WARNING = 0.2
# ...but not on a handful of requests, where one prompt is a large share.
UNCERTAIN_MIN_DECISIONS = 10
# Below this many decisions, a rule that never matched says little about the policy.
UNMATCHED_RULES_MIN_DECISIONS = 20
# A request with no outcome yet may still be in progress: a local model can take minutes.
IN_FLIGHT_GRACE = timedelta(minutes=10)
TOP_CLIENTS = 5


class Severity(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}


class Group(StrEnum):
    HEALTH = "health"
    POLICY = "policy"
    SECURITY = "security"
    SERVICE = "service"


@dataclass(frozen=True)
class Example:
    """One request behind an alert, described by its evidence. Never by its text."""

    audit_id: str
    ts: str
    label: str | None
    categories: tuple[str, ...]
    entity_types: tuple[str, ...]
    rule_id: str | None
    reason: str | None
    client: str | None


@dataclass(frozen=True)
class Alert:
    id: str
    group: Group
    severity: Severity
    title: str
    detail: str
    # What the admin should do about it.
    action: str
    count: int = 1
    last_seen: str | None = None
    examples: tuple[Example, ...] = ()


@dataclass(frozen=True)
class ModelState:
    name: str
    stub: bool
    status: ProviderStatus


@dataclass(frozen=True)
class LogSummary:
    alerts: list[Alert]
    metrics: dict[str, Any]


# ---------------------------------------------------------------- live status


_DETECTOR_ACTIONS = {
    "presidio": "Check that the spaCy model is installed; /healthz shows its version.",
    "semantic": (
        "Check that Ollama is running and the model is pulled. A TimeoutError can also mean "
        "a prompt was too long to judge within SCP_DETECTION_TIMEOUT_S; it clears with the "
        "next prompt judged in time."
    ),
}


def live_alerts(
    *,
    policy_error: str | None,
    failing_detectors: Mapping[str, str],
    sovereign: ModelState,
    external: ModelState,
    verification: Report,
) -> list[Alert]:
    """Problems that exist right now, whatever the time window."""
    alerts: list[Alert] = []
    if policy_error is not None:
        alerts.append(
            Alert(
                "policy_invalid",
                Group.HEALTH,
                Severity.CRITICAL,
                "The policy is missing or invalid",
                f"{policy_error}. Every request is blocked and no model is called.",
                "Restore the default policy, or save a valid one, on the Policy tab. The "
                "change takes effect on the next request, with no restart.",
            )
        )
    for name, error in sorted(failing_detectors.items()):
        alerts.append(
            Alert(
                f"detector_failing:{name}",
                Group.HEALTH,
                Severity.CRITICAL,
                f"Detector '{name}' is failing",
                f"Its most recent run ended in {error}. A prompt it cannot check is never "
                "sent out: the shipped policy blocks it with HTTP 503.",
                _DETECTOR_ACTIONS.get(name, "Check the control plane logs for this detector."),
            )
        )
    alerts.extend(_model_alerts(sovereign, external))
    if not verification.ok:
        first = (verification.chain_problems or verification.replay_problems)[0]
        alerts.append(
            Alert(
                "audit_verification_failed",
                Group.HEALTH,
                Severity.CRITICAL,
                "The audit log failed verification",
                f"Record {first.seq}: {first.reason}. Records from that point cannot be trusted.",
                "Compare the log with the receipts callers kept, find out who changed the "
                "file, and restore it from a backup. `make verify` gives the full report.",
            )
        )
    return alerts


def _model_alerts(sovereign: ModelState, external: ModelState) -> list[Alert]:
    alerts: list[Alert] = []
    if sovereign.stub:
        alerts.append(
            Alert(
                "local_model_stub",
                Group.HEALTH,
                Severity.INFO,
                "The local model is a stub",
                "Prompts that stay inside get a labelled stand-in answer, and the semantic "
                "detector is off.",
                "Run with Ollama (docker compose up) for a real model inside the boundary.",
            )
        )
    elif not sovereign.status.ready:
        alerts.append(
            Alert(
                "local_model_down",
                Group.HEALTH,
                Severity.CRITICAL,
                "The local model is not ready",
                f"{sovereign.status.detail}. Prompts that must stay inside are blocked, and "
                "the semantic detector cannot run, so every prompt is blocked.",
                "Check the Ollama container and that the model is pulled "
                "(docker compose logs ollama ollama-pull).",
            )
        )
    if not external.status.ready:
        alerts.append(
            Alert(
                "external_model_down",
                Group.HEALTH,
                Severity.WARNING,
                "The external model is not reachable",
                f"{external.status.detail}. Prompts the policy allows out get no answer.",
                "Check the provider's status, the API key and network access.",
            )
        )
    return alerts


# ---------------------------------------------------------------- audit log


@dataclass(frozen=True)
class _Kind:
    group: Group
    severity: Severity
    title: str
    detail: str
    action: str


_KINDS: dict[str, _Kind] = {
    "no_rule_matched": _Kind(
        Group.POLICY,
        Severity.WARNING,
        "No policy rule matched",
        "None of the policy's rules matched these requests, so its default action was "
        "applied. Their categories or label are not covered by any rule.",
        "Look at the categories and finding types below, then add a rule on the Policy "
        "tab, or confirm that the default action is right for them.",
    ),
    "blocked_policy_unavailable": _Kind(
        Group.POLICY,
        Severity.WARNING,
        "Blocked while the policy was missing or invalid",
        "No decision could be made for these requests, so they were blocked. No model was called.",
        "See the policy timeline below for when the policy broke and was fixed.",
    ),
    "uncertain_share": _Kind(
        Group.POLICY,
        Severity.WARNING,
        "Many prompts had only weak evidence",
        "A large share of the judged prompts was 'uncertain', so they were kept inside "
        "although nothing certain was found.",
        "Look at which finding types score in the uncertain band. A better recognizer or a "
        "threshold change in the policy may help.",
    ),
    "prompt_injection": _Kind(
        Group.SECURITY,
        Severity.WARNING,
        "Prompt injection detected",
        "The semantic detector judged these prompts to be attempts to control the AI they "
        "are sent to. Under the default policy they are blocked before any model is called.",
        "Check which client sent them. Repeated attempts from one client may be an attack, "
        "or a tool that pastes untrusted content into prompts.",
    ),
    "secret_sent": _Kind(
        Group.SECURITY,
        Severity.WARNING,
        "A secret or credential was sent",
        "These prompts contained a key, token, password or private key. Under the default "
        "policy they are blocked, so the secret did not reach a model.",
        "Tell the sender. If the credential may have been shared anywhere else, rotate it.",
    ),
    "egress_refused": _Kind(
        Group.SECURITY,
        Severity.WARNING,
        "Egress refused by the allowlist",
        "The policy allowed these prompts out, but the destination is not on "
        "egress.allowed_destinations, so nothing was sent.",
        "Add the destination to the allowlist if it should be used, or leave it refused.",
    ),
    "rejected_requests": _Kind(
        Group.SECURITY,
        Severity.INFO,
        "Requests rejected at the door",
        "Malformed, oversized or non-JSON requests. Their content was neither inspected "
        "nor stored.",
        "If one client sends many, check that client.",
    ),
    "answers_withheld": _Kind(
        Group.SERVICE,
        Severity.WARNING,
        "Answers withheld",
        "The model answered, but the answer could not be checked for private data because "
        "a detector failed, so it was not returned.",
        "Fix the failing detector; see the detection failures.",
    ),
    "local_model_unavailable": _Kind(
        Group.SERVICE,
        Severity.WARNING,
        "Blocked because the local model was down",
        "These prompts had to stay inside and the local model did not answer, so they were "
        "blocked. They were not sent outside.",
        "Check the Ollama container and that the model is pulled.",
    ),
    "external_model_errors": _Kind(
        Group.SERVICE,
        Severity.WARNING,
        "External model errors",
        "The external model was called but returned no answer.",
        "Check the provider's status, the API key and network access.",
    ),
    "detection_failures": _Kind(
        Group.SERVICE,
        Severity.WARNING,
        "Detection failures",
        "A detector failed or timed out, so these prompts could not be checked and were "
        "not sent out: the shipped policy blocks them.",
        "Check the detector named in each entry. A semantic TimeoutError usually means the "
        "prompt was too long to judge within SCP_DETECTION_TIMEOUT_S on this hardware.",
    ),
    "internal_errors": _Kind(
        Group.SERVICE,
        Severity.WARNING,
        "Requests that failed on an internal error",
        "An unexpected exception ended these requests, and no answer was returned. Each one "
        "has an error record naming the step that failed and the exception class.",
        "Search the control plane logs for the audit ID: the stack trace is logged there.",
    ),
    "interrupted_requests": _Kind(
        Group.SERVICE,
        Severity.WARNING,
        "Requests interrupted before their outcome",
        "A request was recorded but has no outcome or error, so the process stopped "
        "mid-request. Its last record shows how far it got: a model_call record means a "
        "model was being called, and a model_reply record means its answer was back but "
        "not yet returned.",
        "Check the control plane logs around that time. `make verify` lists them too.",
    ),
    "model_notes": _Kind(
        Group.SERVICE,
        Severity.INFO,
        "External model refused or truncated answers",
        "The provider flagged these answers: a refusal answered by the fallback model, or an "
        "answer cut off at the length limit.",
        "Usually nothing. Many of them may point to prompts the model will not answer.",
    ),
}


@dataclass(frozen=True)
class _Request:
    """A decision record and, if they were written, its detection and its outcome or error."""

    decision: Mapping[str, Any]
    outcome: Mapping[str, Any] | None
    error: Mapping[str, Any] | None = None
    detection: Mapping[str, Any] | None = None

    @property
    def body(self) -> Mapping[str, Any]:
        return self.decision["body"]

    @property
    def signals(self) -> Mapping[str, Any]:
        detection = self.detection["body"] if self.detection else None
        return recorded_signals(self.body, detection) or {}

    @property
    def rule_id(self) -> str | None:
        return _get(self.body, "decision", "rule_id")

    @property
    def action(self) -> str | None:
        return _get(self.body, "decision", "action")

    @property
    def label(self) -> str | None:
        return _get(self.body, "classification", "label")

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(_get(self.body, "classification", "categories") or ())

    @property
    def entity_types(self) -> tuple[str, ...]:
        findings = self.signals.get("findings") or ()
        return tuple(sorted({f["entity_type"] for f in findings}))

    @property
    def client(self) -> str | None:
        return _get(self.body, "request", "client_id_claimed")

    @property
    def outcome_body(self) -> Mapping[str, Any]:
        return self.outcome["body"] if self.outcome else {}

    @property
    def reason(self) -> str | None:
        return self.outcome_body.get("reason")

    def example(self, reason: str | None = None) -> Example:
        return Example(
            audit_id=self.decision["audit_id"],
            ts=self.decision["ts"],
            label=self.label,
            categories=self.categories,
            entity_types=self.entity_types,
            rule_id=self.rule_id,
            reason=reason if reason is not None else self.reason,
            client=self.client,
        )


class _Tally:
    """Counts requests per alert kind and keeps the most recent few as examples."""

    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._examples: dict[str, list[Example]] = {}

    def add(self, kind: str, example: Example) -> None:
        self._counts[kind] += 1
        self._examples.setdefault(kind, []).append(example)

    def alerts(self) -> list[Alert]:
        alerts = []
        for kind, count in self._counts.items():
            spec = _KINDS[kind]
            newest = sorted(self._examples[kind], key=lambda e: e.ts, reverse=True)
            alerts.append(
                Alert(
                    kind,
                    spec.group,
                    spec.severity,
                    spec.title,
                    spec.detail,
                    spec.action,
                    count=count,
                    last_seen=newest[0].ts,
                    examples=tuple(newest[:EXAMPLES_PER_ALERT]),
                )
            )
        return alerts


def summarize_log(
    records: Sequence[Mapping[str, Any]],
    *,
    since: datetime,
    now: datetime,
    rule_ids: Sequence[str],
) -> LogSummary:
    """Alerts and metrics for the requests decided at or after `since`.

    `rule_ids` are the rules of the policy in force now, to find the ones that never matched.
    """
    outcomes = {r["audit_id"]: r for r in records if r["event"] == EVENT_OUTCOME}
    errors = {r["audit_id"]: r for r in records if r["event"] == EVENT_ERROR}
    detections = {r["audit_id"]: r for r in records if r["event"] == EVENT_DETECTION}
    requests = [
        _Request(
            r,
            outcomes.get(r["audit_id"]),
            errors.get(r["audit_id"]),
            detections.get(r["audit_id"]),
        )
        for r in records
        if r["event"] == EVENT_DECISION and _ts(r) >= since
    ]
    tally = _Tally()
    for request in requests:
        _tally_request(tally, request, now)
    decided = {r["audit_id"] for r in records if r["event"] == EVENT_DECISION}
    for received in records:
        if (
            received["event"] == EVENT_RECEIVED
            and received["audit_id"] not in decided
            and _ts(received) >= since
        ):
            _tally_undecided(tally, received, errors.get(received["audit_id"]), now)

    judged = [
        r
        for r in requests
        if r.label != Label.INVALID_INPUT and r.rule_id != POLICY_UNAVAILABLE_RULE_ID
    ]
    uncertain = [r for r in judged if r.label == Label.UNCERTAIN]
    share = len(uncertain) / len(judged) if judged else 0.0
    if len(judged) >= UNCERTAIN_MIN_DECISIONS and share >= UNCERTAIN_SHARE_WARNING:
        for request in uncertain:
            tally.add("uncertain_share", request.example())

    policy_events = [r for r in records if r["event"] in _POLICY_EVENTS and _ts(r) >= since]
    metrics = _metrics(requests, policy_events, rule_ids, uncertain_share=share)
    return LogSummary(alerts=tally.alerts(), metrics=metrics)


_POLICY_EVENTS = frozenset({EVENT_POLICY_LOADED, EVENT_POLICY_CHANGED})

# Decisions, categories and outcome reasons that need attention, and their alert kind.
_RULE_KINDS = {
    DEFAULT_RULE_ID: "no_rule_matched",
    POLICY_UNAVAILABLE_RULE_ID: "blocked_policy_unavailable",
}
_CATEGORY_KINDS = {"prompt_injection": "prompt_injection", "secret": "secret_sent"}
_REASON_KINDS = (
    ("egress_denied:", "egress_refused"),
    ("output_scan_failed", "answers_withheld"),
    ("sovereign_model_unavailable:", "local_model_unavailable"),
    ("external_model_error:", "external_model_errors"),
)


def _tally_request(tally: _Tally, request: _Request, now: datetime) -> None:
    _tally_decision(tally, request)
    if request.error is not None:
        tally.add("internal_errors", request.example(_error_reason(request.error)))
    elif request.outcome is None:
        if _ts(request.decision) < now - IN_FLIGHT_GRACE:
            tally.add("interrupted_requests", request.example())
    else:
        _tally_outcome(tally, request)


def _tally_undecided(
    tally: _Tally, received: Mapping[str, Any], error: Mapping[str, Any] | None, now: datetime
) -> None:
    """A request that never reached a decision: it failed, was interrupted, or is in progress."""
    example = Example(
        audit_id=received["audit_id"],
        ts=received["ts"],
        label=None,
        categories=(),
        entity_types=(),
        rule_id=None,
        reason=_error_reason(error) if error else "no decision",
        client=_get(received["body"], "request", "client_id_claimed"),
    )
    if error is not None:
        tally.add("internal_errors", example)
    elif _ts(received) < now - IN_FLIGHT_GRACE:
        tally.add("interrupted_requests", example)


def _error_reason(error: Mapping[str, Any]) -> str:
    """Where and how a request failed, such as `detection:RuntimeError`."""
    return f"{_get(error['body'], 'stage')}:{_get(error['body'], 'error')}"


def _tally_decision(tally: _Tally, request: _Request) -> None:
    rule_id = request.rule_id or ""
    if rule_id in _RULE_KINDS:
        tally.add(_RULE_KINDS[rule_id], request.example())
    elif rule_id == INVALID_REQUEST_RULE_ID:
        tally.add("rejected_requests", request.example(_get(request.body, "request", "rejected")))
    for category in request.categories:
        if category in _CATEGORY_KINDS:
            tally.add(_CATEGORY_KINDS[category], request.example())
    for run in request.signals.get("detectors") or ():
        if not run.get("ok", True):
            tally.add("detection_failures", request.example(f"{run['name']}:{run.get('error')}"))


def _tally_outcome(tally: _Tally, request: _Request) -> None:
    reason = request.reason or ""
    for prefix, kind in _REASON_KINDS:
        if reason.startswith(prefix):
            tally.add(kind, request.example())
    if note := _get(request.outcome_body, "model", "note"):
        tally.add("model_notes", request.example(note))


def _metrics(
    requests: Sequence[_Request],
    policy_events: Iterable[Mapping[str, Any]],
    rule_ids: Sequence[str],
    *,
    uncertain_share: float,
) -> dict[str, Any]:
    by_rule = Counter(rule for r in requests if (rule := r.rule_id))
    clients: Counter[str | None] = Counter(r.client for r in requests)
    blocked: Counter[str | None] = Counter(r.client for r in requests if r.action == "block")
    redacted: Counter[str] = Counter()
    latency: dict[str, list[int]] = {"inside": [], "outside": []}
    sent_outside = kept_inside = 0
    for request in requests:
        body = request.outcome_body
        redacted.update(_get(body, "redaction", "by_entity") or {})
        if _get(body, "egress", "attempted"):
            sent_outside += 1
        model = body.get("model") or {}
        if model.get("called") and model.get("in_boundary"):
            kept_inside += 1
        # Stub calls are not model calls worth timing.
        if model.get("called") and not model.get("stub") and model.get("latency_ms") is not None:
            latency["inside" if model.get("in_boundary") else "outside"].append(model["latency_ms"])

    enough = len(requests) >= UNMATCHED_RULES_MIN_DECISIONS
    return {
        "requests": len(requests),
        "by_action": _ranked(Counter(a for r in requests if (a := r.action))),
        "by_outcome": _ranked(
            Counter(
                _get(r.outcome_body, "status") or ("error" if r.error else "no outcome")
                for r in requests
            )
        ),
        "by_label": _ranked(Counter(label for r in requests if (label := r.label))),
        "by_category": _ranked(Counter(c for r in requests for c in r.categories)),
        "fail_closed": sum(bool(_get(r.body, "decision", "fail_closed")) for r in requests),
        "sent_outside": sent_outside,
        "kept_inside": kept_inside,
        "redacted_by_entity": _ranked(redacted),
        "uncertain_share": round(uncertain_share, 3),
        "latency_ms": {where: _latency(values) for where, values in latency.items()},
        "top_clients": [
            {"client": client, "requests": count, "blocked": blocked[client]}
            for client, count in clients.most_common(TOP_CLIENTS)
        ],
        "rule_matches": _ranked(by_rule),
        # None until there are enough decisions for "never matched" to mean something.
        "rules_not_matched": [r for r in rule_ids if by_rule[r] == 0] if enough else None,
        "policy_timeline": _policy_changes(policy_events),
    }


def _policy_changes(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Each change of policy state. A restart reloads the same policy: not a change.

    An administrator's change is always listed, with its note, even if it went back to
    the version in force before.
    """
    changes = []
    previous = None
    for record in records:
        event = _policy_event(record)
        state = event["sha256"] if event["valid"] else f"invalid:{event['error']}"
        if state != previous or event["note"] is not None:
            changes.append(event)
        previous = state
    return changes


def _policy_event(record: Mapping[str, Any]) -> dict[str, Any]:
    body = record["body"]
    if record["event"] == EVENT_POLICY_CHANGED:
        policy = body.get("policy") or {}
        return {
            "ts": record["ts"],
            "valid": True,
            "id": policy.get("id"),
            "version": policy.get("version"),
            "sha256": policy.get("sha256"),
            "error": None,
            "note": body.get("note"),
            "changed_by": body.get("changed_by"),
            "changes": body.get("changes") or [],
        }
    return {
        "ts": record["ts"],
        "valid": bool(body.get("valid")),
        "id": body.get("id"),
        "version": body.get("version"),
        "sha256": body.get("sha256"),
        "error": body.get("error"),
        "note": None,
        "changed_by": None,
        "changes": [],
    }


def _latency(values: Sequence[int]) -> dict[str, int | None]:
    if not values:
        return {"count": 0, "median": None, "p95": None}
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "median": _nearest_rank(ordered, 0.5),
        "p95": _nearest_rank(ordered, 0.95),
    }


def _nearest_rank(ordered: Sequence[int], quantile: float) -> int:
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


def _ranked(counter: Counter[str]) -> dict[str, int]:
    return dict(counter.most_common())


# ---------------------------------------------------------------- the report


def build_report(
    live: Sequence[Alert],
    summary: LogSummary,
    *,
    hours: int,
    since: datetime,
    now: datetime,
) -> dict[str, Any]:
    alerts = sorted(
        [*live, *summary.alerts],
        key=lambda a: (_SEVERITY_RANK[a.severity], _newest_first(a.last_seen)),
    )
    worst = alerts[0].severity.value if alerts else "ok"
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "window": {
            "hours": hours,
            "since": since.isoformat(timespec="seconds"),
            "requests": summary.metrics["requests"],
        },
        "status": worst,
        "alerts": [asdict(alert) for alert in alerts],
        "metrics": summary.metrics,
    }


def _newest_first(ts: str | None) -> float:
    # Live alerts have no timestamp: they are happening now, so they sort first.
    return -datetime.fromisoformat(ts).timestamp() if ts else -math.inf


def _ts(record: Mapping[str, Any]) -> datetime:
    return datetime.fromisoformat(record["ts"])


def _get(source: Mapping[str, Any] | None, *keys: str) -> Any:
    """Read a nested field, tolerating older records that lack it."""
    value: Any = source
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value
