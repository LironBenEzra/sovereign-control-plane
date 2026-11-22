import { useCallback, useEffect, useRef, useState } from "react";
import { getAlerts } from "../api";
import {
  ACTION_LABELS,
  LABEL_TEXT,
  OUTCOME_TEXT,
  categoryTone,
  formatDateTime,
  shortHash,
} from "../text";
import type {
  Action,
  Alert,
  AlertExample,
  AlertGroup,
  AlertMetrics,
  AlertsReport,
  Label,
  LatencyStats,
  Outcome,
  Severity,
} from "../types";

interface Props {
  onShowEvidence: (auditId: string) => void;
}

const POLL_MS = 30_000;

const PERIODS = [
  { hours: 1, label: "1 hour" },
  { hours: 24, label: "24 hours" },
  { hours: 24 * 7, label: "7 days" },
  { hours: 24 * 30, label: "30 days" },
];

const GROUPS: { id: AlertGroup; title: string; empty: string }[] = [
  { id: "health", title: "Health now", empty: "Every component is working." },
  {
    id: "policy",
    title: "Policy",
    empty: "Every request matched a rule, and the policy was valid throughout.",
  },
  {
    id: "security",
    title: "Security events",
    empty: "No prompt injections, secrets, refused egress or rejected requests.",
  },
  {
    id: "service",
    title: "Service problems",
    empty: "No withheld answers, model errors, detection failures or interrupted requests.",
  },
];

// Severity is never shown by colour alone: each has a shape and a word.
const SEVERITY: Record<Severity, { icon: string; text: string }> = {
  critical: { icon: "■", text: "Critical" },
  warning: { icon: "▲", text: "Warning" },
  info: { icon: "●", text: "Info" },
};

export function Alerts({ onShowEvidence }: Props) {
  const [hours, setHours] = useState(24);
  const [report, setReport] = useState<AlertsReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Only the newest request may update the view, so a slow answer for an old period
  // cannot overwrite the period just chosen.
  const latest = useRef(0);

  const refresh = useCallback(async () => {
    const id = ++latest.current;
    try {
      const next = await getAlerts(hours);
      if (id !== latest.current) return;
      setReport(next);
      setError(null);
    } catch {
      if (id === latest.current) setError("The alerts could not be loaded.");
    }
  }, [hours]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  return (
    <div className="alerts">
      <header className="page-head alerts-head">
        <div>
          <h2 className="page-title">Alerts</h2>
          <p className="hint">
            What needs attention, from live status and the audit log. Alerts never show prompt text,
            so each request is shown by its evidence. Open a request to see its full records.
          </p>
        </div>
        <div className="alerts-controls">
          <div className="segmented" role="group" aria-label="Period">
            {PERIODS.map((period) => (
              <button
                key={period.hours}
                type="button"
                aria-pressed={hours === period.hours}
                onClick={() => setHours(period.hours)}
              >
                {period.label}
              </button>
            ))}
          </div>
          <button type="button" className="secondary" onClick={() => void refresh()}>
            Refresh
          </button>
        </div>
        {report && (
          <p className="hint alerts-summary">
            <StatusTag status={report.status} />
            <span>
              {report.window.requests} requests since {formatDateTime(report.window.since)}.
              Updated {formatDateTime(report.generated_at)}.
            </span>
          </p>
        )}
      </header>

      {error && (
        <div className="banner banner-bad" role="alert">
          {error}
        </div>
      )}

      {report &&
        GROUPS.map((group) => (
          <AlertSection
            key={group.id}
            title={group.title}
            empty={group.empty}
            alerts={report.alerts.filter((a) => a.group === group.id)}
            onShowEvidence={onShowEvidence}
          />
        ))}
      {report && <PolicyHygiene metrics={report.metrics} />}
      {report && <Traffic metrics={report.metrics} />}
    </div>
  );
}

function StatusTag({ status }: { status: Severity | "ok" }) {
  if (status === "ok") {
    return <span className="sev-tag sev-ok">✓ Nothing needs attention</span>;
  }
  return <SeverityTag severity={status} />;
}

function SeverityTag({ severity }: { severity: Severity }) {
  const { icon, text } = SEVERITY[severity];
  return (
    <span className={`sev-tag sev-${severity}`}>
      <span aria-hidden="true">{icon}</span> {text}
    </span>
  );
}

function AlertSection({
  title,
  empty,
  alerts,
  onShowEvidence,
}: {
  title: string;
  empty: string;
  alerts: Alert[];
  onShowEvidence: (auditId: string) => void;
}) {
  return (
    <section className="section alert-section">
      <h2>
        {title} <span className="count">{alerts.length}</span>
      </h2>
      {alerts.length === 0 ? (
        <p className="hint">{empty}</p>
      ) : (
        alerts.map((alert) => (
          <AlertCard key={alert.id} alert={alert} onShowEvidence={onShowEvidence} />
        ))
      )}
    </section>
  );
}

function AlertCard({
  alert,
  onShowEvidence,
}: {
  alert: Alert;
  onShowEvidence: (auditId: string) => void;
}) {
  return (
    <article className={`alert-card sev-${alert.severity}`}>
      <header>
        <SeverityTag severity={alert.severity} />
        <h3>{alert.title}</h3>
        <span className="hint">
          {alert.last_seen === null
            ? "Now"
            : `${alert.count} ${alert.count === 1 ? "request" : "requests"}, the last ${formatDateTime(alert.last_seen)}`}
        </span>
      </header>
      <p>{alert.detail}</p>
      <p className="alert-action">
        <strong>What to do:</strong> {alert.action}
      </p>
      {alert.examples.length > 0 && (
        <Examples alert={alert} examples={alert.examples} onShowEvidence={onShowEvidence} />
      )}
    </article>
  );
}

function Examples({
  alert,
  examples,
  onShowEvidence,
}: {
  alert: Alert;
  examples: AlertExample[];
  onShowEvidence: (auditId: string) => void;
}) {
  return (
    <div className="table-wrap">
      <table className="examples">
        {alert.count > examples.length && (
          <caption>
            The {examples.length} most recent of {alert.count}
          </caption>
        )}
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Request</th>
            <th scope="col">What was found</th>
            <th scope="col">Rule and reason</th>
            <th scope="col">Client</th>
          </tr>
        </thead>
        <tbody>
          {examples.map((example) => (
            <tr key={`${example.audit_id}-${example.reason ?? ""}`}>
              <td className="nowrap">{formatDateTime(example.ts)}</td>
              <td>
                <button
                  type="button"
                  className="link mono"
                  title="Open this request's records in the audit log"
                  onClick={() => onShowEvidence(example.audit_id)}
                >
                  {shortHash(example.audit_id, 8)}
                </button>
              </td>
              <td>
                <Found example={example} />
              </td>
              <td>
                <RuleAndReason example={example} />
              </td>
              <td>{example.client ?? <span className="muted">not given</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Requests refused before detection ran have nothing found, and a label that says so.
const NOT_INSPECTED: Record<string, string> = {
  "builtin:policy-unavailable": "Not inspected: no valid policy",
  "builtin:invalid-request": "Not inspected: rejected",
};

function Found({ example }: { example: AlertExample }) {
  const notInspected = example.rule_id ? NOT_INSPECTED[example.rule_id] : undefined;
  if (notInspected) {
    return <span className="muted">{notInspected}</span>;
  }
  const label = example.label as Label | null;
  if (example.categories.length === 0) {
    return <span className="muted">{label ? LABEL_TEXT[label] : "–"}</span>;
  }
  return (
    <span className="chips">
      {example.categories.map((category) => (
        <span key={category} className={`chip tone-${categoryTone(category)}`}>
          {category}
        </span>
      ))}
      <span className="muted entity-types">{example.entity_types.join(", ")}</span>
    </span>
  );
}

function RuleAndReason({ example }: { example: AlertExample }) {
  // "blocked_by_policy" only repeats what the rule already says.
  const reason = example.reason === "blocked_by_policy" ? null : example.reason;
  return (
    <>
      <span className="mono">{example.rule_id ?? "–"}</span>
      {reason && <span className="mono muted reason">{reason}</span>}
    </>
  );
}

// ------------------------------------------------------------------ policy hygiene

function PolicyHygiene({ metrics }: { metrics: AlertMetrics }) {
  const notMatched = metrics.rules_not_matched;
  return (
    <section className="section">
      <h2>Policy hygiene</h2>
      <div className="hygiene">
        <div>
          <h3>Policy changes</h3>
          {metrics.policy_timeline.length === 0 ? (
            <p className="hint">No change in this period.</p>
          ) : (
            <ul className="timeline">
              {metrics.policy_timeline.map((event) => (
                <li key={event.ts} className={event.valid ? "" : "timeline-bad"}>
                  <span className="nowrap">{formatDateTime(event.ts)}</span>{" "}
                  {event.valid ? (
                    <>
                      {event.note !== null ? "Changed to" : "Loaded"} <code>{event.id}</code> v
                      {event.version}{" "}
                      <span className="muted mono">{shortHash(event.sha256 ?? "", 8)}</span>
                      {event.note !== null && <span className="reason">{event.note}</span>}
                    </>
                  ) : (
                    <>Invalid: {event.error}</>
                  )}
                </li>
              ))}
            </ul>
          )}
          <h3>Weak evidence</h3>
          <p className="hint">
            {Math.round(metrics.uncertain_share * 100)}% of judged prompts were only “uncertain”
            and kept inside.
          </p>
        </div>
        <div>
          <BarList
            title="How often each rule matched"
            data={metrics.rule_matches}
            mono
          />
          <h3>Rules that never matched</h3>
          {notMatched === null ? (
            <p className="hint">Shown once the period has at least 20 requests.</p>
          ) : notMatched.length === 0 ? (
            <p className="hint">Every rule matched at least once.</p>
          ) : (
            <p className="chips">
              {notMatched.map((rule) => (
                <code key={rule}>{rule}</code>
              ))}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

// ------------------------------------------------------------------ traffic

function Traffic({ metrics }: { metrics: AlertMetrics }) {
  const blocked = metrics.by_action.block ?? 0;
  const failClosedShare =
    metrics.requests > 0 ? Math.round((metrics.fail_closed / metrics.requests) * 100) : 0;
  return (
    <section className="section traffic">
      <h2>Traffic</h2>
      <div className="stat-tiles">
        <Stat label="Requests" value={metrics.requests} />
        <Stat label="Sent outside" value={metrics.sent_outside} tone="act-allow" />
        <Stat label="Answered inside" value={metrics.kept_inside} tone="act-route_sovereign" />
        <Stat label="Blocked" value={blocked} tone="act-block" />
        <Stat
          label="Failed closed"
          value={metrics.fail_closed}
          note={`${failClosedShare}%`}
          tone="chip-warn"
        />
      </div>
      <div className="bar-grid">
        <BarList
          title="By action"
          data={metrics.by_action}
          names={actionName}
          tone={(key) => `act-${key}`}
        />
        <BarList
          title="By outcome"
          data={metrics.by_outcome}
          names={outcomeName}
          tone={(key) => `outcome-${key}`}
        />
        <BarList
          title="By category"
          data={metrics.by_category}
          mono
          tone={(key) => `tone-${categoryTone(key)}`}
        />
        <BarList
          title="Values redacted, by type"
          data={metrics.redacted_by_entity}
          mono
          tone={() => "act-redact"}
        />
      </div>
      <div className="stat-tiles">
        <LatencyStat label="Local model answer time" stats={metrics.latency_ms.inside} />
        <LatencyStat label="External model answer time" stats={metrics.latency_ms.outside} />
      </div>
      <h3>Top clients</h3>
      {metrics.top_clients.length === 0 ? (
        <p className="hint">No requests in this period.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Client (claimed)</th>
                <th scope="col" className="num">
                  Requests
                </th>
                <th scope="col" className="num">
                  Blocked
                </th>
              </tr>
            </thead>
            <tbody>
              {metrics.top_clients.map((row) => (
                <tr key={row.client ?? "-"}>
                  <td>{row.client ?? <span className="muted">not given</span>}</td>
                  <td className="num">{row.requests}</td>
                  <td className="num">{row.blocked}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Stat({
  label,
  value,
  note,
  tone,
}: {
  label: string;
  value: string | number;
  note?: string;
  // A class that sets --tone: where these requests ended up.
  tone?: string;
}) {
  return (
    <div className={tone ? `stat ${tone}` : "stat"}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">
        {value}
        {note && <span className="stat-note"> {note}</span>}
      </span>
    </div>
  );
}

function LatencyStat({ label, stats }: { label: string; stats: LatencyStats }) {
  if (stats.count === 0 || stats.median === null || stats.p95 === null) {
    return <Stat label={label} value="–" note="no calls" />;
  }
  return (
    <Stat
      label={label}
      value={`${seconds(stats.median)} median`}
      note={`p95 ${seconds(stats.p95)}, ${stats.count} calls`}
    />
  );
}

/** One series of counts as horizontal bars, largest first, each value at its tip. */
function BarList({
  title,
  data,
  names,
  mono = false,
  tone,
}: {
  title: string;
  data: Record<string, number>;
  names?: (key: string) => string;
  mono?: boolean;
  // A class that sets --tone for one bar, so a bar has the colour of what it counts.
  tone?: (key: string) => string;
}) {
  const entries = Object.entries(data);
  const max = Math.max(1, ...entries.map(([, value]) => value));
  return (
    <figure className="bars">
      <figcaption>{title}</figcaption>
      {entries.length === 0 ? (
        <p className="hint">None in this period.</p>
      ) : (
        <ul>
          {entries.map(([key, value]) => {
            const name = names ? names(key) : key;
            return (
              <li key={key} className={tone?.(key)} title={`${name}: ${value}`}>
                <span className={mono ? "bar-name mono" : "bar-name"}>{name}</span>
                <span className="bar-track" aria-hidden="true">
                  <span className="bar" style={{ width: `${(value / max) * 100}%` }} />
                </span>
                <span className="bar-value">{value}</span>
              </li>
            );
          })}
        </ul>
      )}
    </figure>
  );
}

function actionName(key: string): string {
  return ACTION_LABELS[key as Action] ?? key;
}

function outcomeName(key: string): string {
  return OUTCOME_TEXT[key as Outcome] ?? (key === "no outcome" ? "No outcome" : key);
}

function seconds(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}
