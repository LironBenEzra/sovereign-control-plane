import { useEffect, useState } from "react";
import { getAlerts, getHealth } from "./api";
import { Alerts } from "./components/Alerts";
import { AuditLog } from "./components/AuditLog";
import { Playground } from "./components/Playground";
import { PolicyView } from "./components/PolicyView";
import type { AlertsReport, Health, ModelStatus } from "./types";

type Tab = "playground" | "alerts" | "audit" | "policy";

const TABS: { id: Tab; label: string }[] = [
  { id: "playground", label: "Playground" },
  { id: "alerts", label: "Alerts" },
  { id: "audit", label: "Audit log" },
  { id: "policy", label: "Policy" },
];

const HEALTH_POLL_MS = 15_000;
// For the badge on the Alerts tab: what needs attention in the last 24 hours.
const ALERTS_POLL_MS = 30_000;

export function App() {
  const [tab, setTab] = useState<Tab>("playground");
  const [auditQuery, setAuditQuery] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [reachable, setReachable] = useState(true);
  const [alerts, setAlerts] = useState<AlertsReport | null>(null);

  useEffect(() => {
    let cancelled = false;
    const poll = () =>
      getHealth()
        .then((next) => {
          if (cancelled) return;
          setHealth(next);
          setReachable(true);
        })
        .catch(() => {
          if (!cancelled) setReachable(false);
        });
    void poll();
    const timer = window.setInterval(poll, HEALTH_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const poll = () =>
      getAlerts(24)
        .then((next) => {
          if (!cancelled) setAlerts(next);
        })
        .catch(() => {
          // The header already says when the control plane is unreachable.
        });
    void poll();
    const timer = window.setInterval(poll, ALERTS_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const needAttention = alerts?.alerts.filter((a) => a.severity !== "info").length ?? 0;

  // The window scroll is shared by every tab, so a new tab would otherwise open part way down.
  function openTab(next: Tab) {
    setTab(next);
    window.scrollTo({ top: 0 });
  }

  function showEvidence(auditId: string) {
    setAuditQuery(auditId);
    openTab("audit");
  }

  return (
    <>
      {/* The header and the tab bar span the window; the pages under them stay centred. */}
      <header className="masthead">
        <div className="topbar">
          <div className="brand">
            <span className="brand-mark" aria-hidden="true" />
            <div>
              <h1>Sovereign Control Plane</h1>
              <p>Private-data policy enforcement in front of AI models</p>
            </div>
          </div>
          <div className="status" aria-label="System status">
            {!reachable && <span className="status-alert">Control plane unreachable</span>}
            {reachable && health && !health.policy.valid && (
              <span
                className="status-alert"
                title={`${health.policy.error ?? "The policy file is missing or invalid"}. Every request is blocked until a valid policy is restored on the Policy tab.`}
              >
                Policy invalid
              </span>
            )}
            {reachable && health && Object.keys(health.failing_detectors).length > 0 && (
              <span
                className="status-alert"
                title={`Failing: ${Object.keys(health.failing_detectors).join(", ")}. Every prompt is treated as private and answers are withheld until it is fixed.`}
              >
                Detection unavailable
              </span>
            )}
            {health && (
              <>
                <ModelChip label="Sovereign model" side="inside" model={health.sovereign_model} />
                <ModelChip label="External model" side="outside" model={health.external_model} />
              </>
            )}
          </div>
        </div>
      </header>

      <nav className="tabs" aria-label="Views">
        <div className="tabs-inner">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              className={tab === item.id ? "tab active" : "tab"}
              aria-current={tab === item.id ? "page" : undefined}
              onClick={() => openTab(item.id)}
            >
              {item.label}
              {item.id === "alerts" && needAttention > 0 && alerts && (
                <span
                  className={`tab-badge sev-${alerts.status}`}
                  aria-label={`${needAttention} need attention`}
                >
                  {needAttention}
                </span>
              )}
            </button>
          ))}
        </div>
      </nav>

      {/* The playground stays mounted so its last result survives a visit to the audit tab. */}
      <main className="app">
        <div hidden={tab !== "playground"}>
          <Playground onShowEvidence={showEvidence} />
        </div>
        {tab === "alerts" && <Alerts onShowEvidence={showEvidence} />}
        {tab === "audit" && <AuditLog query={auditQuery} onQueryChange={setAuditQuery} />}
        {tab === "policy" && (
          <PolicyView
            onOpenAuditLog={() => {
              setAuditQuery(null);
              openTab("audit");
            }}
          />
        )}
      </main>
    </>
  );
}

function ModelChip({
  label,
  side,
  model,
}: {
  label: string;
  // Which side of the boundary the model is on, for its colour.
  side: "inside" | "outside";
  model: ModelStatus;
}) {
  const state = model.stub ? "stub" : model.ready ? "ready" : "down";
  return (
    <span className={`status-item status-${side} status-${state}`} title={model.detail}>
      <span className="dot" aria-hidden="true" />
      <span className="status-label">{label}</span>
      <span className="status-value">
        {model.stub ? "stub" : model.ready ? model.model : "not ready"}
      </span>
    </span>
  );
}
