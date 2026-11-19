import { useEffect, useState } from "react";
import { getHealth } from "./api";
import { AuditLog } from "./components/AuditLog";
import { Playground } from "./components/Playground";
import { PolicyView } from "./components/PolicyView";
import type { Health, ModelStatus } from "./types";

type Tab = "playground" | "audit" | "policy";

const TABS: { id: Tab; label: string }[] = [
  { id: "playground", label: "Playground" },
  { id: "audit", label: "Audit log" },
  { id: "policy", label: "Policy" },
];

const HEALTH_POLL_MS = 15_000;

export function App() {
  const [tab, setTab] = useState<Tab>("playground");
  const [focusAuditId, setFocusAuditId] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [reachable, setReachable] = useState(true);

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

  function showEvidence(auditId: string) {
    setFocusAuditId(auditId);
    setTab("audit");
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <div>
            <h1>Sovereign Control Plane</h1>
            <p>Private-data policy enforcement in front of AI models</p>
          </div>
        </div>
        <div className="status">
          {!reachable && <span className="chip outcome-failed">Control plane unreachable</span>}
          {health && (
            <>
              <ModelChip label="Sovereign model" model={health.sovereign_model} />
              <ModelChip label="External model" model={health.external_model} />
            </>
          )}
        </div>
      </header>

      <nav className="tabs" aria-label="Views">
        {TABS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={tab === item.id ? "tab active" : "tab"}
            aria-current={tab === item.id ? "page" : undefined}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      {/* The playground stays mounted so its last result survives a visit to the audit tab. */}
      <main>
        <div hidden={tab !== "playground"}>
          <Playground onShowEvidence={showEvidence} />
        </div>
        {tab === "audit" && (
          <AuditLog
            key={focusAuditId ?? "all"}
            focusAuditId={focusAuditId}
            onClearFocus={() => setFocusAuditId(null)}
          />
        )}
        {tab === "policy" && <PolicyView />}
      </main>
    </div>
  );
}

function ModelChip({ label, model }: { label: string; model: ModelStatus }) {
  const state = model.stub ? "stub" : model.ready ? "ready" : "down";
  return (
    <span className={`status-chip status-${state}`} title={model.detail}>
      <span className="dot" aria-hidden="true" />
      <span className="status-label">{label}</span>
      <span className="status-value">
        {model.provider}
        {model.stub ? " (stub)" : model.ready ? "" : " (not ready)"}
      </span>
    </span>
  );
}
