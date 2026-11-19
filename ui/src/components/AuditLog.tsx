import { useCallback, useEffect, useState } from "react";
import { listAudit, verifyAudit } from "../api";
import { formatTime, shortHash } from "../text";
import type { AuditRecord, VerifyReport } from "../types";

interface Props {
  focusAuditId: string | null;
  onClearFocus: () => void;
}

export function AuditLog({ focusAuditId, onClearFocus }: Props) {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const [report, setReport] = useState<VerifyReport | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const page = await listAudit();
      setRecords(page.records);
      setTotal(page.total);
      setError(null);
    } catch {
      setError("The audit log could not be loaded.");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function verify() {
    setVerifying(true);
    try {
      setReport(await verifyAudit());
      await refresh();
    } catch {
      setError("Verification could not be run.");
    } finally {
      setVerifying(false);
    }
  }

  const visible = focusAuditId
    ? records.filter((record) => record.audit_id === focusAuditId)
    : records;
  // Evidence reads best in the order it happened when looking at one request.
  const ordered = focusAuditId ? [...visible].reverse() : visible;
  const shown = selected ?? (focusAuditId ? (ordered[0] ?? null) : null);

  return (
    <div className="audit">
      <section className="card">
        <div className="toolbar">
          <div>
            <h2>Audit log</h2>
            <p className="hint">
              Append-only, hash chained, and signed with Ed25519. {total} record
              {total === 1 ? "" : "s"} in total.
            </p>
          </div>
          <div className="toolbar-actions">
            <button type="button" className="secondary" onClick={() => void refresh()}>
              Refresh
            </button>
            <button
              type="button"
              className="primary"
              onClick={() => void verify()}
              disabled={verifying}
            >
              {verifying ? "Verifying…" : "Verify chain"}
            </button>
          </div>
        </div>

        {error && (
          <div className="banner banner-bad" role="alert">
            {error}
          </div>
        )}
        {report && <VerifyBanner report={report} />}

        {focusAuditId && (
          <div className="banner banner-info">
            Showing the evidence for request <code>{focusAuditId}</code>.
            <button type="button" className="link" onClick={onClearFocus}>
              Show all records
            </button>
          </div>
        )}

        <div className="table-wrap">
          <table className="records">
            <thead>
              <tr>
                <th className="num">#</th>
                <th>Time</th>
                <th>Event</th>
                <th>Summary</th>
                <th>Audit ID</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody>
              {ordered.map((record) => (
                <tr
                  key={record.seq}
                  className={shown?.seq === record.seq ? "selected" : undefined}
                  onClick={() => setSelected(record)}
                >
                  <td className="num">{record.seq}</td>
                  <td>{formatTime(record.ts)}</td>
                  <td>
                    <span className={`chip event-${record.event}`}>{record.event}</span>
                  </td>
                  <td>{summarize(record)}</td>
                  <td className="mono">{shortHash(record.audit_id, 8)}</td>
                  <td className="mono">{shortHash(record.hash)}</td>
                </tr>
              ))}
              {ordered.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No records yet. Send a prompt from the playground.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {shown && (
        <section className="card">
          <h2>
            Record #{shown.seq} <span className="muted">{shown.event}</span>
          </h2>
          <p className="hint">
            <code>hash</code> is the SHA-256 of this record's content plus <code>prev_hash</code>,
            and <code>sig</code> is the signature over that hash. No raw private value is stored,
            only keyed hashes.
          </p>
          <pre className="block json">{JSON.stringify(shown, null, 2)}</pre>
        </section>
      )}
    </div>
  );
}

function VerifyBanner({ report }: { report: VerifyReport }) {
  if (!report.ok) {
    const problems = [...report.chain_problems, ...report.replay_problems];
    return (
      <div className="banner banner-bad" role="alert">
        <strong>The log failed verification.</strong>
        <ul>
          {problems.map((problem, index) => (
            <li key={index}>
              Record {problem.seq ?? "?"}: {problem.reason}
            </li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <div className="banner banner-good" role="status">
      <strong>The log is intact.</strong> {report.records} records verified (hashes, links and
      signatures), and {report.decisions_replayed} decision
      {report.decisions_replayed === 1 ? "" : "s"} replayed from the recorded signals and policy.
      {report.head_hash && (
        <span className="mono head">
          {" "}
          Head: #{report.head_seq} {shortHash(report.head_hash, 16)}
        </span>
      )}
      {report.incomplete_requests.length > 0 && (
        <div>
          {report.incomplete_requests.length} interrupted request
          {report.incomplete_requests.length === 1 ? "" : "s"} (a decision with no outcome).
        </div>
      )}
    </div>
  );
}

function field(source: unknown, key: string): unknown {
  return typeof source === "object" && source !== null
    ? (source as Record<string, unknown>)[key]
    : undefined;
}

function summarize(record: AuditRecord): string {
  const body = record.body;
  if (record.event === "decision") {
    const decision = field(body, "decision");
    const label = field(field(body, "classification"), "label");
    return `${String(field(decision, "action"))} · ${String(field(decision, "rule_id"))} · ${String(label)}`;
  }
  if (record.event === "outcome") {
    const reason = field(body, "reason");
    const provider = field(field(body, "model"), "provider");
    return [field(body, "status"), provider, reason].filter(Boolean).map(String).join(" · ");
  }
  if (record.event === "policy_loaded") {
    return field(body, "valid")
      ? `policy ${String(field(body, "id"))} v${String(field(body, "version"))}`
      : `invalid policy: ${String(field(body, "error"))}`;
  }
  return "";
}
