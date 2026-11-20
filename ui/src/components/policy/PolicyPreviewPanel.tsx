import { type ReactNode, useEffect, useState } from "react";
import { ApiError, previewPolicy } from "../../api";
import { SAMPLES } from "../../samples";
import { ACTION_LABELS, LABEL_TEXT } from "../../text";
import type { PolicyDocument, PolicyPreview, PolicyVerdict } from "../../types";

interface Row {
  label: string;
  prompt: string;
  result?: PolicyPreview;
  error?: string;
}

interface Props {
  draft: PolicyDocument;
  token: string;
  tokenField: ReactNode;
  onTokenRejected: () => void;
  onTokenAccepted: () => void;
}

const sampleRows = (): Row[] => SAMPLES.map(({ label, prompt }) => ({ label, prompt }));

export function PolicyPreviewPanel({
  draft,
  token,
  tokenField,
  onTokenRejected,
  onTokenAccepted,
}: Props) {
  const [rows, setRows] = useState<Row[]>(sampleRows);
  const [custom, setCustom] = useState("");
  const [running, setRunning] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Results describe the draft they were run on. An edit makes them stale, so they go.
  useEffect(() => {
    setRows((current) => current.map(({ label, prompt }) => ({ label, prompt })));
  }, [draft]);

  async function run() {
    setError(null);
    setRows((current) => current.map(({ label, prompt }) => ({ label, prompt })));
    // One request per prompt, in turn, so results appear as they come and a slow local
    // model does not hold one long request open.
    for (const [index, row] of rows.entries()) {
      setRunning(index);
      try {
        const result = await previewPolicy(draft, row.prompt, token);
        onTokenAccepted();
        setRows((current) => current.map((r, i) => (i === index ? { ...r, result } : r)));
      } catch (caught) {
        if (caught instanceof ApiError && caught.status === 401) {
          onTokenRejected();
          setError("The admin token was not accepted.");
          break;
        }
        const message = caught instanceof Error ? caught.message : "The preview failed.";
        setRows((current) => current.map((r, i) => (i === index ? { ...r, error: message } : r)));
      }
    }
    setRunning(null);
  }

  const done = rows.filter((row) => row.result).length;
  const changed = rows.filter((row) => row.result?.changed).length;

  return (
    <section className="sheet policy-panel" aria-labelledby="preview-title">
      <h2 id="preview-title">Try the draft</h2>
      <p className="hint">
        Each prompt goes through the detectors and is decided under the policy in force and under
        your draft. No model is called, nothing is sent anywhere, and nothing is recorded. On the
        hosted demo the local model judges each prompt, which takes a few seconds.
      </p>

      <div className="table-wrap">
        <table className="preview-table">
          <thead>
            <tr>
              <th>Prompt</th>
              <th>Policy in force</th>
              <th>Your draft</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index} className={row.result?.changed ? "preview-changed" : undefined}>
                <td className="preview-prompt">
                  <strong>{row.label}</strong>
                  <span className="hint">{row.prompt}</span>
                </td>
                {row.result ? (
                  <>
                    <td>
                      <VerdictCell verdict={row.result.current} />
                    </td>
                    <td>
                      <VerdictCell verdict={row.result.draft} />
                      {row.result.changed && <span className="chip chip-warn">Changes</span>}
                    </td>
                  </>
                ) : (
                  <td colSpan={2} className="hint">
                    {running === index ? (
                      <span className="working">
                        <span className="spinner" aria-hidden="true" /> Checking…
                      </span>
                    ) : (
                      (row.error ?? "Not run yet")
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <form
        className="add-prompt"
        onSubmit={(event) => {
          event.preventDefault();
          const prompt = custom.trim();
          if (!prompt) return;
          setRows((current) => [...current, { label: "Your prompt", prompt }]);
          setCustom("");
        }}
      >
        <label className="field">
          <span className="field-label">Add a prompt of your own</span>
          <input
            value={custom}
            maxLength={2000}
            onChange={(event) => setCustom(event.target.value)}
            placeholder="Type a prompt to test the draft on"
          />
        </label>
        <button type="submit" className="secondary" disabled={custom.trim() === ""}>
          Add
        </button>
      </form>

      {tokenField}
      {error && (
        <div className="banner banner-bad" role="alert">
          {error}
        </div>
      )}
      <div className="panel-actions">
        <p className="hint" role="status">
          {running !== null
            ? `Checking ${running + 1} of ${rows.length}…`
            : done > 0
              ? `${changed} of ${done} decision${done === 1 ? "" : "s"} would change.`
              : ""}
        </p>
        <button
          type="button"
          className="primary"
          disabled={running !== null || token === ""}
          onClick={() => void run()}
        >
          {done > 0 ? "Run again" : "Run"}
        </button>
      </div>
    </section>
  );
}

function VerdictCell({ verdict }: { verdict: PolicyVerdict | null }) {
  if (!verdict) return <span className="hint">No valid policy in force</span>;
  return (
    <div className="verdict-cell">
      <span className={`chip act-${verdict.action}`}>{ACTION_LABELS[verdict.action]}</span>
      <code>{verdict.rule_id}</code>
      <span className="hint">
        {LABEL_TEXT[verdict.label]}
        {verdict.findings.length > 0 && `: ${verdict.findings.join(", ")}`}
      </span>
    </div>
  );
}
