import { useEffect, useRef, useState } from "react";
import { ApiError, previewPolicy } from "../../api";
import { SAMPLES } from "../../samples";
import { ACTION_LABELS, LABEL_TEXT } from "../../text";
import type { PolicyDocument, PolicyPreview, PolicyVerdict } from "../../types";

interface Row {
  label: string;
  prompt: string;
  result?: PolicyPreview;
  error?: string;
  // The result is for an earlier version of the draft and is being replaced.
  stale?: boolean;
}

const sampleRows = (): Row[] => SAMPLES.map(({ label, prompt }) => ({ label, prompt }));

// Wait this long after the last edit before deciding again.
const EDIT_PAUSE_MS = 400;

/**
 * Tries a draft on prompts, next to the policy in force. Needs no admin token: it changes
 * nothing. It starts as soon as it opens and runs again after every edit; the server
 * reuses detection for prompts it has seen, so a run after an edit only re-decides.
 */
export function PolicyPreviewPanel({ draft }: { draft: PolicyDocument }) {
  const [rows, setRows] = useState<Row[]>(sampleRows);
  const [custom, setCustom] = useState("");
  const [running, setRunning] = useState<number | null>(null);
  const [invalid, setInvalid] = useState(false);
  const rowsRef = useRef(rows);
  rowsRef.current = rows;
  const draftRef = useRef(draft);
  draftRef.current = draft;
  // Each run has a number. Starting a run stops any older one, so results from an older
  // draft never land in the table.
  const runId = useRef(0);

  async function run() {
    const id = ++runId.current;
    const target = draftRef.current;
    const list = rowsRef.current;
    setInvalid(false);
    // One request per prompt, in turn, so results appear as they come and a slow local
    // model does not hold one long request open.
    for (const [index, row] of list.entries()) {
      if (runId.current !== id) return;
      setRunning(index);
      let update: Partial<Row>;
      try {
        update = { result: await previewPolicy(target, row.prompt), error: undefined };
      } catch (caught) {
        // An invalid draft fails the same way for every prompt: say it once and stop.
        if (caught instanceof ApiError && caught.status === 422) {
          if (runId.current === id) {
            setInvalid(true);
            setRunning(null);
          }
          return;
        }
        update = {
          result: undefined,
          error: caught instanceof Error ? caught.message : "The preview failed.",
        };
      }
      if (runId.current !== id) return;
      setRows((current) =>
        current.map((r, i) => (i === index ? { ...r, ...update, stale: false } : r)),
      );
    }
    setRunning(null);
  }

  // Starts when the panel opens, and again shortly after each edit. Results already shown
  // stay, dimmed, until the new ones replace them.
  useEffect(() => {
    setRows((current) =>
      current.map((r) => (r.result || r.error ? { ...r, stale: true } : r)),
    );
    const timer = window.setTimeout(() => void run(), EDIT_PAUSE_MS);
    return () => window.clearTimeout(timer);
  }, [draft]);

  // Leaving the panel stops a run in progress.
  useEffect(
    () => () => {
      runId.current += 1;
    },
    [],
  );

  function addPrompt(prompt: string) {
    // Your own prompt goes first, so it is checked first.
    const next: Row[] = [{ label: "Your prompt", prompt }, ...rowsRef.current];
    rowsRef.current = next;
    setRows(next);
    void run();
  }

  const done = rows.filter((row) => row.result && !row.stale).length;
  const changed = rows.filter((row) => row.result?.changed && !row.stale).length;

  return (
    <section className="sheet policy-panel" aria-labelledby="preview-title">
      <h2 id="preview-title">Try the draft</h2>
      <p className="hint">
        Each prompt goes through the detectors and is decided under the policy in force and under
        your draft. No model is called, nothing is sent anywhere, and nothing is recorded. The
        first check of a prompt takes a few seconds on the hosted demo, where the local model
        judges it; after that, each edit updates the table in a moment.
      </p>

      <form
        className="add-prompt"
        onSubmit={(event) => {
          event.preventDefault();
          const prompt = custom.trim();
          if (!prompt) return;
          setCustom("");
          addPrompt(prompt);
        }}
      >
        <label className="field">
          <span className="field-label">Try a prompt of your own</span>
          <input
            value={custom}
            maxLength={2000}
            onChange={(event) => setCustom(event.target.value)}
            placeholder="Type a prompt to test the draft on"
          />
        </label>
        <button type="submit" className="secondary" disabled={custom.trim() === ""}>
          Check
        </button>
      </form>

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
              <tr
                key={`${index}-${row.prompt}`}
                className={
                  [
                    row.result?.changed && !row.stale ? "preview-changed" : "",
                    row.stale ? "preview-stale" : "",
                  ]
                    .filter(Boolean)
                    .join(" ") || undefined
                }
              >
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
                      (row.error ?? "Waiting…")
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {invalid && (
        <div className="banner banner-bad" role="alert">
          The draft is not valid yet. Fix what the form points out, and the table updates.
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
          className="secondary"
          disabled={running !== null}
          onClick={() => void run()}
        >
          Run again
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
