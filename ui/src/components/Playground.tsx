import { useState } from "react";
import { ApiError, infer, type InferenceReply } from "../api";
import { SAMPLES } from "../samples";
import { DecisionPanel } from "./DecisionPanel";

interface Props {
  onShowEvidence: (auditId: string) => void;
}

export function Playground({ onShowEvidence }: Props) {
  const [prompt, setPrompt] = useState(SAMPLES[1]?.prompt ?? "");
  const [sentPrompt, setSentPrompt] = useState("");
  const [reply, setReply] = useState<InferenceReply | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function send() {
    if (!prompt.trim() || busy) return;
    setBusy(true);
    setError(null);
    setReply(null);
    try {
      const next = await infer(prompt);
      setSentPrompt(prompt);
      setReply(next);
    } catch (caught) {
      setReply(null);
      setError(
        caught instanceof ApiError
          ? caught.message
          : "The control plane could not be reached. Is it running?",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="playground">
      <section className="sheet request">
        <label className="sheet-title" htmlFor="prompt">
          Prompt
        </label>
        <p className="hint">
          Sent to <code>POST /v1/inference</code>, like any client's request. Ctrl+Enter sends
          it.
        </p>
        <textarea
          id="prompt"
          value={prompt}
          rows={7}
          spellCheck={false}
          onChange={(event) => setPrompt(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) void send();
          }}
        />
        <div className="samples">
          <span className="field-label">Samples, with the decision each should get</span>
          <div className="sample-list">
            {SAMPLES.map((sample) => (
              <button
                key={sample.label}
                type="button"
                className="sample"
                onClick={() => setPrompt(sample.prompt)}
              >
                {sample.label}
                <span className="sample-expect">{sample.expect}</span>
              </button>
            ))}
          </div>
        </div>
        <button
          type="button"
          className="primary"
          onClick={() => void send()}
          disabled={busy || !prompt.trim()}
        >
          {busy ? "Sending…" : "Send through the control plane"}
        </button>
      </section>

      <section className="result">
        {error && (
          <div className="banner banner-bad" role="alert">
            <strong>No answer was returned.</strong> {error}
          </div>
        )}
        {busy && (
          <div className="sheet working" role="status">
            <span className="spinner" aria-hidden="true" />
            Inspecting, deciding and enforcing. The sovereign model runs on CPU, so an answer
            from it can take several seconds.
          </div>
        )}
        {reply ? (
          <DecisionPanel reply={reply} prompt={sentPrompt} onShowEvidence={onShowEvidence} />
        ) : (
          !error &&
          !busy && (
            <div className="empty">
              <h2>Send a prompt to see what happens to it</h2>
              <p>
                The result shows what was found in it, which policy rule decided, what crossed the
                trust boundary and what stayed inside, and the signed records it left.
              </p>
            </div>
          )
        )}
      </section>
    </div>
  );
}
