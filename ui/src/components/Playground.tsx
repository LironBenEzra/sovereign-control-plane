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
                className={`sample ${expectTone(sample.expect)}`}
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
              <div className="empty-map">
                <div className="empty-inside">
                  <span className="empty-side">Inside your boundary</span>
                  <ol className="empty-steps">
                    {EMPTY_STEPS.map(([title, detail], index) => (
                      <li key={title}>
                        <span className="empty-n">{index + 1}</span>
                        <b>{title}</b>
                        <span>{detail}</span>
                      </li>
                    ))}
                  </ol>
                </div>
                <div className="empty-outside">
                  <span className="empty-side">Outside</span>
                  <b>External model</b>
                  <span>Gets only what the policy lets out</span>
                </div>
              </div>
            </div>
          )
        )}
      </section>
    </div>
  );
}

// The four steps every result shows, in the same order and words.
const EMPTY_STEPS: [string, string][] = [
  ["Inspect", "Find the private data"],
  ["Decide", "The first rule that matches"],
  ["Enforce", "Block, keep inside, redact or allow"],
  ["Audit", "Sign a record of every step"],
];

// A sample's colour is where its prompt should end up, as everywhere else in the interface.
function expectTone(expect: string): string {
  switch (expect) {
    case "allow":
      return "act-allow";
    case "redact":
      return "act-redact";
    case "block":
      return "act-block";
    default:
      // "sovereign" and "fail closed" both stay inside.
      return "act-route_sovereign";
  }
}
