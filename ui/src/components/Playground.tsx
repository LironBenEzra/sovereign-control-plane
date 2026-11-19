import { useState } from "react";
import { ApiError, infer, type InferenceReply } from "../api";
import { DecisionPanel } from "./DecisionPanel";

interface Sample {
  label: string;
  expect: string;
  prompt: string;
}

const SAMPLES: Sample[] = [
  {
    label: "No private data",
    expect: "allow",
    prompt: "Explain what a hash chain is in two sentences.",
  },
  {
    label: "Contact PII",
    expect: "redact",
    prompt:
      "Write a short, friendly reply to Dana Levi at dana.levi@example.com confirming Tuesday's meeting.",
  },
  {
    label: "Government ID",
    expect: "sovereign",
    prompt:
      "My social security number is 536-90-4399. In one sentence, what is a W-2 form?",
  },
  {
    label: "Secret",
    expect: "block",
    prompt: "Why does this fail? AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
  },
  {
    label: "Weak signal",
    expect: "fail closed",
    prompt: "Call me on 212-555-0123 tomorrow.",
  },
];

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
      <section className="card request">
        <h2>Request</h2>
        <p className="hint">
          The prompt goes to <code>POST /v1/inference</code>. The control plane inspects it,
          applies the policy, enforces the decision and records evidence.
        </p>
        <label className="field-label" htmlFor="prompt">
          Prompt
        </label>
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
          <span className="field-label">Try a sample</span>
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
          {busy ? "Working…" : "Send through the control plane"}
        </button>
      </section>

      <section className="result">
        {error && (
          <div className="banner banner-bad" role="alert">
            <strong>No answer was returned.</strong> {error}
          </div>
        )}
        {busy && (
          <div className="card working" role="status">
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
            <div className="card empty">
              <h2>What you will see</h2>
              <ol className="steps-preview">
                <li>
                  <strong>Inspect</strong> which spans of the prompt are private data, and why.
                </li>
                <li>
                  <strong>Decide</strong> which policy rule matched and what it requires.
                </li>
                <li>
                  <strong>Enforce</strong> which model was called and exactly what it received.
                </li>
                <li>
                  <strong>Audit</strong> the signed, hash-chained evidence for this request.
                </li>
              </ol>
            </div>
          )
        )}
      </section>
    </div>
  );
}
