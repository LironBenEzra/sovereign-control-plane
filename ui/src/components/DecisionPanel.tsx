import type { InferenceReply } from "../api";
import {
  ACTION_LABELS,
  ACTION_SUMMARIES,
  LABEL_TEXT,
  OUTCOME_TEXT,
  categoryTone,
  normalizePrompt,
  segmentText,
  shortHash,
} from "../text";
import type { Finding } from "../types";

interface Props {
  reply: InferenceReply;
  prompt: string;
  onShowEvidence: (auditId: string) => void;
}

export function DecisionPanel({ reply, prompt, onShowEvidence }: Props) {
  const { result, httpStatus } = reply;
  const { decision, classification, policy, model, receipts } = result;
  const inspected = normalizePrompt(prompt);
  const counted = classification.findings.filter((finding) => finding.counted);
  const ignored = classification.findings.length - counted.length;

  return (
    <div className="decision">
      <header className={`card verdict action-${decision.action}`}>
        <div className="verdict-main">
          <span className="verdict-label">Decision</span>
          <span className="verdict-action">{ACTION_LABELS[decision.action]}</span>
          <span className="verdict-summary">{ACTION_SUMMARIES[decision.action]}</span>
        </div>
        <div className="chips">
          <span className={`chip outcome-${result.outcome}`}>{OUTCOME_TEXT[result.outcome]}</span>
          {decision.fail_closed && <span className="chip chip-warn">Fail closed</span>}
          {httpStatus !== 200 && <span className="chip">HTTP {httpStatus}</span>}
        </div>
      </header>

      <Step number={1} title="Inspect" subtitle={LABEL_TEXT[classification.label]}>
        <p>{classification.rationale}</p>
        {classification.label !== "invalid_input" && (
          <>
            <div className="field-label">Prompt as inspected</div>
            <HighlightedText text={inspected} findings={classification.findings} />
          </>
        )}
        {counted.length > 0 && <FindingsTable text={inspected} findings={counted} />}
        {ignored > 0 && (
          <p className="hint">
            {ignored} weaker signal{ignored === 1 ? " was" : "s were"} below the policy's minimum
            score and ignored.
          </p>
        )}
      </Step>

      <Step number={2} title="Decide" subtitle={`Rule: ${decision.rule_id}`}>
        <p>{decision.rationale}</p>
        {policy ? (
          <dl className="facts">
            <dt>Policy</dt>
            <dd>
              {policy.id} <span className="muted">v{policy.version}</span>
            </dd>
            <dt>Policy SHA-256</dt>
            <dd className="mono" title={policy.sha256}>
              {shortHash(policy.sha256, 16)}
            </dd>
          </dl>
        ) : (
          <p className="hint">No policy was consulted for this decision.</p>
        )}
      </Step>

      <Step number={3} title="Enforce" subtitle={OUTCOME_TEXT[result.outcome]}>
        {result.outcome_reason && (
          <p>
            Reason: <code>{result.outcome_reason}</code>
          </p>
        )}
        {model ? (
          <dl className="facts">
            <dt>Model</dt>
            <dd>
              {model.provider} <span className="muted">{model.model}</span>
            </dd>
            <dt>Location</dt>
            <dd>
              <span className={`chip ${model.in_boundary ? "chip-inside" : "chip-outside"}`}>
                {model.in_boundary ? "Inside the trust boundary" : "External"}
              </span>
              {model.stub && (
                <span className="chip chip-warn" title="No real model was called">
                  Stub
                </span>
              )}
            </dd>
          </dl>
        ) : (
          <p className="hint">No model was called.</p>
        )}
        {result.forwarded_prompt !== null && (
          <>
            <div className="field-label">
              Exactly what the model received
              {model && !model.in_boundary && " (this is what left the boundary)"}
            </div>
            <pre className="block">{result.forwarded_prompt}</pre>
          </>
        )}
        {result.response !== null && (
          <>
            <div className="field-label">Response returned to the caller</div>
            <pre className="block block-response">{result.response}</pre>
          </>
        )}
      </Step>

      <Step number={4} title="Audit" subtitle="Two signed records">
        <dl className="facts">
          <dt>Audit ID</dt>
          <dd className="mono">{result.audit_id}</dd>
          <dt>Decision record</dt>
          <dd className="mono" title={receipts.decision.hash}>
            #{receipts.decision.seq} · {shortHash(receipts.decision.hash, 16)}
          </dd>
          <dt>Outcome record</dt>
          <dd className="mono" title={receipts.outcome.hash}>
            #{receipts.outcome.seq} · {shortHash(receipts.outcome.hash, 16)}
          </dd>
          <dt>Signing key</dt>
          <dd className="mono">{receipts.outcome.key_id}</dd>
        </dl>
        <p className="hint">
          The decision record was written before any model was called. These hashes are your
          receipt: if a record is later changed or removed, it will no longer match.
        </p>
        <button type="button" className="link" onClick={() => onShowEvidence(result.audit_id)}>
          Open the evidence for this request →
        </button>
      </Step>
    </div>
  );
}

function Step(props: {
  number: number;
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <section className="card step">
      <header className="step-head">
        <span className="step-number">{props.number}</span>
        <h3>{props.title}</h3>
        <span className="step-subtitle">{props.subtitle}</span>
      </header>
      <div className="step-body">{props.children}</div>
    </section>
  );
}

function describe(findings: Finding[]): string {
  return findings
    .map((f) => `${f.entity_type} · score ${f.score} · ${f.recognizer} (${f.detector})`)
    .join("\n");
}

function HighlightedText({ text, findings }: { text: string; findings: Finding[] }) {
  return (
    <pre className="block inspected">
      {segmentText(text, findings).map((segment, index) => {
        const strongest = segment.findings.reduce<Finding | null>(
          (best, f) => (best === null || f.score > best.score ? f : best),
          null,
        );
        if (strongest === null) return <span key={index}>{segment.text}</span>;
        return (
          <mark
            key={index}
            className={`tone-${categoryTone(strongest.category)}`}
            title={describe(segment.findings)}
          >
            {segment.text}
            <span className="mark-tag">{strongest.entity_type}</span>
          </mark>
        );
      })}
    </pre>
  );
}

function FindingsTable({ text, findings }: { text: string; findings: Finding[] }) {
  const chars = Array.from(text);
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Found</th>
            <th>Type</th>
            <th>Category</th>
            <th className="num">Score</th>
            <th>Recognizer</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={index}>
              <td className="mono found">{chars.slice(finding.start, finding.end).join("")}</td>
              <td>{finding.entity_type}</td>
              <td>
                <span className={`chip tone-${categoryTone(finding.category)}`}>
                  {finding.category ?? "unmapped"}
                </span>
              </td>
              <td className="num">{finding.score.toFixed(2)}</td>
              <td className="muted">
                {finding.recognizer} <span className="detector">({finding.detector})</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
