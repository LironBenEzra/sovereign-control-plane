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
import type { Finding, InferenceResult } from "../types";

interface Props {
  reply: InferenceReply;
  prompt: string;
  onShowEvidence: (auditId: string) => void;
}

export function DecisionPanel({ reply, prompt, onShowEvidence }: Props) {
  const { result, httpStatus } = reply;
  const { decision, classification, policy, receipts } = result;
  const inspected = normalizePrompt(prompt);
  const counted = classification.findings.filter((finding) => finding.counted);
  const ignored = classification.findings.length - counted.length;

  return (
    <article className={`result-sheet action-${decision.action}`}>
      <header className="verdict">
        <div className="verdict-main">
          <h2 className="verdict-action">{ACTION_LABELS[decision.action]}</h2>
          <p className="verdict-summary">{ACTION_SUMMARIES[decision.action]}</p>
        </div>
        <div className="chips">
          <span className={`chip outcome-${result.outcome}`}>{OUTCOME_TEXT[result.outcome]}</span>
          {decision.fail_closed && <span className="chip chip-warn">Failed closed</span>}
          {httpStatus !== 200 && <span className="chip">HTTP {httpStatus}</span>}
        </div>
      </header>

      <Step number={1} title="Inspect" subtitle={LABEL_TEXT[classification.label]}>
        <p>{classification.rationale}</p>
        {classification.label !== "invalid_input" && (
          <>
            <div className="field-label">The prompt as inspected</div>
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

      <Step number={2} title="Decide" subtitle={`Rule ${decision.rule_id}`}>
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
        <Boundary result={result} />
      </Step>

      <Step number={4} title="Audit" subtitle="Signed receipts">
        <dl className="facts">
          <dt>Audit ID</dt>
          <dd className="mono">{result.audit_id}</dd>
          <dt>Decision record</dt>
          <dd>
            <span className="mono">#{receipts.decision.seq}</span>{" "}
            <span className="mono muted" title={receipts.decision.hash}>
              {shortHash(receipts.decision.hash, 16)}
            </span>
          </dd>
          <dt>Outcome record</dt>
          <dd>
            <span className="mono">#{receipts.outcome.seq}</span>{" "}
            <span className="mono muted" title={receipts.outcome.hash}>
              {shortHash(receipts.outcome.hash, 16)}
            </span>
          </dd>
          <dt>Signing key</dt>
          <dd className="mono">{receipts.outcome.key_id}</dd>
        </dl>
        <p className="hint">
          The decision record was written before any model was called. These hashes are your
          receipt: if a record is later changed or removed, it will no longer match.
        </p>
        <button type="button" className="link" onClick={() => onShowEvidence(result.audit_id)}>
          Open the evidence for this request
        </button>
      </Step>
    </article>
  );
}

/**
 * Where the prompt went, drawn on either side of the trust boundary. The left side never
 * leaves the boundary; the right side is exactly what crossed it, if anything did.
 */
function Boundary({ result }: { result: InferenceResult }) {
  const { model } = result;
  const external = model !== null && !model.in_boundary;
  const restored = result.model_reply !== null && result.model_reply !== result.response;
  const sentOutside = external && result.forwarded_prompt !== null;
  return (
    <div className="boundary">
      <section className="boundary-side boundary-inside" aria-label="Inside your boundary">
        <h4>Inside your boundary</h4>
        {model === null && <p className="hint">No model was called.</p>}
        {model?.in_boundary && result.forwarded_prompt !== null && (
          <Passage label={`Sent to ${model.provider}, ${model.model}`}>
            {result.forwarded_prompt}
          </Passage>
        )}
        {result.response !== null && (
          <Passage
            label={restored ? "Returned to you, with the original values put back" : "Returned to you"}
            prose
          >
            {result.response}
          </Passage>
        )}
      </section>
      <section className="boundary-side boundary-outside" aria-label="Outside">
        <h4>Outside</h4>
        {sentOutside && model ? (
          <>
            <Passage label={`Sent to ${model.provider}${model.stub ? ", a stub" : ""}`}>
              {result.forwarded_prompt}
            </Passage>
            {result.model_reply !== null ? (
              <Passage label="The reply that came back">{result.model_reply}</Passage>
            ) : (
              <p className="hint">No answer came back.</p>
            )}
          </>
        ) : (
          <p className="nothing-crossed">Nothing crossed the boundary.</p>
        )}
      </section>
    </div>
  );
}

function Passage(props: { label: string; prose?: boolean; children: React.ReactNode }) {
  return (
    <div className="passage">
      <div className="field-label">{props.label}</div>
      <pre className={props.prose ? "block block-response" : "block"}>{props.children}</pre>
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
    <section className="step">
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
    .map((f) => `${f.entity_type}, score ${f.score}, ${f.recognizer} (${f.detector})`)
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

// A semantic finding covers a whole passage; the table shows its start, the highlight above
// shows all of it.
const FOUND_CHARS = 48;

function FoundCell({ value }: { value: string }) {
  const chars = Array.from(value);
  const shown = chars.length > FOUND_CHARS ? `${chars.slice(0, FOUND_CHARS).join("")}…` : value;
  return (
    <td className="mono found" title={value}>
      {shown}
    </td>
  );
}

function FindingsTable({ text, findings }: { text: string; findings: Finding[] }) {
  const chars = Array.from(text);
  return (
    <div className="table-wrap">
      <table className="findings">
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
              <FoundCell value={chars.slice(finding.start, finding.end).join("")} />
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
