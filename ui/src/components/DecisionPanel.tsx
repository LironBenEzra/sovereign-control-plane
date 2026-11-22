import { Fragment } from "react";
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
        <Boundary result={result} inspected={inspected} />
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

type Side = "inside" | "outside";

interface FlowStep {
  side: Side;
  title: string;
  body: React.ReactNode;
}

/**
 * What happened to the prompt, step by step, drawn on either side of the trust boundary:
 * each step sits on the side where it happened, so the order shows the prompt crossing
 * the line and coming back. The left side never leaves the boundary; the right side is
 * exactly what crossed it, if anything did.
 */
function Boundary({ result, inspected }: { result: InferenceResult; inspected: string }) {
  const steps = flowSteps(result, inspected);
  const crossed = steps.some((step) => step.side === "outside");
  return (
    <div className="boundary">
      <h4 className="boundary-head boundary-inside">Inside your boundary</h4>
      <h4 className="boundary-head boundary-outside">Outside</h4>
      {steps.map((step, index) => {
        const number = `3.${index + 1}`;
        const last = index === steps.length - 1 ? " boundary-last" : "";
        const card = <FlowCard number={number} step={step} />;
        return (
          <Fragment key={number}>
            <div className={`boundary-cell boundary-inside${last}`}>
              {step.side === "inside" && card}
            </div>
            <div className={`boundary-cell boundary-outside${last}`}>
              {step.side === "outside" && card}
              {!crossed && index === 0 && (
                <p className="nothing-crossed">Nothing crossed the boundary.</p>
              )}
            </div>
          </Fragment>
        );
      })}
    </div>
  );
}

function flowSteps(result: InferenceResult, inspected: string): FlowStep[] {
  const { model, forwarded_prompt: sent, model_reply: reply, response } = result;
  if (model === null || sent === null) {
    // A model without a forwarded prompt is the sovereign model failing: it was called, and
    // the outcome reason above says why it did not answer.
    const steps: FlowStep[] = [
      model === null
        ? { side: "inside", title: "No model was called", body: null }
        : {
            side: model.in_boundary ? "inside" : "outside",
            title: `${modelName(model)} was called and did not answer`,
            body: null,
          },
    ];
    // What the caller gets instead of an answer: the policy's block message, or why none came.
    if (response !== null) {
      steps.push({
        side: "inside",
        title: "Returned to you",
        body: <pre className="block block-response">{response}</pre>,
      });
    }
    return steps;
  }

  const steps: FlowStep[] = [];
  const side: Side = model.in_boundary ? "inside" : "outside";
  const masked = side === "outside" ? swaps(sent, inspected) : null;
  if (masked && masked.some((part) => part.placeholder)) {
    steps.push({
      side: "inside",
      title: "Private values replaced with placeholders",
      body: <SwapTable parts={masked} />,
    });
  }

  steps.push({ side, title: `Sent to ${modelName(model)}`, body: <Placeholders text={sent} /> });

  if (result.outcome === "withheld") {
    // The server does not return a withheld answer, so there is no text to show.
    steps.push({
      side: "inside",
      title: "An answer came back, but scanning it failed, so it was withheld",
      body: null,
    });
  } else if (side === "outside") {
    steps.push(
      reply === null
        ? { side, title: "No answer came back", body: null }
        : { side, title: "The reply that came back", body: <Placeholders text={reply} /> },
    );
  }

  if (response !== null) {
    const restored = reply !== null && reply !== response ? swaps(reply, response) : null;
    const putBack = restored?.some((part) => part.placeholder) ?? false;
    steps.push({
      side: "inside",
      title: putBack ? "Original values put back, then returned to you" : "Returned to you",
      body: (
        <pre className="block block-response">
          {putBack && restored ? <Restored parts={restored} /> : response}
        </pre>
      ),
    });
  }
  return steps;
}

function modelName(model: NonNullable<InferenceResult["model"]>): string {
  return model.stub ? `${model.provider}, a stub` : `${model.provider}, ${model.model}`;
}

function FlowCard({ number, step }: { number: string; step: FlowStep }) {
  return (
    <section className="flow-step" aria-label={`${number} ${step.title}`}>
      <div className="flow-head">
        <span className="flow-number">{number}</span>
        <span className="flow-title">{step.title}</span>
      </div>
      <span className="flow-side">
        {step.side === "inside" ? "Inside your boundary" : "Outside"}
      </span>
      {step.body}
    </section>
  );
}

// The server names placeholders <ENTITY_TYPE_n>, as enforcement.redact() writes them.
const PLACEHOLDER = /(<[A-Z][A-Z0-9_]*_\d+>)/;

interface SwapPart {
  text: string;
  placeholder?: string;
}

/**
 * Lines up a text that has placeholders with the same text that has the values, and
 * returns the second one split into plain parts and swapped values. Only the server knows
 * the mapping, so this reads it back from the two texts; if they do not line up exactly
 * (two placeholders side by side, or one placeholder with two values), it returns null and
 * the plain text is shown instead.
 */
function swaps(withPlaceholders: string, withValues: string): SwapPart[] | null {
  const pieces = withPlaceholders.split(PLACEHOLDER);
  const parts: SwapPart[] = [];
  const seen = new Map<string, string>();
  let cursor = 0;
  for (let i = 0; i < pieces.length; i += 1) {
    const piece = pieces[i] ?? "";
    if (i % 2 === 0) {
      if (!withValues.startsWith(piece, cursor)) return null;
      if (piece) parts.push({ text: piece });
      cursor += piece.length;
      continue;
    }
    const next = pieces[i + 1] ?? "";
    let end: number;
    if (i + 2 >= pieces.length) {
      end = next ? withValues.length - next.length : withValues.length;
    } else if (!next) {
      return null;
    } else {
      end = withValues.indexOf(next, cursor);
    }
    if (end < cursor) return null;
    const value = withValues.slice(cursor, end);
    if (!value || (seen.has(piece) && seen.get(piece) !== value)) return null;
    seen.set(piece, value);
    // A placeholder that came back unchanged (an output-scan one) was not swapped.
    parts.push(value === piece ? { text: value } : { text: value, placeholder: piece });
    cursor = end;
  }
  return cursor === withValues.length ? parts : null;
}

function SwapTable({ parts }: { parts: SwapPart[] }) {
  const rows = new Map<string, string>();
  for (const part of parts) if (part.placeholder) rows.set(part.placeholder, part.text);
  return (
    <>
      <table className="flow-swaps">
        <thead>
          <tr>
            <th>Your value</th>
            <th>Sent as</th>
          </tr>
        </thead>
        <tbody>
          {[...rows].map(([placeholder, value]) => (
            <tr key={placeholder}>
              <td>{value}</td>
              <td>
                <mark className="flow-mark flow-out">{placeholder}</mark>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="hint">The values stay here. Only the placeholders are sent.</p>
    </>
  );
}

function Placeholders({ text }: { text: string }) {
  return (
    <pre className="block">
      {text.split(PLACEHOLDER).map((piece, index) =>
        index % 2 === 1 ? (
          <mark key={index} className="flow-mark flow-out">
            {piece}
          </mark>
        ) : (
          piece
        ),
      )}
    </pre>
  );
}

function Restored({ parts }: { parts: SwapPart[] }) {
  return (
    <>
      {parts.map((part, index) =>
        part.placeholder ? (
          <mark key={index} className="flow-mark flow-in" title={`Was ${part.placeholder}`}>
            {part.text}
            <span className="mark-tag">{part.placeholder.slice(1, -1)}</span>
          </mark>
        ) : (
          part.text
        ),
      )}
    </>
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
