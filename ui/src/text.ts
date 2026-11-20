import type { Action, Finding, Label, Outcome } from "./types";

// The same invisible characters the control plane strips before inspection
// (normalize_prompt in src/control_plane/pipeline.py). Finding offsets refer to the
// normalized text, so the UI must highlight that text, not what was typed.
const INVISIBLE = new Set(
  [0x00ad, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff].map((codePoint) =>
    String.fromCodePoint(codePoint),
  ),
);

export function normalizePrompt(prompt: string): string {
  return Array.from(prompt.normalize("NFKC"))
    .filter((char) => !INVISIBLE.has(char))
    .join("");
}

export interface Segment {
  text: string;
  findings: Finding[];
}

/**
 * Split text into plain and highlighted runs.
 *
 * Offsets from the API count Unicode code points (Python strings), while JavaScript
 * strings index UTF-16 units, so the text is sliced as an array of code points.
 * Overlapping findings are merged into one run, the same way redaction merges them.
 */
export function segmentText(text: string, findings: Finding[]): Segment[] {
  const chars = Array.from(text);
  const sorted = findings
    .filter((finding) => finding.counted)
    .sort((a, b) => a.start - b.start || a.end - b.end);

  const segments: Segment[] = [];
  let cursor = 0;
  let group: Finding[] = [];
  let groupStart = 0;
  let groupEnd = 0;

  const flush = () => {
    if (group.length === 0) return;
    if (groupStart > cursor) {
      segments.push({ text: chars.slice(cursor, groupStart).join(""), findings: [] });
    }
    segments.push({ text: chars.slice(groupStart, groupEnd).join(""), findings: group });
    cursor = groupEnd;
    group = [];
  };

  for (const finding of sorted) {
    if (group.length > 0 && finding.start < groupEnd) {
      groupEnd = Math.max(groupEnd, finding.end);
      group.push(finding);
      continue;
    }
    flush();
    group = [finding];
    groupStart = finding.start;
    groupEnd = finding.end;
  }
  flush();

  if (cursor < chars.length) {
    segments.push({ text: chars.slice(cursor).join(""), findings: [] });
  }
  return segments;
}

export type Tone = "danger" | "regulated" | "caution" | "pii" | "neutral";

const CATEGORY_TONES: Record<string, Tone> = {
  secret: "danger",
  possible_secret: "caution",
  government_id: "regulated",
  financial: "regulated",
  health: "regulated",
  confidential_business: "regulated",
  prompt_injection: "danger",
  pii: "pii",
};

export function categoryTone(category: string | null): Tone {
  return (category && CATEGORY_TONES[category]) || "neutral";
}

export const ACTION_LABELS: Record<Action, string> = {
  allow: "Allow",
  redact: "Redact",
  block: "Block",
  route_sovereign: "Route to sovereign model",
};

export const ACTION_SUMMARIES: Record<Action, string> = {
  allow: "Sent to the external model unchanged.",
  redact: "Private values replaced with placeholders, then sent to the external model.",
  block: "No model was called.",
  route_sovereign: "Sent to the model inside the trust boundary. Nothing was sent outside.",
};

export const LABEL_TEXT: Record<Label, string> = {
  no_private_data: "No private data",
  contains_private_data: "Contains private data",
  uncertain: "Uncertain, treated as private",
  unknown_assume_private: "Detection failed, assumed private",
  invalid_input: "Invalid request",
};

export const OUTCOME_TEXT: Record<Outcome, string> = {
  completed: "Completed",
  blocked: "Blocked",
  failed: "Model call failed",
  withheld: "Answer withheld",
};

export const shortHash = (hash: string, length = 12) =>
  hash.length > length ? `${hash.slice(0, length)}…` : hash;

/** Date and time, for periods longer than a day. */
export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
}

export function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleTimeString([], { hour12: false });
}
