// Mirrors the control plane's JSON API (src/control_plane/api.py).

export type Action = "allow" | "redact" | "block" | "route_sovereign";

export type Label =
  | "no_private_data"
  | "contains_private_data"
  | "uncertain"
  | "unknown_assume_private"
  | "invalid_input";

export type Outcome = "completed" | "blocked" | "failed" | "withheld";

export interface Finding {
  entity_type: string;
  category: string | null;
  // Offsets are Unicode code points into the normalized prompt.
  start: number;
  end: number;
  score: number;
  detector: string;
  recognizer: string;
  counted: boolean;
}

export interface Receipt {
  seq: number;
  hash: string;
  sig: string;
  key_id: string;
}

export interface InferenceResult {
  audit_id: string;
  decision: { action: Action; rule_id: string; rationale: string; fail_closed: boolean };
  classification: { label: Label; categories: string[]; rationale: string; findings: Finding[] };
  policy: { id: string; version: string; sha256: string } | null;
  outcome: Outcome;
  outcome_reason: string | null;
  model: { provider: string; model: string; in_boundary: boolean; stub: boolean } | null;
  forwarded_prompt: string | null;
  response: string | null;
  receipts: { decision: Receipt; outcome: Receipt };
}

export interface AuditRecord {
  seq: number;
  ts: string;
  event: string;
  audit_id: string;
  body: Record<string, unknown>;
  prev_hash: string;
  hash: string;
  sig: string;
  key_id: string;
}

export interface Problem {
  seq: number | null;
  reason: string;
}

export interface VerifyReport {
  ok: boolean;
  records: number;
  head_seq: number | null;
  head_hash: string | null;
  chain_problems: Problem[];
  incomplete_requests: string[];
  decisions_replayed: number;
  replay_problems: Problem[];
}

export interface PolicyInfo {
  valid: boolean;
  id?: string;
  version?: string;
  sha256?: string;
  error?: string;
  text: string | null;
}

export interface ModelStatus {
  provider: string;
  model: string;
  stub: boolean;
  ready: boolean;
  detail: string;
}

export interface Health {
  status: string;
  detectors: Record<string, string>;
  sovereign_model: ModelStatus;
  external_model: ModelStatus;
}
