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
  // The model's answer before placeholders are restored. Differs from `response` only
  // when the control plane put redacted values back.
  model_reply: string | null;
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

// One request and every record it left, oldest first. A policy record is an entry of its own.
export interface AuditEntry {
  audit_id: string;
  records: [AuditRecord, ...AuditRecord[]];
}

export interface AuditPage {
  total: number;
  entries: AuditEntry[];
  // Pass as `before` for the next, older page. Null on the last page.
  next_before: number | null;
  // The rules and categories in the whole log, for the filters to offer.
  options: { rules: string[]; categories: string[] };
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

// The policy as the editor sees it: the shape of src/control_plane/policy.py's PolicyDocument.
export interface PolicyRule {
  id: string;
  description: string;
  // Matches when every condition given holds; empty lists match every request.
  when: { any_category: string[]; label: Label[] };
  action: Action;
}

export interface PolicyDocument {
  id: string;
  version: string;
  description: string;
  categories: Record<string, string[]>;
  detection: { min_score: number; confident_score: number };
  rules: PolicyRule[];
  default_action: Action;
  egress: { allowed_destinations: string[] };
  response: { redact_categories: string[]; restore_placeholders: boolean };
  block_message: string;
}

export interface PolicyRef {
  id: string;
  version: string;
  sha256: string;
}

// One policy_changed record from the audit log.
export interface PolicyHistoryEntry {
  seq: number;
  ts: string;
  policy: PolicyRef;
  previous: PolicyRef | null;
  changes: string[];
  note: string;
  changed_by: string;
  restored_default: boolean;
}

export interface PolicyInfo {
  valid: boolean;
  error: string | null;
  // The version a save must start from. Set even while the policy is broken.
  base_sha256: string | null;
  // False when the server has no admin token: the policy is read-only.
  editable: boolean;
  is_default: boolean;
  catalog: {
    // Entity type -> the detectors that can find it.
    entity_types: Record<string, string[]>;
    labels: Label[];
    actions: Action[];
    destinations: string[];
  };
  history: PolicyHistoryEntry[];
  text: string | null;
  document: PolicyDocument | null;
  id?: string;
  version?: string;
  sha256?: string;
}

export interface FieldError {
  // Where the problem is, such as "rules.2.action". Empty for the policy as a whole.
  path: string;
  message: string;
}

export interface PolicyCheck {
  valid: boolean;
  errors: FieldError[];
  changes: string[];
}

export interface PolicyVerdict {
  policy_version: string;
  label: Label;
  categories: string[];
  action: Action;
  rule_id: string;
  rationale: string;
  fail_closed: boolean;
  findings: string[];
}

export interface PolicyPreview {
  current: PolicyVerdict | null;
  draft: PolicyVerdict;
  changed: boolean;
}

export interface PolicyChangeResult {
  policy: PolicyRef;
  changes: string[];
  receipt: Receipt;
}

export interface ModelStatus {
  provider: string;
  model: string;
  stub: boolean;
  ready: boolean;
  detail: string;
}

export interface Health {
  status: "ok" | "degraded";
  // While invalid, every request is blocked until a valid policy is restored.
  policy: { valid: boolean; error: string | null };
  detectors: Record<string, string>;
  // Detector name -> error, for detectors whose most recent run failed.
  failing_detectors: Record<string, string>;
  sovereign_model: ModelStatus;
  external_model: ModelStatus;
}

// GET /v1/alerts: computed from live status and the audit log, never from prompt text.
export type Severity = "critical" | "warning" | "info";
export type AlertGroup = "health" | "policy" | "security" | "service";

export interface AlertExample {
  audit_id: string;
  ts: string;
  label: string | null;
  categories: string[];
  entity_types: string[];
  rule_id: string | null;
  reason: string | null;
  client: string | null;
}

export interface Alert {
  id: string;
  group: AlertGroup;
  severity: Severity;
  title: string;
  detail: string;
  action: string;
  count: number;
  // Null for a live alert: it is happening now.
  last_seen: string | null;
  examples: AlertExample[];
}

export interface LatencyStats {
  count: number;
  median: number | null;
  p95: number | null;
}

export interface PolicyEvent {
  ts: string;
  valid: boolean;
  id: string | null;
  version: string | null;
  sha256: string | null;
  error: string | null;
  // Set when an administrator changed the policy, null when it was only loaded.
  note: string | null;
  changed_by: string | null;
  changes: string[];
}

export interface AlertMetrics {
  requests: number;
  by_action: Record<string, number>;
  by_outcome: Record<string, number>;
  by_label: Record<string, number>;
  by_category: Record<string, number>;
  fail_closed: number;
  sent_outside: number;
  kept_inside: number;
  redacted_by_entity: Record<string, number>;
  uncertain_share: number;
  latency_ms: { inside: LatencyStats; outside: LatencyStats };
  top_clients: { client: string | null; requests: number; blocked: number }[];
  rule_matches: Record<string, number>;
  // Null until the period has enough requests for "never matched" to mean something.
  rules_not_matched: string[] | null;
  policy_timeline: PolicyEvent[];
}

export interface AlertsReport {
  generated_at: string;
  window: { hours: number; since: string; requests: number };
  status: Severity | "ok";
  alerts: Alert[];
  metrics: AlertMetrics;
}
