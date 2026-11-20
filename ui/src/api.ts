import type {
  Action,
  AlertsReport,
  AuditPage,
  FieldError,
  Health,
  InferenceResult,
  PolicyChangeResult,
  PolicyCheck,
  PolicyDocument,
  PolicyInfo,
  PolicyPreview,
  VerifyReport,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    // Field by field, when the server rejected a policy.
    readonly errors: FieldError[] = [],
  ) {
    super(message);
  }
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new ApiError(response.status, `${path} returned HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

export interface InferenceReply {
  httpStatus: number;
  result: InferenceResult;
}

function isInferenceResult(body: unknown): body is InferenceResult {
  return typeof body === "object" && body !== null && "audit_id" in body && "decision" in body;
}

/**
 * Send a prompt through the control plane.
 *
 * A rejected request (HTTP 413, 415, 422) still comes back as a full decision with
 * its own audit record, so it is returned, not thrown. Only a response with no
 * decision at all (for example 503 when evidence cannot be written) is an error.
 */
export async function infer(prompt: string): Promise<InferenceReply> {
  const response = await fetch("/v1/inference", {
    method: "POST",
    headers: { "content-type": "application/json", "x-client-id": "web-ui" },
    body: JSON.stringify({ prompt }),
  });
  const body: unknown = await response.json().catch(() => null);
  if (isInferenceResult(body)) {
    return { httpStatus: response.status, result: body };
  }
  const fields = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  const detail =
    "detail" in fields
      ? String(fields.detail)
      : `The control plane returned HTTP ${response.status}.`;
  // A failed request still has an audit ID, and its records say how far it got.
  const auditId = typeof fields.audit_id === "string" ? fields.audit_id : null;
  throw new ApiError(response.status, auditId ? `${detail} Audit ID: ${auditId}.` : detail);
}

export async function getHealth(): Promise<Health> {
  const response = await fetch("/healthz");
  // A 503 still carries the full status: it means "degraded", not "unreachable".
  if (response.ok || response.status === 503) {
    return (await response.json()) as Health;
  }
  throw new ApiError(response.status, `/healthz returned HTTP ${response.status}`);
}
export const getPolicy = () => getJson<PolicyInfo>("/v1/policy");

function isFieldErrors(value: unknown): value is FieldError[] {
  return Array.isArray(value) && value.every((item) => typeof item === "object" && item !== null && "path" in item);
}

/** The server's reason for refusing, from FastAPI's `detail`, in whatever shape it came. */
function refusal(status: number, body: unknown): ApiError {
  const detail = typeof body === "object" && body !== null ? (body as { detail?: unknown }).detail : undefined;
  if (typeof detail === "string") return new ApiError(status, detail);
  if (isFieldErrors(detail)) return new ApiError(status, "The request was not valid.", detail);
  if (typeof detail === "object" && detail !== null) {
    const { message, errors } = detail as { message?: unknown; errors?: unknown };
    return new ApiError(
      status,
      typeof message === "string" ? message : "The request was refused.",
      isFieldErrors(errors) ? errors : [],
    );
  }
  return new ApiError(status, `The control plane returned HTTP ${status}.`);
}

async function sendJson<T>(method: string, path: string, body: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(path, { method, headers, body: JSON.stringify(body) });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) throw refusal(response.status, payload);
  return payload as T;
}

/** Validate a draft and list what saving it would change. Needs no token. */
export const checkPolicy = (document: PolicyDocument) =>
  sendJson<PolicyCheck>("POST", "/v1/policy/check", { document });

export const savePolicy = (
  document: PolicyDocument,
  baseSha256: string | null,
  note: string,
  token: string,
) =>
  sendJson<PolicyChangeResult>(
    "PUT",
    "/v1/policy",
    { document, base_sha256: baseSha256, note },
    token,
  );

export const restoreDefaultPolicy = (baseSha256: string | null, note: string, token: string) =>
  sendJson<PolicyChangeResult>(
    "POST",
    "/v1/policy/restore-default",
    { base_sha256: baseSha256, note },
    token,
  );

/** What the draft and the policy in force decide for one prompt. Calls no model. */
export const previewPolicy = (document: PolicyDocument, prompt: string, token: string) =>
  sendJson<PolicyPreview>("POST", "/v1/policy/preview", { document, prompt }, token);
export const verifyAudit = () => getJson<VerifyReport>("/v1/audit/verify");
export const getAlerts = (hours = 24) => getJson<AlertsReport>(`/v1/alerts?hours=${hours}`);

/** Newest first. `auditId` (a full audit ID or its first characters) narrows it to those requests. */
export interface AuditQuery {
  limit: number;
  // The previous page's `next_before`, for the next, older page.
  before?: number;
  // A full audit ID or its first characters.
  auditId?: string;
  action?: Action;
  ruleId?: string;
  category?: string;
}

export function listAuditRequests({ limit, before, auditId, action, ruleId, category }: AuditQuery) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (before !== undefined) params.set("before", String(before));
  if (auditId) params.set("audit_id", auditId);
  if (action) params.set("action", action);
  if (ruleId) params.set("rule_id", ruleId);
  if (category) params.set("category", category);
  return getJson<AuditPage>(`/v1/audit/requests?${params.toString()}`);
}
