import type {
  AuditRecord,
  Health,
  InferenceResult,
  PolicyInfo,
  VerifyReport,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
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
  const detail =
    typeof body === "object" && body !== null && "detail" in body
      ? String((body as { detail: unknown }).detail)
      : `The control plane returned HTTP ${response.status}.`;
  throw new ApiError(response.status, detail);
}

export const getHealth = () => getJson<Health>("/healthz");
export const getPolicy = () => getJson<PolicyInfo>("/v1/policy");
export const verifyAudit = () => getJson<VerifyReport>("/v1/audit/verify");

export const listAudit = (limit = 200) =>
  getJson<{ total: number; records: AuditRecord[] }>(`/v1/audit?limit=${limit}`);
