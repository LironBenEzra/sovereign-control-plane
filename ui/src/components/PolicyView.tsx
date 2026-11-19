import { useEffect, useState } from "react";
import { getPolicy } from "../api";
import type { PolicyInfo } from "../types";

export function PolicyView() {
  const [policy, setPolicy] = useState<PolicyInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getPolicy()
      .then(setPolicy)
      .catch(() => setError("The policy could not be loaded."));
  }, []);

  if (error) {
    return (
      <div className="banner banner-bad" role="alert">
        {error}
      </div>
    );
  }
  if (!policy) return <div className="card muted">Loading…</div>;

  return (
    <section className="card">
      <h2>Active policy</h2>
      <p className="hint">
        Rules live in one file, <code>policy/policy.yaml</code>. It is re-read on every request,
        so an edit takes effect on the next one. Every audit record names the SHA-256 of the
        policy text it was decided under.
      </p>

      {policy.valid ? (
        <dl className="facts">
          <dt>Policy</dt>
          <dd>
            {policy.id} <span className="muted">v{policy.version}</span>
          </dd>
          <dt>SHA-256</dt>
          <dd className="mono">{policy.sha256}</dd>
        </dl>
      ) : (
        <div className="banner banner-bad" role="alert">
          <strong>The policy is invalid, so every request is being blocked.</strong>
          <div className="mono">{policy.error}</div>
        </div>
      )}

      {policy.text !== null ? (
        <pre className="block yaml">{policy.text}</pre>
      ) : (
        <p className="hint">The policy file could not be read.</p>
      )}
    </section>
  );
}
