import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, checkPolicy, getPolicy, restoreDefaultPolicy, savePolicy } from "../api";
import { forgetAdminToken, readAdminToken, storeAdminToken } from "../adminToken";
import { formatDateTime, shortHash } from "../text";
import type {
  FieldError,
  PolicyChangeResult,
  PolicyCheck,
  PolicyDocument,
  PolicyHistoryEntry,
  PolicyInfo,
} from "../types";
import { PolicyForm, ruleIdProblems } from "./policy/PolicyForm";
import { PolicyPreviewPanel } from "./policy/PolicyPreviewPanel";

interface Props {
  onOpenAuditLog: () => void;
}

type Panel = "save" | "restore" | "preview";

export function PolicyView({ onOpenAuditLog }: Props) {
  const [info, setInfo] = useState<PolicyInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Non-null while editing: the policy as it would be saved.
  const [draft, setDraft] = useState<PolicyDocument | null>(null);
  const [check, setCheck] = useState<PolicyCheck | null>(null);
  const [panel, setPanel] = useState<Panel | null>(null);
  const [token, setToken] = useState(readAdminToken);
  const [saved, setSaved] = useState<PolicyChangeResult | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      setInfo(await getPolicy());
      setLoadError(null);
    } catch {
      setLoadError("The policy could not be loaded.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Validate the draft and list what saving it would change, shortly after each edit.
  useEffect(() => {
    if (!draft) {
      setCheck(null);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      checkPolicy(draft)
        .then((result) => {
          if (!cancelled) setCheck(result);
        })
        .catch(() => {
          if (!cancelled) setCheck(null);
        });
    }, 300);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [draft]);

  useEffect(() => {
    if (panel) panelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [panel]);

  if (loadError) {
    return (
      <div className="banner banner-bad" role="alert">
        {loadError}
      </div>
    );
  }
  if (!info) return <div className="sheet muted">Loading…</div>;

  function startEditing() {
    if (!info?.document) return;
    setSaved(null);
    setDraft(structuredClone(info.document));
  }

  function stopEditing() {
    setDraft(null);
    setPanel(null);
  }

  function openSavePanel() {
    // Each saved change needs its own version; the server refuses one already in use.
    // Unless the editor chose a version, the draft gets the next free one.
    if (draft && info?.next_version && draft.version === info.version) {
      setDraft({ ...draft, version: info.next_version });
    }
    setPanel("save");
  }

  async function afterChange(result: PolicyChangeResult) {
    storeAdminToken(token);
    stopEditing();
    setSaved(result);
    await load();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function tokenRejected() {
    forgetAdminToken();
    setToken("");
  }

  // With open editing nobody needs a token, so none is asked for.
  const needsToken = !info.open_editing;
  const tokenField = needsToken ? <AdminTokenField token={token} onChange={setToken} /> : null;
  const idProblems = draft ? ruleIdProblems(draft.rules) : new Map<number, string>();
  const errors = check?.errors ?? [];
  const draftValid = draft !== null && idProblems.size === 0 && check?.valid === true;
  const changes = check?.changes ?? [];

  return (
    <div className="policy-page">
      <section className="sheet">
        <div className="toolbar">
          <div>
            <h2>Policy</h2>
            <p className="hint">
              Every prompt is checked against this policy. A change takes effect on the next
              request, and each change is signed into the audit log with who made it and why.{" "}
              {info.open_editing
                ? "On this demo anyone can change it, and “Back to the original policy” always puts the shipped one back."
                : "Anyone can edit a draft and try it on prompts; only saving it needs the admin token."}
            </p>
          </div>
          {!draft && (
            <div className="toolbar-actions">
              {info.editable && (!info.is_default || !info.valid) && (
                <button type="button" className="secondary" onClick={() => setPanel("restore")}>
                  Back to the original policy
                </button>
              )}
              <button
                type="button"
                className="primary"
                onClick={startEditing}
                disabled={!info.document}
              >
                {info.editable ? "Edit policy" : "Try an edit"}
              </button>
            </div>
          )}
        </div>

        {info.valid ? (
          <dl className="facts">
            <dt>Policy</dt>
            <dd>
              {info.id} <span className="muted">v{info.version}</span>
            </dd>
            <dt>SHA-256</dt>
            <dd className="mono">{info.sha256}</dd>
            <dt>Source</dt>
            <dd>
              {info.is_default
                ? "The default policy, as shipped in policy/policy.yaml"
                : "Changed from the default"}
            </dd>
          </dl>
        ) : (
          <div className="banner banner-bad" role="alert">
            <strong>There is no valid policy, so every request is being blocked.</strong>
            <div className="mono">{info.error}</div>
            {info.editable && (
              <button type="button" className="link" onClick={() => setPanel("restore")}>
                Back to the original policy
              </button>
            )}
          </div>
        )}

        {!info.editable && (
          <div className="banner banner-info" role="status">
            You can edit a draft and try it, but saving is turned off on this server because it
            has no admin token. Set <code>SCP_ADMIN_TOKEN</code> to turn saving on.
          </div>
        )}
        {saved && (
          <div className="banner banner-good" role="status">
            <strong>
              Version {saved.policy.version} is in force from the next request.
            </strong>{" "}
            The change is record #{saved.receipt.seq} in the audit log.
            <button type="button" className="link" onClick={onOpenAuditLog}>
              Open the audit log
            </button>
          </div>
        )}
      </section>

      {draft && info.document ? (
        <PolicyForm document={draft} catalog={info.catalog} onChange={setDraft} />
      ) : (
        info.document && <PolicyForm document={info.document} catalog={info.catalog} onChange={null} />
      )}

      {draft && errors.length > 0 && (
        <div className="banner banner-bad" role="alert">
          <strong>Fix these before saving:</strong>
          <ul>
            {errors.map((error, index) => (
              <li key={index}>
                {fieldName(error, draft)}: {error.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div ref={panelRef} className="panel-anchor">
        {panel === "preview" && draft && <PolicyPreviewPanel draft={draft} />}
        {panel === "save" && draft && (
          <SavePanel
            draft={draft}
            info={info}
            changes={changes}
            token={needsToken ? token : ""}
            needsToken={needsToken}
            tokenField={tokenField}
            onTokenRejected={tokenRejected}
            onReload={() => {
              stopEditing();
              void load();
            }}
            onSaved={(result) => void afterChange(result)}
            onCancel={() => setPanel(null)}
          />
        )}
        {panel === "restore" && (
          <RestorePanel
            info={info}
            token={needsToken ? token : ""}
            needsToken={needsToken}
            tokenField={tokenField}
            onTokenRejected={tokenRejected}
            onRestored={(result) => void afterChange(result)}
            onCancel={() => setPanel(null)}
          />
        )}
      </div>

      {draft && (
        <div className="edit-bar" role="region" aria-label="Your draft">
          <p className="edit-status" role="status">
            {errors.length + idProblems.size > 0 ? (
              <span className="hint-bad">The draft has problems to fix.</span>
            ) : changes.length === 0 ? (
              "No changes yet."
            ) : (
              `${changes.length} change${changes.length === 1 ? "" : "s"} not saved.`
            )}
          </p>
          <div className="toolbar-actions">
            <button type="button" className="secondary" onClick={stopEditing}>
              Discard
            </button>
            <button
              type="button"
              className="secondary"
              disabled={!draftValid}
              onClick={() => setPanel("preview")}
            >
              Try the draft
            </button>
            {info.editable && (
              <button
                type="button"
                className="primary"
                disabled={!draftValid || changes.length === 0}
                onClick={openSavePanel}
              >
                Save
              </button>
            )}
          </div>
        </div>
      )}

      <History entries={info.history} />

      {info.text && (
        <details className="sheet yaml-details">
          <summary>The policy as stored (YAML)</summary>
          <pre className="block yaml">{info.text}</pre>
        </details>
      )}
    </div>
  );
}

/** "rules.2.action" as a person would say it: "Rule 3 (redact-pii), action". */
function fieldName(error: FieldError, draft: PolicyDocument): string {
  if (!error.path) return "Policy";
  const [head, index, ...rest] = error.path.split(".");
  if (head === "rules" && index !== undefined) {
    const id = draft.rules[Number(index)]?.id;
    const rule = `Rule ${Number(index) + 1}${id ? ` (${id})` : ""}`;
    return [rule, ...rest].join(", ").replaceAll("_", " ");
  }
  return error.path.split(".").join(", ").replaceAll("_", " ");
}

function AdminTokenField({ token, onChange }: { token: string; onChange: (token: string) => void }) {
  return (
    <label className="field">
      <span className="field-label">Admin token</span>
      <input
        type="password"
        className="mono"
        value={token}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => onChange(event.target.value.trim())}
      />
      <span className="hint">
        Needed to change the policy. Ask whoever runs this server; the hosted demo keeps it in
        AWS Secrets Manager. This browser tab keeps it until the tab is closed.
      </span>
    </label>
  );
}

interface ChangeErrorState {
  message: string;
  errors: FieldError[];
  conflict: boolean;
}

function describeFailure(caught: unknown, onTokenRejected: () => void): ChangeErrorState {
  if (caught instanceof ApiError) {
    if (caught.status === 401) {
      onTokenRejected();
      return { message: "The admin token was not accepted.", errors: [], conflict: false };
    }
    return { message: caught.message, errors: caught.errors, conflict: caught.status === 409 };
  }
  return { message: "The control plane could not be reached.", errors: [], conflict: false };
}

function SavePanel({
  draft,
  info,
  changes,
  token,
  needsToken,
  tokenField,
  onTokenRejected,
  onReload,
  onSaved,
  onCancel,
}: {
  draft: PolicyDocument;
  info: PolicyInfo;
  changes: string[];
  token: string;
  needsToken: boolean;
  tokenField: ReactNode;
  onTokenRejected: () => void;
  onReload: () => void;
  onSaved: (result: PolicyChangeResult) => void;
  onCancel: () => void;
}) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ChangeErrorState | null>(null);

  async function submit() {
    setBusy(true);
    setFailure(null);
    try {
      onSaved(await savePolicy(draft, info.base_sha256, note.trim(), token));
    } catch (caught) {
      setFailure(describeFailure(caught, onTokenRejected));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="sheet policy-panel" aria-labelledby="save-title">
      <h2 id="save-title">
        Save version {draft.version}
      </h2>
      <span className="field-label">What changes</span>
      <ul className="change-list">
        {changes.map((change, index) => (
          <li key={index}>{change}</li>
        ))}
      </ul>
      <label className="field">
        <span className="field-label">Why are you changing it? This goes into the audit log.</span>
        {/* The reason is the one thing left to fill in, so the cursor goes there. */}
        <textarea
          rows={2}
          value={note}
          maxLength={500}
          required
          autoFocus
          onChange={(event) => setNote(event.target.value)}
        />
      </label>
      {tokenField}
      {failure && <FailureBanner failure={failure} draft={draft} onReload={onReload} />}
      <div className="panel-actions">
        {note.trim() === "" && <span className="hint">Write why to save.</span>}
        <button type="button" className="secondary" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="button"
          className="primary"
          disabled={busy || note.trim() === "" || (needsToken && token === "")}
          onClick={() => void submit()}
        >
          {busy ? "Saving…" : "Save and apply"}
        </button>
      </div>
    </section>
  );
}

function RestorePanel({
  info,
  token,
  needsToken,
  tokenField,
  onTokenRejected,
  onRestored,
  onCancel,
}: {
  info: PolicyInfo;
  token: string;
  needsToken: boolean;
  tokenField: ReactNode;
  onTokenRejected: () => void;
  onRestored: (result: PolicyChangeResult) => void;
  onCancel: () => void;
}) {
  const [note, setNote] = useState("Back to the original policy.");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ChangeErrorState | null>(null);

  async function submit() {
    setBusy(true);
    setFailure(null);
    try {
      onRestored(await restoreDefaultPolicy(info.base_sha256, note.trim(), token));
    } catch (caught) {
      setFailure(describeFailure(caught, onTokenRejected));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="sheet policy-panel" aria-labelledby="restore-title">
      <h2 id="restore-title">Back to the original policy</h2>
      <p className="hint">
        Puts the original policy, as shipped in <code>policy/policy.yaml</code>, back in force.
        Like any change, it is recorded in the audit log, and the versions before it stay in the
        history.
      </p>
      <label className="field">
        <span className="field-label">Note for the audit log</span>
        <textarea
          rows={2}
          value={note}
          maxLength={500}
          onChange={(event) => setNote(event.target.value)}
        />
      </label>
      {tokenField}
      {failure && <FailureBanner failure={failure} onReload={onCancel} />}
      <div className="panel-actions">
        <button type="button" className="secondary" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="button"
          className="primary"
          disabled={busy || note.trim() === "" || (needsToken && token === "")}
          onClick={() => void submit()}
        >
          {busy ? "Restoring…" : "Back to the original policy"}
        </button>
      </div>
    </section>
  );
}

function FailureBanner({
  failure,
  draft,
  onReload,
}: {
  failure: ChangeErrorState;
  draft?: PolicyDocument;
  onReload: () => void;
}) {
  return (
    <div className="banner banner-bad" role="alert">
      <strong>{failure.message}</strong>
      {failure.errors.length > 0 && draft && (
        <ul>
          {failure.errors.map((error, index) => (
            <li key={index}>
              {fieldName(error, draft)}: {error.message}
            </li>
          ))}
        </ul>
      )}
      {failure.conflict && (
        <button type="button" className="link" onClick={onReload}>
          Reload the policy
        </button>
      )}
    </div>
  );
}

function History({ entries }: { entries: PolicyHistoryEntry[] }) {
  return (
    <section className="sheet" aria-labelledby="history-title">
      <h2 id="history-title">Change history</h2>
      <p className="hint">
        Read from the signed audit log, newest first. Each change was recorded before it took
        effect.
      </p>
      {entries.length === 0 ? (
        <p className="empty-history">No change yet: this server is running the policy it started with.</p>
      ) : (
        <ol className="history">
          {entries.map((entry) => (
            <li key={entry.seq}>
              <header>
                <strong>
                  {entry.restored_default ? "Back to the original, " : ""}v{entry.policy.version}
                </strong>
                <span className="hint nowrap">{formatDateTime(entry.ts)}</span>
                <span className="hint mono">{entry.changed_by}</span>
                <span className="hint">record #{entry.seq}</span>
                <span className="hint mono">{shortHash(entry.policy.sha256, 8)}</span>
              </header>
              <p>{entry.note}</p>
              {entry.changes.length > 0 && (
                <ul className="change-list">
                  {entry.changes.map((change, index) => (
                    <li key={index}>{change}</li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
