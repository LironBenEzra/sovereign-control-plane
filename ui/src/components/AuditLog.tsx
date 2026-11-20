import { type FormEvent, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { listAuditRequests, verifyAudit } from "../api";
import { ACTION_LABELS, OUTCOME_TEXT, formatTime, shortHash } from "../text";
import type { Action, AuditEntry, AuditPage, AuditRecord, VerifyReport } from "../types";

interface Props {
  // A full audit ID or its first characters. Null shows the whole log.
  query: string | null;
  onQueryChange: (query: string | null) => void;
}

// A request's records, in the order they are written, then the policy's.
const EVENT_NAMES: Record<string, string> = {
  received: "Received",
  detection: "Detection",
  decision: "Decision",
  model_call: "Model call",
  outcome: "Outcome",
  error: "Error",
  policy_loaded: "Policy",
  policy_changed: "Policy edit",
};

// Mirrors the API's check, so a typo is explained here instead of failing as a 422.
const AUDIT_ID_QUERY = /^[0-9a-f]{4,32}$/;

// Requests per page. Each one is a single row until it is opened.
const PAGE_SIZE = 25;

const ACTIONS: Action[] = ["allow", "redact", "route_sovereign", "block"];

// Each null shows every entry; any filter keeps only requests whose decision matches.
interface Filters {
  action: Action | null;
  ruleId: string | null;
  category: string | null;
}

const NO_FILTERS: Filters = { action: null, ruleId: null, category: null };

// An entry is known by its first record: a policy record has no audit ID of its own.
const entryKey = (entry: AuditEntry) => entry.records[0].seq;

export function AuditLog({ query, onQueryChange }: Props) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  // The rules and categories found in the log, for the filters to offer.
  const [options, setOptions] = useState<AuditPage["options"]>({ rules: [], categories: [] });
  const filtered = filters.action !== null || filters.ruleId !== null || filters.category !== null;
  // The entries opened to show their steps, and the records shown in full. Each opens and
  // closes on its own click only, so a click never collapses something elsewhere.
  const [opened, setOpened] = useState<ReadonlySet<number>>(new Set());
  const [shownRecords, setShownRecords] = useState<ReadonlySet<number>>(new Set());
  // The element just clicked and where it was on screen. After the render it is put back
  // there, so what was clicked never moves and new content always opens below it. Browsers
  // differ in how they keep the view steady when content changes, and Safari does not try.
  const clicked = useRef<{ element: Element; top: number } | null>(null);
  // Space after the list. Closing something near the end of the page shortens it, and the
  // browser would scroll up and move what was clicked; this space takes up the difference
  // instead, and goes once it is scrolled out of sight.
  const tail = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const anchor = clicked.current;
    if (!anchor) return;
    clicked.current = null;
    const moved = anchor.element.getBoundingClientRect().top - anchor.top;
    if (moved === 0) return;
    const target = window.scrollY + moved;
    const room = document.documentElement.scrollHeight - window.innerHeight;
    if (target > room && tail.current) {
      tail.current.style.height = `${tail.current.offsetHeight + target - room}px`;
    }
    window.scrollTo(0, target);
  });

  useEffect(() => {
    function dropTailOutOfSight() {
      const spacer = tail.current;
      if (!spacer || spacer.offsetHeight === 0) return;
      if (spacer.getBoundingClientRect().top >= window.innerHeight) spacer.style.height = "0";
    }
    window.addEventListener("scroll", dropTailOutOfSight, { passive: true });
    return () => window.removeEventListener("scroll", dropTailOutOfSight);
  }, []);
  const [report, setReport] = useState<VerifyReport | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState(query ?? "");
  const [draftError, setDraftError] = useState<string | null>(null);
  // The query the shown entries answer, so the banner never describes a stale result.
  const [loadedQuery, setLoadedQuery] = useState<string | null | undefined>(undefined);

  const refresh = useCallback(async () => {
    try {
      const page = await listAuditRequests({
        limit: PAGE_SIZE,
        auditId: query ?? undefined,
        ...filterParams(filters),
      });
      setEntries(page.entries);
      setTotal(page.total);
      setNextBefore(page.next_before);
      setOptions(page.options);
      setLoadedQuery(query);
      // A search that finds one request opens it: its steps are what was asked for.
      const [only] = page.entries;
      if (query && page.entries.length === 1 && only) {
        setOpened((current) => new Set([...current, entryKey(only)]));
      }
      setError(null);
    } catch {
      setError(query ? "The search could not be run." : "The audit log could not be loaded.");
    }
  }, [query, filters]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function showOlder() {
    if (nextBefore === null) return;
    setLoadingOlder(true);
    try {
      const page = await listAuditRequests({
        limit: PAGE_SIZE,
        before: nextBefore,
        auditId: query ?? undefined,
        ...filterParams(filters),
      });
      setEntries((shown) => [...shown, ...page.entries]);
      setTotal(page.total);
      setNextBefore(page.next_before);
    } catch {
      setError("Older requests could not be loaded.");
    } finally {
      setLoadingOlder(false);
    }
  }

  async function verify() {
    setVerifying(true);
    try {
      setReport(await verifyAudit());
      await refresh();
    } catch {
      setError("Verification could not be run.");
    } finally {
      setVerifying(false);
    }
  }

  function toggle(
    setter: (update: (current: ReadonlySet<number>) => ReadonlySet<number>) => void,
    key: number,
    element: Element,
  ) {
    clicked.current = { element, top: element.getBoundingClientRect().top };
    setter((current) => {
      const next = new Set(current);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  }

  function search(event: FormEvent) {
    event.preventDefault();
    const value = draft.trim().toLowerCase();
    if (value === "") {
      clearSearch();
      return;
    }
    if (!AUDIT_ID_QUERY.test(value)) {
      setDraftError("Enter at least 4 characters of an audit ID, using 0–9 and a–f.");
      return;
    }
    onQueryChange(value);
  }

  function clearSearch() {
    setDraft("");
    setDraftError(null);
    onQueryChange(null);
  }

  return (
    <>
      <section className="sheet">
        <div className="toolbar">
          <div>
            <h2>Audit log</h2>
            <p className="hint">
              Append-only, hash chained, and signed with Ed25519. One row per request: open it to
              see each step it recorded.
            </p>
          </div>
          <div className="toolbar-actions">
            <button type="button" className="secondary" onClick={() => void refresh()}>
              Refresh
            </button>
            <button
              type="button"
              className="primary"
              onClick={() => void verify()}
              disabled={verifying}
            >
              {verifying ? "Verifying…" : "Verify chain"}
            </button>
          </div>
        </div>

        <form className="audit-search" role="search" onSubmit={search}>
          <label className="field-label" htmlFor="audit-search">
            Find a request
          </label>
          <div className="audit-search-row">
            <input
              id="audit-search"
              type="search"
              value={draft}
              onChange={(event) => {
                setDraft(event.target.value);
                setDraftError(null);
              }}
              placeholder="Audit ID, or its first 8 characters"
              spellCheck={false}
              autoComplete="off"
              aria-describedby="audit-search-hint"
              aria-invalid={draftError !== null}
            />
            <button type="submit" className="secondary">
              Find
            </button>
          </div>
          <p id="audit-search-hint" className={draftError ? "hint hint-bad" : "hint"}>
            {draftError ?? "Shows that request with every record it left, from its arrival to its outcome."}
          </p>
        </form>

        <div className="audit-filters">
          <FilterSelect
            label="Decision"
            all="All decisions"
            value={filters.action}
            options={ACTIONS.map((action) => ({ value: action, label: ACTION_LABELS[action] }))}
            onChange={(value) => setFilters({ ...filters, action: value as Action | null })}
          />
          <FilterSelect
            label="Rule"
            all="All rules"
            value={filters.ruleId}
            options={options.rules.map((rule) => ({ value: rule, label: rule }))}
            onChange={(value) => setFilters({ ...filters, ruleId: value })}
          />
          <FilterSelect
            label="Category"
            all="All categories"
            value={filters.category}
            options={options.categories.map((category) => ({
              value: category,
              label: category.replaceAll("_", " "),
            }))}
            onChange={(value) => setFilters({ ...filters, category: value })}
          />
          {filtered && (
            <button type="button" className="link" onClick={() => setFilters(NO_FILTERS)}>
              Clear filters
            </button>
          )}
        </div>

        {error && (
          <div className="banner banner-bad" role="alert">
            {error}
          </div>
        )}
        {report && <VerifyBanner report={report} />}

        {query && loadedQuery === query && (
          <div className="banner banner-info" role="status">
            {total === 0 && (
              <>
                No request has an audit ID starting with <code>{query}</code>.
              </>
            )}
            {total === 1 && entries[0] && (
              <>
                Request <code>{entries[0].audit_id}</code> and every record it left.
              </>
            )}
            {total > 1 && (
              <>
                {total} requests have an audit ID starting with <code>{query}</code>.
              </>
            )}{" "}
            <button type="button" className="link" onClick={clearSearch}>
              Show all requests
            </button>
          </div>
        )}

        <div className="audit-head" aria-hidden="true">
          <span>Time</span>
          <span>What happened</span>
          <span>Records</span>
          <span>Audit ID</span>
        </div>
        <ol className="audit-entries">
          {entries.map((entry) => (
            <RequestEntry
              key={entryKey(entry)}
              entry={entry}
              open={opened.has(entryKey(entry))}
              onToggle={(element) => toggle(setOpened, entryKey(entry), element)}
              shownRecords={shownRecords}
              onShowRecord={(seq, element) => toggle(setShownRecords, seq, element)}
            />
          ))}
        </ol>
        {entries.length === 0 && loadedQuery !== undefined && !query && (
          <p className="hint">
            {filtered
              ? "No request matches these filters."
              : "No records yet. Send a prompt from the playground."}
          </p>
        )}
        {entries.length > 0 && (
          <div className="audit-more">
            <span className="hint">
              Showing {entries.length} of {total}{" "}
              {filtered ? (total === 1 ? "request" : "requests") : total === 1 ? "entry" : "entries"},
              newest first.
            </span>
            {nextBefore !== null && (
              <button
                type="button"
                className="secondary"
                onClick={() => void showOlder()}
                disabled={loadingOlder}
              >
                {loadingOlder ? "Loading…" : "Show older"}
              </button>
            )}
          </div>
        )}
      </section>
      <div ref={tail} aria-hidden="true" />
    </>
  );
}

interface RequestEntryProps {
  entry: AuditEntry;
  open: boolean;
  onToggle: (clicked: Element) => void;
  shownRecords: ReadonlySet<number>;
  onShowRecord: (seq: number, clicked: Element) => void;
}

function filterParams(filters: Filters) {
  return {
    action: filters.action ?? undefined,
    ruleId: filters.ruleId ?? undefined,
    category: filters.category ?? undefined,
  };
}

interface FilterSelectProps {
  label: string;
  // The option that turns this filter off.
  all: string;
  value: string | null;
  options: { value: string; label: string }[];
  onChange: (value: string | null) => void;
}

function FilterSelect({ label, all, value, options, onChange }: FilterSelectProps) {
  return (
    <label className="audit-filter">
      <span className="field-label">{label}</span>
      <select value={value ?? ""} onChange={(event) => onChange(event.target.value || null)}>
        <option value="">{all}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function RequestEntry({ entry, open, onToggle, shownRecords, onShowRecord }: RequestEntryProps) {
  const first = entry.records[0];
  const summary = summarizeEntry(entry);
  const stepsId = `steps-${first.seq}`;
  const isRequest = AUDIT_ID_QUERY.test(entry.audit_id);
  return (
    <li className={open ? "audit-entry audit-entry-open" : "audit-entry"}>
      <button
        type="button"
        className="audit-entry-row"
        aria-expanded={open}
        aria-controls={stepsId}
        onClick={(event) => onToggle(event.currentTarget)}
      >
        <span className="audit-entry-time" title={first.ts}>
          {formatTime(first.ts)}
        </span>
        <span className="audit-entry-what">
          {!isRequest && (
            <span className={`chip event-chip event-${first.event}`}>
              {EVENT_NAMES[first.event] ?? first.event}
            </span>
          )}{" "}
          <span className={`summary-title ${summary.tone}`}>{summary.title}</span>{" "}
          <span className={summary.detailIsCode ? "muted mono" : "muted"}>{summary.detail}</span>
          {summary.evidence && <span className="audit-entry-evidence">{summary.evidence}</span>}
        </span>
        <span className="audit-entry-count">
          {entry.records.length} record{entry.records.length === 1 ? "" : "s"}
        </span>
        <span className="audit-entry-id mono" title={entry.audit_id}>
          {isRequest ? shortHash(entry.audit_id, 8) : entry.audit_id}
        </span>
      </button>
      {open && (
        <div id={stepsId}>
          {isRequest && <FullAuditId auditId={entry.audit_id} />}
          <ol className="audit-steps">
            {entry.records.map((record) => (
              <Step
                key={record.seq}
                record={record}
                start={first}
                shown={shownRecords.has(record.seq)}
                onToggle={(element) => onShowRecord(record.seq, element)}
              />
            ))}
          </ol>
        </div>
      )}
    </li>
  );
}

// The row shows the first characters only. An opened request shows the whole ID, to copy.
function FullAuditId({ auditId }: { auditId: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(auditId);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // The browser can refuse clipboard access. The ID is still there to select.
    }
  }

  return (
    <p className="audit-entry-full-id">
      <span>Audit ID</span>
      <code>{auditId}</code>
      <button type="button" className="link" onClick={() => void copy()}>
        {copied ? "Copied" : "Copy"}
      </button>
    </p>
  );
}

interface StepProps {
  record: AuditRecord;
  // The request's first record, to show each later step as time since it arrived.
  start: AuditRecord;
  shown: boolean;
  onToggle: (clicked: Element) => void;
}

function Step({ record, start, shown, onToggle }: StepProps) {
  const summary = summarize(record);
  const recordId = `record-${record.seq}`;
  const elapsed = new Date(record.ts).getTime() - new Date(start.ts).getTime();
  return (
    <li className="audit-step">
      <button
        type="button"
        className="audit-step-row"
        aria-expanded={shown}
        aria-controls={recordId}
        onClick={(event) => onToggle(event.currentTarget)}
      >
        <span className={`chip event-chip event-${record.event}`}>
          {EVENT_NAMES[record.event] ?? record.event}
        </span>
        <span className="audit-step-time" title={record.ts}>
          {record === start ? formatTime(record.ts) : `+${formatDuration(elapsed)}`}
        </span>
        <span className="audit-step-what">
          <span className={`summary-title ${summary.tone}`}>{summary.title}</span>{" "}
          <span className={summary.detailIsCode ? "muted mono" : "muted"}>{summary.detail}</span>
          {record.event === "detection" && <MaskedPrompt body={record.body} />}
        </span>
        <span className="audit-step-seq mono">#{record.seq}</span>
      </button>
      {shown && (
        <div className="audit-step-record" id={recordId}>
          <p className="hint">
            <code>hash</code> is the SHA-256 of this record's content plus <code>prev_hash</code>,
            and <code>sig</code> is the signature over that hash. No private value is stored: the
            prompt is kept as a keyed hash, and masked in the detection record.
          </p>
          <pre className="block json">{JSON.stringify(record, null, 2)}</pre>
        </div>
      )}
    </li>
  );
}

// The prompt as the detection record keeps it: every private value replaced by a placeholder.
function MaskedPrompt({ body }: { body: Record<string, unknown> }) {
  if (!("masked_prompt" in body)) return null; // written before the field existed
  const masked = body.masked_prompt;
  return typeof masked === "string" ? (
    <span className="audit-step-prompt">{masked}</span>
  ) : (
    <span className="audit-step-prompt audit-step-prompt-none">
      Prompt not kept: a detector failed, so it could not be masked.
    </span>
  );
}

function VerifyBanner({ report }: { report: VerifyReport }) {
  if (!report.ok) {
    const problems = [...report.chain_problems, ...report.replay_problems];
    return (
      <div className="banner banner-bad" role="alert">
        <strong>The log failed verification.</strong>
        <ul>
          {problems.map((problem, index) => (
            <li key={index}>
              Record {problem.seq ?? "?"}: {problem.reason}
            </li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <div className="banner banner-good" role="status">
      <strong>The log is intact.</strong> {report.records} records verified (hashes, links and
      signatures), and {report.decisions_replayed} decision
      {report.decisions_replayed === 1 ? "" : "s"} replayed from the recorded signals and policy.
      {report.head_hash && (
        <span className="mono head">
          {" "}
          Head: #{report.head_seq} {shortHash(report.head_hash, 16)}
        </span>
      )}
      {report.incomplete_requests.length > 0 && (
        <div>
          {report.incomplete_requests.length} interrupted request
          {report.incomplete_requests.length === 1 ? "" : "s"} (no outcome or error was recorded).
        </div>
      )}
    </div>
  );
}

function field(source: unknown, key: string): unknown {
  return typeof source === "object" && source !== null
    ? (source as Record<string, unknown>)[key]
    : undefined;
}

interface Summary {
  // What happened, in one or two words, so a column of them can be scanned.
  title: string;
  detail: string;
  // A class that colours the title: the decision's action, or "summary-bad" for a failure.
  tone: string;
  // Outcome reasons are machine codes, shown as written so they can be searched for.
  detailIsCode: boolean;
}

function labelFor(labels: Readonly<Record<string, string>>, key: string): string {
  return labels[key] ?? key;
}

function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

// "EMAIL_ADDRESS ×2, PERSON" from {"EMAIL_ADDRESS": 2, "PERSON": 1}.
function formatCounts(counts: unknown): string {
  if (typeof counts !== "object" || counts === null) return "";
  return Object.entries(counts as Record<string, number>)
    .map(([name, count]) => (count > 1 ? `${name} ×${count}` : name))
    .join(", ");
}

function summarize(record: AuditRecord): Summary {
  const body = record.body;
  if (record.event === "received") {
    const request = field(body, "request");
    const rejected = field(request, "rejected");
    if (rejected) {
      return { title: "Rejected", detail: String(rejected), tone: "summary-bad", detailIsCode: true };
    }
    const client = field(request, "client_id_claimed");
    const chars = Number(field(request, "prompt_chars"));
    return {
      title: "Prompt received",
      detail: [
        `${chars.toLocaleString()} characters`,
        client ? `from ${String(client)}` : "",
        field(request, "normalization_changed") ? "normalized" : "",
      ]
        .filter(Boolean)
        .join(", "),
      tone: "",
      detailIsCode: false,
    };
  }
  if (record.event === "detection") {
    const runs = field(body, "detectors");
    const failed = (Array.isArray(runs) ? runs : []).filter((run) => !field(run, "ok"));
    const findings = Number(field(body, "findings"));
    const took = formatDuration(Number(field(body, "duration_ms")));
    if (failed.length > 0) {
      return {
        title: failed.length === 1 ? "Detector failed" : `${failed.length} detectors failed`,
        detail: failed
          .map((run) => `${String(field(run, "name"))}: ${String(field(run, "error"))}`)
          .join(", "),
        tone: "summary-bad",
        detailIsCode: false,
      };
    }
    return findings === 0
      ? { title: "Nothing found", detail: `in ${took}`, tone: "", detailIsCode: false }
      : {
          title: `Found ${findings}`,
          detail: `${formatCounts(field(body, "by_entity"))}, in ${took}`,
          tone: "",
          detailIsCode: false,
        };
  }
  if (record.event === "model_call") {
    const model = field(body, "model");
    const inside = Boolean(field(model, "in_boundary"));
    const redaction = field(body, "redaction");
    return {
      title: inside ? "To sovereign model" : "To external model",
      detail: [
        `${String(field(model, "provider"))} ${String(field(model, "model"))}`,
        field(model, "stub") ? "stub" : "",
        redaction ? `${String(field(redaction, "spans"))} spans redacted` : "",
      ]
        .filter(Boolean)
        .join(", "),
      // Inside and outside keep their colours from the rest of the interface.
      tone: inside ? "action-route_sovereign" : "action-allow",
      detailIsCode: false,
    };
  }
  if (record.event === "error") {
    return {
      title: "Failed",
      detail: `${String(field(body, "stage"))}:${String(field(body, "error"))}`,
      tone: "summary-bad",
      detailIsCode: true,
    };
  }
  if (record.event === "policy_changed") {
    const policy = field(body, "policy");
    const version = `${String(field(policy, "id"))} v${String(field(policy, "version"))}`;
    return {
      title: "Changed",
      detail: `${version}: ${String(field(body, "note"))}`,
      tone: "",
      detailIsCode: false,
    };
  }
  if (record.event === "decision") {
    const decision = field(body, "decision");
    const action = String(field(decision, "action"));
    const label = String(field(field(body, "classification"), "label"));
    return {
      title: labelFor(ACTION_LABELS, action),
      detail: `by ${String(field(decision, "rule_id"))}, ${label.replaceAll("_", " ")}`,
      tone: `action-${action}`,
      detailIsCode: false,
    };
  }
  if (record.event === "outcome") {
    const status = String(field(body, "status"));
    const reason = field(body, "reason");
    const provider = field(field(body, "model"), "provider");
    return {
      title: labelFor(OUTCOME_TEXT, status),
      detail: reason ? String(reason) : provider ? `by ${String(provider)}` : "",
      tone: status === "completed" ? "" : "summary-bad",
      detailIsCode: Boolean(reason),
    };
  }
  if (record.event === "policy_loaded") {
    return field(body, "valid")
      ? {
          title: "Loaded",
          detail: `${String(field(body, "id"))} v${String(field(body, "version"))}`,
          tone: "",
          detailIsCode: false,
        }
      : {
          title: "Invalid",
          detail: String(field(body, "error")).replace(/^invalid policy:\s*/i, ""),
          tone: "summary-bad",
          detailIsCode: false,
        };
  }
  return { title: record.event, detail: "", tone: "", detailIsCode: false };
}

interface EntrySummary extends Summary {
  // What the request was found to hold: its label and finding types.
  evidence: string;
}

// One line for a whole request: how it ended, and on what evidence.
function summarizeEntry(entry: AuditEntry): EntrySummary {
  const find = (event: string) => entry.records.find((record) => record.event === event);
  const received = find("received");
  const decision = find("decision");
  if (!received && !decision) {
    // A policy record, which belongs to no request.
    return { ...summarize(entry.records[0]), evidence: "" };
  }
  const outcome = find("outcome");
  const failure = find("error");
  const evidence = describeEvidence(find("detection"), decision);
  // Records written before `received` existed keep the request in the decision.
  const rejected = field(field((received ?? decision)?.body, "request"), "rejected");
  if (rejected) {
    return {
      title: "Rejected",
      detail: String(rejected),
      tone: "summary-bad",
      detailIsCode: true,
      evidence: "",
    };
  }
  if (failure) {
    return {
      title: "Failed",
      detail: `${String(field(failure.body, "stage"))}:${String(field(failure.body, "error"))}`,
      tone: "summary-bad",
      detailIsCode: true,
      evidence,
    };
  }
  if (!decision) {
    return {
      title: "Received",
      detail: "no decision recorded yet",
      tone: "",
      detailIsCode: false,
      evidence,
    };
  }
  const verdict = field(decision.body, "decision");
  const action = String(field(verdict, "action"));
  const byAction = { title: labelFor(ACTION_LABELS, action), tone: `action-${action}`, evidence };
  if (!outcome) {
    return { ...byAction, detail: "no outcome recorded yet", detailIsCode: false };
  }
  const status = String(field(outcome.body, "status"));
  const reason = field(outcome.body, "reason");
  if (status === "completed") {
    const provider = String(field(field(outcome.body, "model"), "provider"));
    return { ...byAction, detail: `completed by ${provider}`, detailIsCode: false };
  }
  if (reason === "blocked_by_policy") {
    return { ...byAction, detail: `by ${String(field(verdict, "rule_id"))}`, detailIsCode: false };
  }
  // Blocked or failed for another reason than the policy's decision: the reason is the news.
  return {
    title: labelFor(OUTCOME_TEXT, status),
    detail: String(reason),
    tone: "summary-bad",
    detailIsCode: true,
    evidence,
  };
}

// "contains private data: EMAIL_ADDRESS, PERSON", from the detection and decision records.
function describeEvidence(detection?: AuditRecord, decision?: AuditRecord): string {
  const counts = field(detection?.body, "by_entity");
  // Records written before `detection` existed: the decision lists every finding.
  const findings = field(field(decision?.body, "signals"), "findings");
  const types =
    typeof counts === "object" && counts !== null
      ? Object.keys(counts)
      : [
          ...new Set(
            (Array.isArray(findings) ? findings : []).map((f) => String(field(f, "entity_type"))),
          ),
        ];
  const label = field(field(decision?.body, "classification"), "label");
  return [typeof label === "string" ? label.replaceAll("_", " ") : "", types.join(", ")]
    .filter(Boolean)
    .join(": ");
}
