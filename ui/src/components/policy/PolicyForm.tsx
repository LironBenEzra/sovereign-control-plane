import { type ReactNode, useState } from "react";
import { ACTION_LABELS, LABEL_TEXT, categoryTone } from "../../text";
import type { Action, Label, PolicyDocument, PolicyInfo, PolicyRule } from "../../types";

type Catalog = PolicyInfo["catalog"];

interface Props {
  document: PolicyDocument;
  catalog: Catalog;
  // Null shows the policy. A function makes every section editable and receives each edit.
  onChange: ((next: PolicyDocument) => void) | null;
}

const ACTION_HINTS: Record<Action, string> = {
  allow: "send it out unchanged",
  redact: "send it out with private values replaced by placeholders",
  block: "call no model",
  route_sovereign: "answer it with the model inside the boundary",
};

// Mirrors the server's check (RuleId in src/control_plane/policy.py), so a typo is
// explained next to the field instead of only after a round trip.
const RULE_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const CATEGORY_NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** Problems the form can see by itself: the server checks everything again on save. */
export function ruleIdProblems(rules: PolicyRule[]): Map<number, string> {
  const problems = new Map<number, string>();
  rules.forEach((rule, index) => {
    if (!RULE_ID.test(rule.id)) {
      problems.set(index, "Use lowercase letters, digits and hyphens, starting with a letter or digit.");
    } else if (rule.id === "default") {
      problems.set(index, "“default” names the default action. Choose another id.");
    } else if (rules.findIndex((other) => other.id === rule.id) !== index) {
      problems.set(index, "Another rule already has this id.");
    }
  });
  return problems;
}

export function PolicyForm({ document, catalog, onChange }: Props) {
  const set = onChange ? (patch: Partial<PolicyDocument>) => onChange({ ...document, ...patch }) : null;
  return (
    <>
      {set && <AboutSection document={document} set={set} />}
      <RulesSection document={document} catalog={catalog} set={set} />
      <CategoriesSection document={document} catalog={catalog} set={set} />
      <div className="policy-pair">
        <DetectionSection document={document} set={set} />
        <DefaultSection document={document} set={set} />
      </div>
      <div className="policy-pair">
        <EgressSection document={document} catalog={catalog} set={set} />
        <AnswersSection document={document} set={set} />
      </div>
    </>
  );
}

type Setter = ((patch: Partial<PolicyDocument>) => void) | null;

function Section({
  title,
  hint,
  actions,
  children,
}: {
  title: string;
  hint: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="sheet policy-section">
      <header className="section-head">
        <div>
          <h2>{title}</h2>
          <p className="hint">{hint}</p>
        </div>
        {actions}
      </header>
      {children}
    </section>
  );
}

function Toggle({
  pressed,
  onToggle,
  tone,
  children,
}: {
  pressed: boolean;
  onToggle: () => void;
  tone?: string;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      className={`toggle ${tone ?? ""}`}
      aria-pressed={pressed}
      onClick={onToggle}
    >
      {children}
    </button>
  );
}

function toggled<T>(list: T[], item: T): T[] {
  return list.includes(item) ? list.filter((other) => other !== item) : [...list, item];
}

// ------------------------------------------------------------------ about

function AboutSection({ document, set }: { document: PolicyDocument; set: Exclude<Setter, null> }) {
  return (
    <Section
      title="About this policy"
      hint="The name and version are written into every decision record, so give each saved change its own version."
    >
      <div className="field-row">
        <label className="field">
          <span className="field-label">Name</span>
          <input
            className="mono"
            value={document.id}
            maxLength={64}
            onChange={(event) => set({ id: event.target.value })}
          />
        </label>
        <label className="field field-narrow">
          <span className="field-label">Version</span>
          <input
            className="mono"
            value={document.version}
            maxLength={32}
            onChange={(event) => set({ version: event.target.value })}
          />
        </label>
      </div>
      <label className="field">
        <span className="field-label">Description</span>
        <input
          value={document.description}
          maxLength={500}
          onChange={(event) => set({ description: event.target.value })}
        />
      </label>
    </Section>
  );
}

// ------------------------------------------------------------------ rules

function describeCondition(rule: PolicyRule): string {
  const { any_category: categories, label: labels } = rule.when;
  const parts: string[] = [];
  if (categories.length > 0) parts.push(`a prompt with ${categories.join(" or ")} data`);
  if (labels.length > 0) {
    const text = labels.map((label) => LABEL_TEXT[label].toLowerCase()).join(" or ");
    parts.push(`${parts.length > 0 ? "labelled" : "a prompt labelled"} ${text}`);
  }
  return parts.length > 0 ? `Matches ${parts.join(", ")}.` : "Matches every prompt.";
}

function RulesSection({
  document,
  catalog,
  set,
}: {
  document: PolicyDocument;
  catalog: Catalog;
  set: Setter;
}) {
  const rules = document.rules;
  const problems = ruleIdProblems(rules);

  function update(index: number, rule: PolicyRule) {
    set?.({ rules: rules.map((other, i) => (i === index ? rule : other)) });
  }

  function move(index: number, by: number) {
    const next = [...rules];
    const [rule] = next.splice(index, 1);
    if (rule) next.splice(index + by, 0, rule);
    set?.({ rules: next });
  }

  function add() {
    let n = 1;
    while (rules.some((rule) => rule.id === `new-rule-${n}`)) n += 1;
    // At the top, where it is seen. With no condition yet it matches everything, and the
    // form says so until one is chosen.
    const rule: PolicyRule = {
      id: `new-rule-${n}`,
      description: "",
      when: { any_category: [], label: [] },
      action: "block",
    };
    set?.({ rules: [rule, ...rules] });
  }

  return (
    <Section
      title="Rules"
      hint="Checked from the top. The first rule that matches a prompt decides what happens to it."
      actions={
        set && (
          <button type="button" className="secondary" onClick={add}>
            Add a rule
          </button>
        )
      }
    >
      <ol className="rules">
        {rules.map((rule, index) => (
          <li key={index} className={set ? "rule rule-editing" : "rule"}>
            <span className="rule-number" aria-hidden="true">
              {index + 1}
            </span>
            {set ? (
              <RuleEditor
                rule={rule}
                index={index}
                count={rules.length}
                categories={Object.keys(document.categories)}
                labels={catalog.labels}
                actions={catalog.actions}
                idProblem={problems.get(index)}
                onChange={(next) => update(index, next)}
                onMove={(by) => move(index, by)}
                onRemove={() => set({ rules: rules.filter((_, i) => i !== index) })}
              />
            ) : (
              <div className="rule-body">
                <div className="rule-head">
                  <code className="rule-id">{rule.id}</code>
                  <span className={`chip act-${rule.action}`}>{ACTION_LABELS[rule.action]}</span>
                </div>
                {rule.description && <p>{rule.description}</p>}
                <p className="hint">{describeCondition(rule)}</p>
              </div>
            )}
          </li>
        ))}
      </ol>
      {rules.length === 0 && (
        <p className="hint">No rules: every prompt gets the default action below.</p>
      )}
    </Section>
  );
}

function RuleEditor({
  rule,
  index,
  count,
  categories,
  labels,
  actions,
  idProblem,
  onChange,
  onMove,
  onRemove,
}: {
  rule: PolicyRule;
  index: number;
  count: number;
  categories: string[];
  labels: Label[];
  actions: Action[];
  idProblem: string | undefined;
  onChange: (rule: PolicyRule) => void;
  onMove: (by: number) => void;
  onRemove: () => void;
}) {
  const unconditional = rule.when.any_category.length === 0 && rule.when.label.length === 0;
  const name = rule.id || `rule ${index + 1}`;
  return (
    <div className="rule-body">
      <div className="field-row">
        <label className="field">
          <span className="field-label">Rule id</span>
          <input
            className="mono"
            value={rule.id}
            maxLength={64}
            spellCheck={false}
            aria-invalid={idProblem !== undefined}
            onChange={(event) => onChange({ ...rule, id: event.target.value })}
          />
        </label>
        <label className="field">
          <span className="field-label">Action</span>
          <select
            value={rule.action}
            onChange={(event) => onChange({ ...rule, action: event.target.value as Action })}
          >
            {actions.map((action) => (
              <option key={action} value={action}>
                {ACTION_LABELS[action]}: {ACTION_HINTS[action]}
              </option>
            ))}
          </select>
        </label>
        <div className="rule-tools">
          <button
            type="button"
            className="secondary small"
            disabled={index === 0}
            aria-label={`Move ${name} up`}
            onClick={() => onMove(-1)}
          >
            Move up
          </button>
          <button
            type="button"
            className="secondary small"
            disabled={index === count - 1}
            aria-label={`Move ${name} down`}
            onClick={() => onMove(1)}
          >
            Move down
          </button>
          <button
            type="button"
            className="secondary small danger"
            aria-label={`Remove ${name}`}
            onClick={onRemove}
          >
            Remove
          </button>
        </div>
      </div>
      {idProblem && <p className="hint-bad">{idProblem}</p>}
      <label className="field">
        <span className="field-label">Description, shown as the reason for each decision</span>
        <input
          value={rule.description}
          maxLength={500}
          onChange={(event) => onChange({ ...rule, description: event.target.value })}
        />
      </label>
      <fieldset className="toggles">
        <legend className="field-label">Matches a prompt with any of these categories</legend>
        {categories.map((category) => (
          <Toggle
            key={category}
            tone={`tone-${categoryTone(category)}`}
            pressed={rule.when.any_category.includes(category)}
            onToggle={() =>
              onChange({
                ...rule,
                when: { ...rule.when, any_category: toggled(rule.when.any_category, category) },
              })
            }
          >
            {category}
          </Toggle>
        ))}
      </fieldset>
      <fieldset className="toggles">
        <legend className="field-label">
          {rule.when.any_category.length > 0 ? "and" : "or"} labelled any of
        </legend>
        {labels.map((label) => (
          <Toggle
            key={label}
            pressed={rule.when.label.includes(label)}
            onToggle={() =>
              onChange({ ...rule, when: { ...rule.when, label: toggled(rule.when.label, label) } })
            }
          >
            {LABEL_TEXT[label]}
          </Toggle>
        ))}
      </fieldset>
      {unconditional ? (
        <p className="hint-bad">
          With no category and no label, this rule matches every prompt, so the rules below it
          are never reached.
        </p>
      ) : (
        <p className="hint">{describeCondition(rule)}</p>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ categories

function CategoriesSection({
  document,
  catalog,
  set,
}: {
  document: PolicyDocument;
  catalog: Catalog;
  set: Setter;
}) {
  const [newName, setNewName] = useState("");
  const categories = Object.entries(document.categories);
  const assigned = new Set(categories.flatMap(([, types]) => types));
  const available = Object.keys(catalog.entity_types).filter((type) => !assigned.has(type));

  function usedBy(category: string): string[] {
    const rules = document.rules
      .filter((rule) => rule.when.any_category.includes(category))
      .map((rule) => rule.id);
    return document.response.redact_categories.includes(category)
      ? [...rules, "removed from answers"]
      : rules;
  }

  function setTypes(category: string, types: string[]) {
    set?.({ categories: { ...document.categories, [category]: types } });
  }

  const nameProblem =
    newName === ""
      ? null
      : !CATEGORY_NAME.test(newName)
        ? "Use lowercase letters, digits and underscores, starting with a letter."
        : newName in document.categories
          ? "That category already exists."
          : null;

  return (
    <Section
      title="What counts as private data"
      hint="Each category groups the entity types the detectors look for. A type in no category is not looked for at all, and rules refer to categories."
    >
      <div className="table-wrap">
        <table className="categories">
          <thead>
            <tr>
              <th>Category</th>
              <th>Entity types</th>
              <th>Used by</th>
            </tr>
          </thead>
          <tbody>
            {categories.map(([category, types]) => {
              const users = usedBy(category);
              return (
                <tr key={category}>
                  <td>
                    <span className={`chip tone-${categoryTone(category)}`}>{category}</span>
                  </td>
                  <td>
                    <div className="chips">
                      {types.map((type) => {
                        const detectors = catalog.entity_types[type];
                        return (
                          <span
                            key={type}
                            className={detectors ? "chip type-chip" : "chip type-chip chip-warn"}
                            title={
                              detectors
                                ? `Found by ${detectors.join(" and ")}`
                                : "No running detector looks for this type"
                            }
                          >
                            {type}
                            {set && (
                              <button
                                type="button"
                                className="chip-remove"
                                aria-label={`Remove ${type} from ${category}`}
                                onClick={() => setTypes(category, types.filter((t) => t !== type))}
                              >
                                ×
                              </button>
                            )}
                          </span>
                        );
                      })}
                      {types.length === 0 && <span className="hint">None: nothing is looked for.</span>}
                      {set && available.length > 0 && (
                        <select
                          className="add-type"
                          value=""
                          aria-label={`Add an entity type to ${category}`}
                          onChange={(event) => setTypes(category, [...types, event.target.value])}
                        >
                          <option value="">Add a type…</option>
                          {available.map((type) => (
                            <option key={type} value={type}>
                              {type} ({catalog.entity_types[type]?.join(", ")})
                            </option>
                          ))}
                        </select>
                      )}
                    </div>
                  </td>
                  <td className="used-by">
                    {users.length > 0 ? users.join(", ") : <span className="hint">Nothing</span>}
                    {set && users.length === 0 && (
                      <button
                        type="button"
                        className="link remove-category"
                        onClick={() => {
                          const { [category]: _removed, ...rest } = document.categories;
                          set({ categories: rest });
                        }}
                      >
                        Remove category
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {set && (
        <form
          className="add-category"
          onSubmit={(event) => {
            event.preventDefault();
            if (newName === "" || nameProblem) return;
            set({ categories: { ...document.categories, [newName]: [] } });
            setNewName("");
          }}
        >
          <label className="field">
            <span className="field-label">New category</span>
            <input
              className="mono"
              value={newName}
              placeholder="customer_data"
              spellCheck={false}
              onChange={(event) => setNewName(event.target.value.trim())}
            />
          </label>
          <button type="submit" className="secondary" disabled={newName === "" || nameProblem !== null}>
            Add category
          </button>
          {nameProblem && <p className="hint-bad">{nameProblem}</p>}
        </form>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ small sections

function DetectionSection({ document, set }: { document: PolicyDocument; set: Setter }) {
  const { min_score: minScore, confident_score: confident } = document.detection;
  const field = (name: "min_score" | "confident_score", value: number, label: string, hint: string) => (
    <div className="threshold">
      <dt>{label}</dt>
      <dd>
        {set ? (
          <input
            type="number"
            min={0}
            max={1}
            step={0.05}
            value={value}
            aria-label={label}
            onChange={(event) =>
              set({ detection: { ...document.detection, [name]: Number(event.target.value) } })
            }
          />
        ) : (
          <strong>{value}</strong>
        )}
        <span className="hint">{hint}</span>
      </dd>
    </div>
  );
  return (
    <Section title="Detection thresholds" hint="How sure a detector must be. Scores run from 0 to 1.">
      <dl className="thresholds">
        {field("min_score", minScore, "Minimum score", "Findings below it are ignored as noise.")}
        {field(
          "confident_score",
          confident,
          "Confident score",
          "If every finding is below it, the prompt is labelled uncertain.",
        )}
      </dl>
    </Section>
  );
}

function DefaultSection({ document, set }: { document: PolicyDocument; set: Setter }) {
  const options: Action[] = ["block", "route_sovereign"];
  return (
    <Section
      title="When no rule matches"
      hint="The prompt must stay inside: it is either blocked or answered inside the boundary."
    >
      {set ? (
        <fieldset className="choices">
          <legend className="sr-only">Default action</legend>
          {options.map((action) => (
            <label key={action} className="choice">
              <input
                type="radio"
                name="default-action"
                checked={document.default_action === action}
                onChange={() => set({ default_action: action })}
              />
              <span>
                <strong>{ACTION_LABELS[action]}</strong>
                <span className="hint"> {ACTION_HINTS[action]}</span>
              </span>
            </label>
          ))}
        </fieldset>
      ) : (
        <p>
          <span className={`chip act-${document.default_action}`}>
            {ACTION_LABELS[document.default_action]}
          </span>{" "}
          <span className="hint">{ACTION_HINTS[document.default_action]}</span>
        </p>
      )}
    </Section>
  );
}

function EgressSection({
  document,
  catalog,
  set,
}: {
  document: PolicyDocument;
  catalog: Catalog;
  set: Setter;
}) {
  const allowed = document.egress.allowed_destinations;
  const destinations = [...new Set([...catalog.destinations, ...allowed])].sort();
  return (
    <Section
      title="Sending outside the boundary"
      hint="A prompt leaves only when a rule allows or redacts it, and only to a destination listed here."
    >
      {set ? (
        <fieldset className="choices">
          <legend className="sr-only">Allowed destinations</legend>
          {destinations.map((name) => (
            <label key={name} className="choice">
              <input
                type="checkbox"
                checked={allowed.includes(name)}
                onChange={() =>
                  set({ egress: { allowed_destinations: toggled(allowed, name) } })
                }
              />
              <code>{name}</code>
            </label>
          ))}
        </fieldset>
      ) : allowed.length > 0 ? (
        <div className="chips">
          {allowed.map((name) => (
            <span key={name} className="chip chip-outside">
              {name}
            </span>
          ))}
        </div>
      ) : (
        <p>None: nothing leaves the boundary.</p>
      )}
      {set && allowed.length === 0 && (
        <p className="hint">With none listed, nothing leaves the boundary.</p>
      )}
    </Section>
  );
}

function AnswersSection({ document, set }: { document: PolicyDocument; set: Setter }) {
  const response = document.response;
  const categories = Object.keys(document.categories);
  return (
    <Section title="Answers" hint="What is done to a model's answer before the caller gets it.">
      <span className="field-label">Removed from every answer</span>
      {set ? (
        <div className="toggles">
          {categories.map((category) => (
            <Toggle
              key={category}
              tone={`tone-${categoryTone(category)}`}
              pressed={response.redact_categories.includes(category)}
              onToggle={() =>
                set({
                  response: {
                    ...response,
                    redact_categories: toggled(response.redact_categories, category),
                  },
                })
              }
            >
              {category}
            </Toggle>
          ))}
        </div>
      ) : (
        <p>{response.redact_categories.join(", ") || "Nothing"}</p>
      )}
      {set ? (
        <label className="choice">
          <input
            type="checkbox"
            checked={response.restore_placeholders}
            onChange={(event) =>
              set({ response: { ...response, restore_placeholders: event.target.checked } })
            }
          />
          <span>After a redaction, put the original values back into the answer, inside the boundary</span>
        </label>
      ) : (
        <p>
          {response.restore_placeholders
            ? "After a redaction, the original values are put back into the answer, inside the boundary."
            : "After a redaction, the answer keeps the placeholders."}
        </p>
      )}
      <span className="field-label">Message for a blocked prompt</span>
      {set ? (
        <textarea
          rows={2}
          value={document.block_message}
          maxLength={1000}
          aria-label="Message for a blocked prompt"
          onChange={(event) => set({ block_message: event.target.value })}
        />
      ) : (
        <p>{document.block_message}</p>
      )}
    </Section>
  );
}
