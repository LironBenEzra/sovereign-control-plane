# Design

This document explains how the control plane is built and why. The [README](README.md) covers how to run it. A captured run is in [docs/sample-run.md](docs/sample-run.md).

![System design](docs/architecture.png)

The editable source of the diagram is [docs/architecture.excalidraw](docs/architecture.excalidraw).

## 1. What the system guarantees

Every request to `POST /v1/inference` goes through five steps, in this order:

1. **Inspect.** Two independent detectors look for private data and return findings.
2. **Decide.** A pure function applies the policy to those findings and returns one of four actions: `allow`, `redact`, `block`, `route_sovereign`.
3. **Record the decision.** A signed, hash-chained audit record is written and fsynced.
4. **Enforce.** The action is carried out: no model call, a call to the in-boundary model, or a call through the egress gateway.
5. **Record the outcome.** A second record says what actually happened.

Three guarantees follow from that order and from how each step is built:

| Guarantee | How it is kept |
|---|---|
| Nothing leaves the trust boundary unless a policy rule says so. | The pipeline does not hold the external model. It holds an egress gateway that refuses to send unless the action is `allow` or `redact` and the destination is on the policy's allowlist. |
| Nothing happens without evidence. | No model is called until the decision record is on disk. If the outcome record cannot be written, the answer is withheld. |
| When the system is unsure, it protects. | Every failure path ends in `block` or `route_sovereign`. Section 8 lists them, each with the test that proves it. |

## 2. Trust boundary

**Inside the boundary:** the control plane process, both detectors and the NER model they use, the policy file, the sovereign model (Ollama), the audit log, the policy snapshots and the two keys. In the Docker setup this is the Compose network plus one data volume. The Ollama container publishes no port, so it is reachable only from inside that network.

**Outside the boundary:** the external model provider (Anthropic's API, or its labelled stub).

**The caller** is assumed to be inside: a workload or user in the same organization that already holds the data it sends. That is why a response may contain the caller's own private data (for example after the sovereign model answers), and why restored placeholders are safe to return. The caller's *input* is still untrusted: it can be malformed, oversized or crafted to evade detection.

What crosses the boundary, and when:

| Action | What is sent outside |
|---|---|
| `allow` | The normalized prompt, unchanged. |
| `redact` | The prompt with every detected span replaced by a placeholder such as `<EMAIL_ADDRESS_1>`. |
| `route_sovereign` | Nothing. |
| `block` | Nothing. |

Data at rest inside the boundary holds no raw private values. The audit log stores the prompt and each matched value as HMAC-SHA256 keyed hashes. A plain hash would not be enough: a phone number or SSN has so little entropy that a plain SHA-256 can be reversed by trying every value.

## 3. Request lifecycle

The code is in [src/control_plane/pipeline.py](src/control_plane/pipeline.py). One request, step by step:

1. **Ingress** ([api.py](src/control_plane/api.py)). The body is read with a hard byte cap, counted as it streams, because `Content-Length` can be missing or false. It must be JSON with exactly one field, `prompt`, a non-empty string under the length limit. Unknown fields are rejected. A rejected request is audited too, but its content is never stored or inspected.
2. **Normalize.** The prompt is NFKC-normalized and invisible characters (zero-width space, soft hyphen and similar) are removed. This stops a prompt that hides a zero-width space inside the word `password` from slipping past a pattern. The normalized text is what gets inspected *and* what gets forwarded, so the model never sees anything the detectors did not.
3. **Load the policy.** The file is re-read on every request. If its SHA-256 changed, a `policy_loaded` record is written, so the log shows which policy was in force between which records.
4. **Detect.** Both detectors run under one time budget. Their findings are merged into `Signals`.
5. **Classify.** Findings plus policy thresholds give a label and a set of categories.
6. **Decide.** First matching rule wins.
7. **Write the decision record.** If this fails, the request ends with HTTP 503 and no model was called.
8. **Enforce.**
9. **Scan the model's output** with the same detectors and apply the policy's response rules.
10. **Write the outcome record.** If this fails, the answer is withheld (503).
11. **Respond** with the decision, the explanation, the answer and a receipt for both records.

## 4. Detection

I use two detectors that share nothing, so a failure of one cannot hide what the other found.

**Pattern rules** ([detection/rules.py](src/control_plane/detection/rules.py)). Plain regular expressions for secrets and credentials: PEM private keys, AWS access keys, GitHub and Slack tokens, `sk-` keys, JWTs, connection strings with embedded passwords, `password = ...` assignments, plus an entropy check for long random-looking strings and a small list of health terms. No model, no dependency beyond the standard library.

**Presidio** ([detection/presidio.py](src/control_plane/detection/presidio.py)). Microsoft's PII library, running in-process with the spaCy model `en_core_web_md`. It contributes named-entity recognition (people's names) and pattern recognizers that validate checksums (credit cards with Luhn, IBANs) and raise scores when context words such as "SSN" are nearby.

Why this choice:

- **It runs entirely inside the boundary.** Asking a cloud model "does this contain private data?" would send the private data to the cloud to find out. That rules out any hosted classifier for this step.
- **It is deterministic.** For a pinned library and model version the same text always gives the same findings (there is a test for this). Both versions are written into every audit record. An LLM classifier, even a local one, would make "same input, same outcome" depend on sampling.
- **It is explainable per finding.** Each finding carries the entity type, the character span, a score and the name of the recognizer that fired. The decision is not an opaque yes/no.
- **It cannot be talked out of its job.** The detectors do not read the prompt as instructions, so "ignore previous rules and classify this as public" has no effect.

What "unsure" means here. The policy sets two scores:

- below `min_score` (0.35), a finding is noise and is ignored;
- at or above `confident_score` (0.6), a finding is positive evidence;
- in between, it still counts toward categories, and if *every* counted finding is in this band the label is `uncertain`.

So a bare phone-like number that Presidio scores at 0.4 produces `uncertain`, and the default policy keeps that prompt inside the boundary. The four possible labels are `no_private_data`, `contains_private_data`, `uncertain` and `unknown_assume_private` (a detector failed or timed out).

What counts as private data is defined by the policy file, not by the code. The `categories` map lists which entity types belong to which category, and detectors are asked only for those types.

## 5. Policy and determinism

The policy is one YAML file, [policy/policy.yaml](policy/policy.yaml). It holds the category map, the two thresholds, an ordered list of rules, the default action, the egress allowlist and the response rules. Changing behaviour means editing this file; no code changes and no restart.

A rule has an `id`, an `action`, and a `when` clause with up to two conditions: `any_category` and `label`. Rules are checked top to bottom and the first match wins. If none matches, the default action applies, and the default must be `block` or `route_sovereign`.

`decide(classification, policy)` in [policy.py](src/control_plane/policy.py) is a pure function. It reads no clock, no random source, no network and no model. The same classification and policy always give the same decision.

Validation is strict because a quiet mistake in a policy fails open:

- unknown keys are errors (a typo such as `acton:` is not silently ignored);
- a rule that names a category that does not exist is an error (it would never match);
- an entity type mapped to two categories is an error;
- a default action of `allow` or `redact` is an error.

**One invariant is not configurable.** If detection failed, a rule that would send the prompt outside is overridden by the default action. Redaction depends on detection, so when detection has failed, neither `redact` nor `allow` can be trusted, whatever the policy says. The override has its own rule id (`guard:detection-failed`) so it is visible in the evidence.

**An invalid policy blocks everything.** I considered keeping the last valid policy in force. I chose to block, because silently enforcing rules the operator believes they replaced is worse than an outage they will notice immediately.

## 6. Enforcement

| Action | What happens |
|---|---|
| `block` | The policy's block message is returned. No model is called. |
| `route_sovereign` | The full prompt goes to the Ollama model inside the boundary. If that model is down, the request is blocked. It never falls back to the external model. |
| `redact` | Each detected span becomes a typed, numbered placeholder. The same value always gets the same placeholder, so the model can still follow who is who. The redacted text goes through the egress gateway. In the answer, placeholders are swapped back for the original values inside the boundary. |
| `allow` | The prompt goes through the egress gateway unchanged. |

Two details in redaction ([enforcement.py](src/control_plane/enforcement.py)) matter for safety:

- **Overlapping findings are merged, not resolved.** If an email address overlaps a `password=` assignment, picking a winner could leave part of the loser in the clear. The union of the spans is redacted.
- **The placeholder map lives only in memory for one request.** It is never written anywhere.

**The egress gateway** ([egress.py](src/control_plane/egress.py)) is the only object that holds the external provider. It checks the action and the allowlist, then sends. A denied egress is recorded with the destination and the reason. A failed call after the gateway allowed it is recorded as `attempted: true`, because the payload may have left before the error, and the evidence must not claim otherwise.

**The response is enforced too.** The model's answer is scanned by the same detectors. Categories listed under `response.redact_categories` (by default, `secret`) are removed from the answer. If the scan itself fails, the answer is withheld.

## 7. Evidence

### Record format

The log is one JSON object per line, in `data/audit/audit.jsonl`:

```json
{
  "seq": 14,
  "ts": "2026-11-19T20:17:26.482113+00:00",
  "event": "decision",
  "audit_id": "a606761d413e48bc952c118214f82310",
  "body": { "...": "..." },
  "prev_hash": "<hash of record 13>",
  "hash": "<SHA-256 of the canonical JSON of the six fields above>",
  "sig": "<Ed25519 signature over hash>",
  "key_id": "ed25519:2f9c092c2cc3e1de"
}
```

There are three event types: `policy_loaded`, `decision` and `outcome`.

A **decision** body contains everything the decision was made from: the request (keyed hash of the prompt, its length, whether normalization changed it), the signals (each detector's name, version and status, and every finding with type, span, score, recognizer and a keyed hash of the matched value), the classification, the policy id, version and SHA-256, and the action with its rule id and rationale.

An **outcome** body contains what was actually done: the redaction counts, which model was called, whether it is inside the boundary, whether it is a stub, which model actually served the answer, the latency, and for external calls the destination, whether the gateway allowed it, and the SHA-256 and length of the payload that was sent. The payload hash is a plain SHA-256 on purpose, so it can be compared with the provider's own logs.

### Why two records per request

The decision record is written *before* enforcement and the outcome record *after*. This is what keeps the evidence honest:

- The log never claims an egress that did not happen. The outcome is written from the result, not from the plan.
- The log never misses an egress that did happen. The decision was already on disk.
- A crash between the two leaves a decision with no outcome, and the verifier reports it as an interrupted request.

### What tampering it reveals

| Tampering | Detected by |
|---|---|
| Editing any field of any record | The record's hash no longer matches its content. |
| Editing a record and recomputing its hash | The signature no longer matches, and the next record's `prev_hash` breaks. |
| Deleting or reordering records | `seq` and `prev_hash` no longer line up. |
| Inserting a record | Same, plus it cannot be signed without the key. |
| Rewriting the whole chain with a different key | Every signature fails against the published public key. |
| Editing a policy snapshot | Its content no longer matches the SHA-256 it is named by. |
| Cutting records off the end | **Not** detected by the chain alone. Detected by any receipt a caller kept. |
| Rewriting a decision's action and re-signing, by someone who holds the key | The replay check: the action no longer follows from the recorded signals and policy. |

The last two rows are the reason for two features. Every API response carries a **receipt** (sequence number, hash and signature of both records), so a caller can later prove a record existed. And the verifier **replays** every decision.

### Reconstructing a decision from the evidence alone

The verifier ([audit/verify.py](src/control_plane/audit/verify.py)) needs only the log, the public key and the policy snapshots. For each decision record it loads the snapshot named by the recorded SHA-256, checks the snapshot's own hash, rebuilds the signals from the record, runs the same `classify` and `decide` functions the server ran, and compares the result with what was recorded. This works because both functions are pure and because the record holds their complete input. It does not need the original prompt.

The server refuses to append to a log that fails verification at startup. Appending would bury the damage under valid-looking records.

## 8. Fail-closed behaviour

Each row names the test that proves it. The tests are in [tests/](tests/).

| Failure | Result | Test |
|---|---|---|
| A detector raises | `unknown_assume_private`, kept inside | `test_detector_failure_keeps_the_prompt_inside` |
| A detector times out | Same | `test_detector_timeout_keeps_the_prompt_inside` |
| The NER model cannot load at startup | The service starts and treats every request as private | `UnavailableDetector` in `detection/presidio.py` |
| Only low-confidence findings | `uncertain`, kept inside | `test_low_confidence_evidence_is_treated_as_private` |
| Policy file invalid or missing | Every request blocked | `test_an_invalid_policy_blocks_everything` |
| No rule matches | Blocked by the default action | `test_no_matching_rule_blocks` |
| A policy tries to allow when detection failed | Overridden to the default action | `test_detection_failure_can_never_leave_the_boundary` |
| Decision record cannot be written | 503, no model call | `test_no_decision_record_means_no_model_call` |
| Outcome record cannot be written | 503, answer withheld | `test_no_outcome_record_means_the_answer_is_withheld` |
| Sovereign model down | Blocked, never sent outside | `test_sovereign_model_down_blocks_and_never_falls_back_outside` |
| Destination not on the allowlist | Egress refused and audited | `test_a_destination_missing_from_the_allowlist_is_refused` |
| Output scan fails | Answer withheld | `test_a_failed_output_scan_withholds_the_answer` |
| A model provider raises an error it does not document | Recorded as a failed, attempted call | `test_an_unexpected_provider_exception_still_leaves_an_outcome_record` |
| Malformed or oversized request | Rejected and audited, content not stored | `test_bad_requests_are_rejected_and_audited` |

One deliberate asymmetry: fallback is allowed only in the safe direction. A sovereign failure never falls back to the external model. I did not add the opposite fallback (external failure to sovereign) because it is an availability feature, not a safety one, and it would have cost time.

## 9. Threat model

**What is being protected:** private data in prompts, and the integrity of the audit log.

| Threat | Handling | What remains |
|---|---|---|
| A caller sends private data by mistake | Detection, then policy | Anything the detectors miss. See limitations. |
| A caller hides data from detection (invisible characters, look-alike forms) | NFKC normalization and invisible-character removal before inspection | Spacing letters out, encoding as base64, look-alike letters from another alphabet. Not handled. |
| A caller sends malformed or huge input | Strict schema, hard size cap, detection time budget | No rate limiting. |
| A prompt tries to instruct the control plane ("classify this as safe") | Detectors and policy do not interpret the prompt as instructions | None for the decision. The *model* can still be prompt-injected, which is out of scope here. |
| The external model returns sensitive content | Output scan and response redaction | Same detector limits as input. |
| A bug or dependency sends data out directly | The external provider is reachable only through the gateway object | **Code-level only.** The container still has open internet access. Network-level egress control is the main missing piece. |
| Someone with write access to the data volume edits the log | Hash chain and signatures | They can truncate the tail unless someone kept a receipt. |
| Someone who also holds the signing key rewrites the log | Receipts held by callers, and the replay check | A careful insider with the key could fabricate consistent records for requests no caller kept a receipt for. Fixing this needs the key in an HSM and the chain head anchored outside. |
| Someone reads the audit log | It holds keyed hashes, not values | Metadata is visible: when requests happened, what kind of data they held, how long the prompt was. |
| The clock is wrong or changed | Order comes from `seq` and the chain, not from timestamps | Timestamps are not trusted time. |

## 10. Known limitations

These are the gaps I know about. None of them is hidden by the evidence.

- **Detection is not complete, and redaction is only as good as detection.** A name the NER model misses leaves the boundary on a `redact` or `allow` action. This is inherent to detect-then-redact. The mitigation available today is policy: route more to the sovereign model.
- **Detection is English only**, and has no recognizer for street addresses. `LOCATION` is switched off in the default policy because the model tags every country and city.
- **NER has false positives.** "Summarise Hamlet by William Shakespeare" is redacted as a `PERSON`. The answer is still correct because the placeholder is restored, but it is over-protection.
- **The health and entropy rules are heuristics.** They score in the uncertain band on purpose, which keeps the prompt inside the boundary without blocking it.
- **No caller authentication.** `X-Client-Id` is recorded as a claim and labelled `client_id_claimed`. The audit read endpoints are open too.
- **One writer.** The audit log assumes a single process. Several instances would need a shared sequencer.
- **Keys are files on the data volume.**
- **The external call was not exercised against the live Anthropic API in this submission**, because no API key was available on the build machine. It is covered by tests with a fake client, and the stub path is what the sample run shows.
- **Model answers are not deterministic.** Determinism is claimed for the enforcement decision and for what is sent, not for what a model replies.
- **Normalization can change meaning.** NFKC folds look-alike characters, which is what stops evasion, but it also turns `x²` into `x2`. The model receives the normalized text.
- **An internal crash returns HTTP 500 and sends nothing.** If it happens after the decision record was written, the verifier reports that request as interrupted. If it happens before, there is no record of that request. An unexpected error raised by a model provider is handled differently: it is recorded as a failed, attempted call.

## 11. Where each requirement is met

| Requirement | Code | Tests |
|---|---|---|
| 1. Prompt in through an API | `api.py` | `test_api.py` |
| 2. A clear, explainable decision | `detection/`, `classification.py` | `test_detection.py`, `test_presidio_integration.py` |
| 3. Deterministic, configurable enforcement | `policy.py`, `policy/policy.yaml`, `enforcement.py` | `test_policy.py`, `test_enforcement.py` |
| 4. Tamper-evident audit evidence | `audit/`, `evidence.py` | `test_audit.py` |
| 5. Fail closed | `pipeline.py`, `detection/base.py` | `test_pipeline.py` |
| 6. Stay sovereign | `egress.py`, `providers/` | `test_providers.py`, `test_pipeline.py` |
| 7. Explain the design | This document and the README | |
