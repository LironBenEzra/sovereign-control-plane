# Sovereign Control Plane

A control plane that sits in front of AI models and enforces policy on private data. It receives a prompt over an API, decides whether the prompt contains private data, enforces the matching policy rule (allow, redact, block, or route to an in-boundary model), and writes tamper-evident evidence for every decision.

![System design](docs/architecture.png)

- **[DESIGN.md](DESIGN.md)** explains the system design, the trust boundary, the threat model and the reasoning behind each decision.
- **[docs/sample-run.md](docs/sample-run.md)** is a captured run: six requests, each with its enforcement outcome and audit evidence.
- **[docs/architecture.excalidraw](docs/architecture.excalidraw)** is the editable diagram.

## Run it

Prerequisite: Docker with Compose v2.

```bash
docker compose up --build
```

Then open **http://localhost:8000**. That one command starts:

| Service | What it is |
|---|---|
| `control-plane` | The API and the web UI, on port 8000. |
| `ollama` | The sovereign (in-boundary) model server. No port is published. |
| `ollama-pull` | Pulls the sovereign model once (`llama3.2:1b`, about 1.3 GB), then exits. |

The first run builds the image and downloads the model, so it takes a few minutes. The UI header shows `Sovereign model … (not ready)` until the pull finishes. During that time, a request that must stay inside the boundary is **blocked**, not sent elsewhere. That is the fail-closed behaviour working, not a fault.

### API keys and environment variables

No key is needed. Without one, the external model is a stub, and every audit record says so (`"stub": true`).

To use the real Anthropic API as the external model, copy `.env.example` to `.env` and set the key:

```bash
cp .env.example .env
# then edit .env:  ANTHROPIC_API_KEY=sk-ant-...
```

| Variable | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | empty | Enables the real external model. |
| `SCP_EXTERNAL_MODEL` | `claude-opus-5-5` | External model id. |
| `SCP_SOVEREIGN_MODEL` | `llama3.2:1b` | Any model Ollama can pull. |
| `SCP_SOVEREIGN_PROVIDER` | `ollama` | Set to `stub` to run without Ollama. |

### Try it

**In the browser.** The Playground tab has five sample prompts. Each result shows the four steps: what was found and why, which rule matched, exactly what the model received, and the audit receipt. The Audit log tab lists the evidence and has a "Verify chain" button. The Policy tab shows the active rules.

| Playground: a prompt with contact PII is redacted | Audit log: every decision and outcome, with fail-closed cases |
|---|---|
| ![Playground](docs/ui-playground.png) | ![Audit log](docs/ui-audit.png) |

**From the command line.** The demo script needs only Python 3:

```bash
python3 scripts/demo.py     # six requests, each with its response and audit evidence
make verify                 # verify the chain and replay every decision
make tamper-demo            # edit a copy of the log and watch verification fail
```

**With curl:**

```bash
curl -s localhost:8000/v1/inference \
  -H 'content-type: application/json' \
  -d '{"prompt": "Write a short reply to Dana Levi at dana.levi@example.com."}'
```

The real response to that command, with hashes shortened and a few fields left out:

```json
{
  "audit_id": "159207a76e1346678afb4702fb3b21e6",
  "decision": {
    "action": "redact",
    "rule_id": "redact-pii",
    "rationale": "Personal data is replaced with placeholders before the prompt leaves the boundary.",
    "fail_closed": false
  },
  "classification": {
    "label": "contains_private_data",
    "categories": [
      "pii"
    ],
    "rationale": "Found 2 finding(s): EMAIL_ADDRESS x1, PERSON x1.",
    "findings": [
      {
        "entity_type": "PERSON",
        "category": "pii",
        "start": 23,
        "end": 32,
        "score": 0.85,
        "recognizer": "SpacyRecognizer"
      },
      {
        "entity_type": "EMAIL_ADDRESS",
        "category": "pii",
        "start": 36,
        "end": 57,
        "score": 1.0,
        "recognizer": "EmailRecognizer"
      }
    ]
  },
  "policy": {
    "id": "default-sovereign-policy",
    "version": "1.0.0",
    "sha256": "ba46e14e428eff1a..."
  },
  "outcome": "completed",
  "model": {
    "provider": "stub-external",
    "model": "stub-echo",
    "in_boundary": false,
    "stub": true
  },
  "forwarded_prompt": "Write a short reply to <PERSON_1> at <EMAIL_ADDRESS_1>.",
  "response": "[stub-external: no real model was called] I received: Write a short reply to Dana Levi at dana.levi@example.com.",
  "receipts": {
    "decision": {
      "seq": 26,
      "hash": "85fa02eaf101a29e...",
      "key_id": "ed25519:91a2fa3c6452f577"
    },
    "outcome": {
      "seq": 27,
      "hash": "bde2fe53aaa99edb...",
      "key_id": "ed25519:91a2fa3c6452f577"
    }
  }
}
```

`forwarded_prompt` is exactly what left the boundary. `response` is what the caller gets back, with the placeholders restored inside the boundary. (The external model here is the stub, which echoes what it received.)

### Change the policy

Rules live in one file, [policy/policy.yaml](policy/policy.yaml), mounted into the container. It is re-read on every request, so an edit takes effect immediately with no restart. Two edits worth trying:

- Remove `stub-external` (or `anthropic`) from `egress.allowed_destinations`. Clean prompts are now refused at the egress gateway, and the refusal is audited.
- Break the file (delete the `rules:` line). Every request is blocked until it is fixed.

Each change of policy is recorded in the audit log, and `make verify` still replays every earlier decision against the policy version it was made under.

## Assumptions about the host

- Docker Desktop or Docker Engine with Compose v2, about 4 GB of free disk for images and the model, and at least 4 GB of memory available to Docker.
- Internet access on first run, to pull images, Python packages and the model. After that the stack runs offline unless an Anthropic key is set.
- Port 8000 is free.
- The sovereign model runs on CPU. Docker on macOS has no GPU access, so an answer from it takes several seconds.
- Tested on macOS (Apple Silicon) with Docker 28.

## What each request goes through

```
POST /v1/inference {"prompt": "..."}
  1. Inspect   two independent detectors return findings (type, span, score, recognizer)
  2. Decide    a pure function applies policy.yaml: first matching rule wins, default is block
  3. Audit     the DECISION record is written and fsynced before any model is called
  4. Enforce   block | sovereign model | redact + egress gateway | egress gateway
  5. Audit     the OUTCOME record says what actually happened
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/inference` | Send a prompt through the control plane. |
| `GET /v1/audit`, `GET /v1/audit/{audit_id}` | Read the evidence. |
| `GET /v1/audit/verify` | Verify the chain, signatures and replay. |
| `GET /v1/policy` | The active policy and its SHA-256. |
| `GET /healthz` | Component status. Never calls a model. |
| `GET /docs` | OpenAPI documentation. |

The default policy:

| If the prompt contains | Action |
|---|---|
| A secret or credential | `block` |
| A government ID, financial data or health data | `route_sovereign` |
| A possible secret (long random string) | `route_sovereign` |
| Only weak evidence, or detection failed | `route_sovereign` |
| Contact PII (name, email, phone, IP address) | `redact`, then external model |
| Nothing private | `allow` |
| Anything no rule covers | `block` |

## AI tools, models and providers

| Used for | Choice | Why |
|---|---|---|
| Detecting PII | Microsoft **Presidio** with the spaCy model `en_core_web_md`, in-process | Detection has to happen inside the boundary: sending a prompt to a hosted classifier to ask whether it is private would itself be the leak. Presidio is deterministic for a pinned version, runs offline, and explains each finding. |
| Detecting secrets | My own **pattern rules** and an entropy check | Presidio does not cover credentials. A second detector that shares no code with the first also means one failing cannot hide the other's findings. |
| Sovereign model | **Ollama** serving `llama3.2:1b` | A real model running inside the boundary, small enough to pull and run on a reviewer's laptop CPU. The model is one environment variable. |
| External model | **Anthropic Claude API** (`claude-opus-5-5`), or a labelled stub | A real external destination makes "egress only when policy allows" concrete. The stub lets the system run with no key and never pretends to be a real model. |
| Writing the code | **Claude Code** (AI coding assistant) | Used to write the code, tests and the first draft of these documents, from the design decisions recorded in DESIGN.md. |

I deliberately did **not** put an LLM in the decision path. An LLM classifier would catch more contextual cases, but it would make the enforcement outcome depend on sampling, and it could be argued with by the prompt it is classifying. With more time I would add a local LLM as a third detector that can only escalate a request to "private", never downgrade one.

## Design decisions and trade-offs

The full reasoning is in [DESIGN.md](DESIGN.md). The short version:

| Decision | What I gave up |
|---|---|
| **Two audit records per request**: the decision before enforcement, the outcome after. | Twice the records. In return, the log cannot claim an egress that did not happen or miss one that did, and a crash mid-request is visible. |
| **Hash chain plus Ed25519 signatures plus receipts.** | A chain alone cannot see truncation of its tail. Receipts cover that only if a caller keeps them. |
| **The audit log stores keyed hashes, never raw values.** | A reviewer cannot read the original prompt from the log. They can still replay the decision, because the decision depends on the findings, not the text. |
| **The verifier replays every decision** from the recorded signals and the policy snapshot. | The policy functions must stay pure, and the record must hold their complete input. |
| **An invalid policy blocks everything** instead of keeping the last valid one. | Availability. I prefer an outage the operator notices to stale rules they do not. |
| **Low-confidence findings are treated as private.** | More prompts go to the slower sovereign model than strictly necessary. |
| **Sovereign failure never falls back to the external model.** | Availability again, on purpose. |
| **Egress is enforced in code** by one gateway object. | The container still has open network access. See "more time". |
| **JSONL file, single writer.** | No horizontal scaling. In return the log can be read with `cat`, and the verifier is one small file. |
| **`LOCATION` is off by default.** | A home address is not detected. With it on, "the capital of France" is redacted. |

## What I would do with more time

In the order I would do them:

1. **Network-level egress control.** Put the control plane on an internal network whose only route out is an egress proxy with a destination allowlist, so a bug or a compromised dependency cannot send data out.
2. **Anchor the chain head outside the boundary** (a transparency log, an RFC 3161 timestamp, or write-once storage), and move the signing key into an HSM or KMS. Today, an insider who holds the key could rewrite records that no caller kept a receipt for.
3. **Authenticate callers** (mTLS or signed tokens) and put the audit endpoints behind a separate auditor role.
4. **A local LLM as an escalate-only detector** for contextual data that patterns and NER miss, plus recognizers for addresses and for languages other than English.
5. **An evaluation set for detection**: labelled prompts, with precision and recall tracked per entity type, so policy thresholds are chosen from data.
6. **Streaming responses**, with the output scan applied to the stream.
7. **A multi-instance audit writer** backed by a database with an append-only table.

Known gaps are listed in [DESIGN.md, section 10](DESIGN.md#10-known-limitations).

## Development

```bash
make install     # create .venv, install dependencies and the spaCy model
make check       # ruff + pyright + pytest
make dev         # run the API locally with stub models on :8000 (no Docker)
make ui          # build the web UI into ui/dist
```

```
policy/policy.yaml            the one place rules live
src/control_plane/
  api.py                      HTTP edge: bounded read, strict parsing, responses
  pipeline.py                 inspect, decide, record, enforce, record
  detection/                  rules.py, presidio.py, base.py (runner that isolates failures)
  classification.py           findings + thresholds -> label and categories (pure)
  policy.py                   load, validate, hash, decide() (pure)
  enforcement.py              redact, restore placeholders (pure)
  egress.py                   the only path to an external model
  providers/                  ollama.py, anthropic.py, stub.py
  audit/                      log.py (writer), verify.py (verifier CLI), chain.py, keys.py
  evidence.py                 what goes into a record, and how to read it back
  main.py                     composition root
tests/                        153 tests; fakes only at the detector and model boundaries
ui/                           React + Vite + TypeScript
scripts/                      demo.py, tamper_demo.py
```
