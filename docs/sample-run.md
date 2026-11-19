# Sample run

This is captured output from the system running in Docker (`docker compose up --build`). The text inside the code blocks is unedited. The summary table is computed from it.

- **Sovereign model:** Ollama serving `llama3.2:1b`, a real model running inside the boundary.
- **External model:** the labelled stub, because no Anthropic API key was set for this run. The evidence says so: look for `"stub": true` and `"destination": "stub-external"`.
- **Detectors:** the pattern rules and Presidio with `en_core_web_md`.

## 1. Six requests

```bash
python3 scripts/demo.py
```

| # | Classification | Action | Rule | Model called | Outcome | HTTP |
|---|---|---|---|---|---|---|
| 1 | no_private_data | `allow` | `allow-clean` | stub-external (external, stub) | completed | 200 |
| 2 | contains_private_data | `redact` | `redact-pii` | stub-external (external, stub) | completed | 200 |
| 3 | contains_private_data | `route_sovereign` | `keep-regulated-in-boundary` | ollama (inside) | completed | 200 |
| 4 | contains_private_data | `block` | `block-secrets` | none | blocked | 200 |
| 5 | uncertain | `route_sovereign` | `protect-when-unsure` | ollama (inside) | completed | 200 |
| 6 | invalid_input | `block` | `builtin:invalid-request` | none | blocked | 422 |

Each section below holds the request, the API response, and the two audit records (decision and outcome) that request produced.

### 1. No private data -> allow (external model)

Nothing private was found, so the prompt went to the external destination unchanged. The outcome record's `egress` block names the destination and the SHA-256 of what was sent.

<details>
<summary>Full output</summary>

```
--- request body
{
  "prompt": "Explain what a hash chain is in two sentences."
}

--- response (HTTP 200)
{
  "audit_id": "7acd267508464c92aa128817c1da0919",
  "decision": {
    "action": "allow",
    "rule_id": "allow-clean",
    "rationale": "No private data was found, so the prompt may go to the external model.",
    "fail_closed": false
  },
  "classification": {
    "label": "no_private_data",
    "categories": [],
    "rationale": "No finding at or above the minimum score 0.35.",
    "findings": []
  },
  "policy": {
    "id": "default-sovereign-policy",
    "version": "1.0.0",
    "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51"
  },
  "outcome": "completed",
  "outcome_reason": null,
  "model": {
    "provider": "stub-external",
    "model": "stub-echo",
    "in_boundary": false,
    "stub": true
  },
  "forwarded_prompt": "Explain what a hash chain is in two sentences.",
  "response": "[stub-external: no real model was called] I received: Explain what a hash chain is in two sentences.",
  "receipts": {
    "decision": {
      "seq": 1,
      "hash": "edcde056717baec162a783af5bf663d3c974e328e2dbc21b9a8b9af073e8ed18",
      "sig": "PdupiMdg+o3MYGYsusNcmtndfwsuwzTn0mtTt5xU9XGoE4/w6OwBIoiP4lWCBmaS7j1fogxLikZoRdQr27VUAQ==",
      "key_id": "ed25519:91a2fa3c6452f577"
    },
    "outcome": {
      "seq": 2,
      "hash": "10f33c8a2ad1b5f92efc725e11987f476a82a75b7045599d149bda0a06e1c93a",
      "sig": "Yoj/Dni9ISwXZyU7463ZFHJbXCLb4W0zD09BFXUzubr2JRhea8cWqNu3frwXgvHsZYQnr5vi1pRlwyy5XJkYAQ==",
      "key_id": "ed25519:91a2fa3c6452f577"
    }
  }
}

--- audit evidence for this request
[
  {
    "audit_id": "7acd267508464c92aa128817c1da0919",
    "body": {
      "classification": {
        "categories": [],
        "counted_findings": 0,
        "label": "no_private_data",
        "rationale": "No finding at or above the minimum score 0.35."
      },
      "decision": {
        "action": "allow",
        "fail_closed": false,
        "rationale": "No private data was found, so the prompt may go to the external model.",
        "rule_id": "allow-clean"
      },
      "policy": {
        "id": "default-sovereign-policy",
        "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51",
        "version": "1.0.0"
      },
      "request": {
        "client_id_claimed": "demo-script",
        "normalization_changed": false,
        "prompt_chars": 46,
        "prompt_hmac": "a4f10d515a3ee34c865ffaf024507b1a901baa8e075e9f325e4b3f50f9410c83"
      },
      "signals": {
        "detectors": [
          {
            "error": null,
            "name": "rules",
            "ok": true,
            "version": "1"
          },
          {
            "error": null,
            "name": "presidio",
            "ok": true,
            "version": "presidio-analyzer 2.2.366 / en_core_web_md 3.8.0"
          }
        ],
        "findings": []
      }
    },
    "event": "decision",
    "hash": "edcde056717baec162a783af5bf663d3c974e328e2dbc21b9a8b9af073e8ed18",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "ca8d8a362f73b8219d280a61477c8886b50e5ec4f2e7fa11a56094fd94510e14",
    "seq": 1,
    "sig": "PdupiMdg+o3MYGYsusNcmtndfwsuwzTn0mtTt5xU9XGoE4/w6OwBIoiP4lWCBmaS7j1fogxLikZoRdQr27VUAQ==",
    "ts": "2026-11-19T20:29:54.382927+00:00"
  },
  {
    "audit_id": "7acd267508464c92aa128817c1da0919",
    "body": {
      "action": "allow",
      "egress": {
        "allowed": true,
        "attempted": true,
        "denied_reason": null,
        "destination": "stub-external",
        "payload_chars": 46,
        "payload_sha256": "6c4bab8112592a4368b3601a52860a9bd5e959de0bab1326ae2e014fb3fb1875"
      },
      "model": {
        "called": true,
        "error": null,
        "in_boundary": false,
        "latency_ms": 7,
        "model": "stub-echo",
        "note": null,
        "provider": "stub-external",
        "served_by": "stub-echo",
        "stub": true
      },
      "reason": null,
      "redaction": null,
      "response": {
        "chars": 100,
        "hmac": "dc3057475353fa16a0c373b21084e9d7d49d88957282df006595bcc90a337666",
        "output_findings": {},
        "output_redactions": {}
      },
      "status": "completed"
    },
    "event": "outcome",
    "hash": "10f33c8a2ad1b5f92efc725e11987f476a82a75b7045599d149bda0a06e1c93a",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "edcde056717baec162a783af5bf663d3c974e328e2dbc21b9a8b9af073e8ed18",
    "seq": 2,
    "sig": "Yoj/Dni9ISwXZyU7463ZFHJbXCLb4W0zD09BFXUzubr2JRhea8cWqNu3frwXgvHsZYQnr5vi1pRlwyy5XJkYAQ==",
    "ts": "2026-11-19T20:29:54.390515+00:00"
  }
]
```

</details>

### 2. Contact PII -> redact, then external model

A name and an email address were found. Compare `forwarded_prompt` (what left the boundary: placeholders only) with `response` (placeholders restored for the caller). The audit records contain `value_hmac` for each finding and never the values themselves.

<details>
<summary>Full output</summary>

```
--- request body
{
  "prompt": "Write a short, friendly reply to Dana Levi at dana.levi@example.com confirming Tuesday's meeting."
}

--- response (HTTP 200)
{
  "audit_id": "0c40e76209a34241b01d7a02e70ae51b",
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
        "start": 33,
        "end": 42,
        "score": 0.85,
        "detector": "presidio",
        "recognizer": "SpacyRecognizer",
        "counted": true
      },
      {
        "entity_type": "EMAIL_ADDRESS",
        "category": "pii",
        "start": 46,
        "end": 67,
        "score": 1.0,
        "detector": "presidio",
        "recognizer": "EmailRecognizer",
        "counted": true
      }
    ]
  },
  "policy": {
    "id": "default-sovereign-policy",
    "version": "1.0.0",
    "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51"
  },
  "outcome": "completed",
  "outcome_reason": null,
  "model": {
    "provider": "stub-external",
    "model": "stub-echo",
    "in_boundary": false,
    "stub": true
  },
  "forwarded_prompt": "Write a short, friendly reply to <PERSON_1> at <EMAIL_ADDRESS_1> confirming Tuesday's meeting.",
  "response": "[stub-external: no real model was called] I received: Write a short, friendly reply to Dana Levi at dana.levi@example.com confirming Tuesday's meeting.",
  "receipts": {
    "decision": {
      "seq": 3,
      "hash": "5501aa8f705fd978a75eb02d6367668a42bd7ab15d2ed99898c80873423fd62d",
      "sig": "aIECQc5J6fEbWBxYHGOo6EaGPe1pH1QQrw3r4Tz7MkARpzN6mrNeUx/+kan85WrlS9uSEf0esCGDPEBuMHKvAQ==",
      "key_id": "ed25519:91a2fa3c6452f577"
    },
    "outcome": {
      "seq": 4,
      "hash": "d43e17166a2592f1fcf71fc86fc0dbc4608b61e6a9e74fb6c6d67f8959af0faa",
      "sig": "RUQHa9xa312ex5iqJx+HLqHuFxxQTxhSlxklWpRhsVmHdjzGM6A8q1cWgWRYGupasvWF4e/kPXGu+vOXwGidCA==",
      "key_id": "ed25519:91a2fa3c6452f577"
    }
  }
}

--- audit evidence for this request
[
  {
    "audit_id": "0c40e76209a34241b01d7a02e70ae51b",
    "body": {
      "classification": {
        "categories": [
          "pii"
        ],
        "counted_findings": 2,
        "label": "contains_private_data",
        "rationale": "Found 2 finding(s): EMAIL_ADDRESS x1, PERSON x1."
      },
      "decision": {
        "action": "redact",
        "fail_closed": false,
        "rationale": "Personal data is replaced with placeholders before the prompt leaves the boundary.",
        "rule_id": "redact-pii"
      },
      "policy": {
        "id": "default-sovereign-policy",
        "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51",
        "version": "1.0.0"
      },
      "request": {
        "client_id_claimed": "demo-script",
        "normalization_changed": false,
        "prompt_chars": 97,
        "prompt_hmac": "f57fc0c84fa2de2f1bb00f723fff1636120250db6259d49dd31aab1e042797c5"
      },
      "signals": {
        "detectors": [
          {
            "error": null,
            "name": "rules",
            "ok": true,
            "version": "1"
          },
          {
            "error": null,
            "name": "presidio",
            "ok": true,
            "version": "presidio-analyzer 2.2.366 / en_core_web_md 3.8.0"
          }
        ],
        "findings": [
          {
            "detector": "presidio",
            "end": 42,
            "entity_type": "PERSON",
            "recognizer": "SpacyRecognizer",
            "score": 0.85,
            "start": 33,
            "value_hmac": "3ee1ed75320bdbc2d235cb155373ea57c9bfe5f059bc3626afc591fedff4bae3"
          },
          {
            "detector": "presidio",
            "end": 67,
            "entity_type": "EMAIL_ADDRESS",
            "recognizer": "EmailRecognizer",
            "score": 1.0,
            "start": 46,
            "value_hmac": "24bb645cdf94ddb3ec7ebd10ff9118f2e3bb28bf142e712335f45028a8355241"
          }
        ]
      }
    },
    "event": "decision",
    "hash": "5501aa8f705fd978a75eb02d6367668a42bd7ab15d2ed99898c80873423fd62d",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "10f33c8a2ad1b5f92efc725e11987f476a82a75b7045599d149bda0a06e1c93a",
    "seq": 3,
    "sig": "aIECQc5J6fEbWBxYHGOo6EaGPe1pH1QQrw3r4Tz7MkARpzN6mrNeUx/+kan85WrlS9uSEf0esCGDPEBuMHKvAQ==",
    "ts": "2026-11-19T20:29:54.552017+00:00"
  },
  {
    "audit_id": "0c40e76209a34241b01d7a02e70ae51b",
    "body": {
      "action": "redact",
      "egress": {
        "allowed": true,
        "attempted": true,
        "denied_reason": null,
        "destination": "stub-external",
        "payload_chars": 94,
        "payload_sha256": "a15dcc0c89214de7ca404b4011929f6be7f302945db1259247914e4c37b956f9"
      },
      "model": {
        "called": true,
        "error": null,
        "in_boundary": false,
        "latency_ms": 7,
        "model": "stub-echo",
        "note": null,
        "provider": "stub-external",
        "served_by": "stub-echo",
        "stub": true
      },
      "reason": null,
      "redaction": {
        "by_entity": {
          "EMAIL_ADDRESS": 1,
          "PERSON": 1
        },
        "placeholders_restored": 2,
        "spans": 2
      },
      "response": {
        "chars": 151,
        "hmac": "d79eb31bbb2bdc8de9a24b4bf7068eedbe80fff3c9eeb2af50c9d633cac82a21",
        "output_findings": {},
        "output_redactions": {}
      },
      "status": "completed"
    },
    "event": "outcome",
    "hash": "d43e17166a2592f1fcf71fc86fc0dbc4608b61e6a9e74fb6c6d67f8959af0faa",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "5501aa8f705fd978a75eb02d6367668a42bd7ab15d2ed99898c80873423fd62d",
    "seq": 4,
    "sig": "RUQHa9xa312ex5iqJx+HLqHuFxxQTxhSlxklWpRhsVmHdjzGM6A8q1cWgWRYGupasvWF4e/kPXGu+vOXwGidCA==",
    "ts": "2026-11-19T20:29:54.560096+00:00"
  }
]
```

</details>

### 3. Regulated data (government ID) -> sovereign model

A US social security number was found, so the prompt was answered by the model inside the boundary. `egress` is `null` in the outcome record: nothing was sent outside.

<details>
<summary>Full output</summary>

```
--- request body
{
  "prompt": "My social security number is 536-90-4399. In one sentence, what is a W-2 form?"
}

--- response (HTTP 200)
{
  "audit_id": "ea8de60d42064d41a74ed9ac43e33b33",
  "decision": {
    "action": "route_sovereign",
    "rule_id": "keep-regulated-in-boundary",
    "rationale": "Regulated data (government IDs, financial, health) is answered by the sovereign model only.",
    "fail_closed": false
  },
  "classification": {
    "label": "contains_private_data",
    "categories": [
      "government_id"
    ],
    "rationale": "Found 1 finding(s): US_SSN x1.",
    "findings": [
      {
        "entity_type": "US_SSN",
        "category": "government_id",
        "start": 29,
        "end": 40,
        "score": 0.85,
        "detector": "presidio",
        "recognizer": "UsSsnRecognizer",
        "counted": true
      }
    ]
  },
  "policy": {
    "id": "default-sovereign-policy",
    "version": "1.0.0",
    "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51"
  },
  "outcome": "completed",
  "outcome_reason": null,
  "model": {
    "provider": "ollama",
    "model": "llama3.2:1b",
    "in_boundary": true,
    "stub": false
  },
  "forwarded_prompt": "My social security number is 536-90-4399. In one sentence, what is a W-2 form?",
  "response": "A W-2 form is a tax document issued by an employer to report an employee's earnings and taxes withheld, typically showing the amount of money earned, taxes paid, and any other relevant information.",
  "receipts": {
    "decision": {
      "seq": 5,
      "hash": "04902c4b69136acab30eee4ab4dd2402696d3bb47ceaca5fa5236170bfd79d0e",
      "sig": "bbxRVKECvYQwYUlirw2tvPxk6q9mBB9n6YJK73WZFyKhkBQYLN6S+2JME8Ylab4z/ZtiNhVeXHvbgBZJImQKCQ==",
      "key_id": "ed25519:91a2fa3c6452f577"
    },
    "outcome": {
      "seq": 6,
      "hash": "2e3cce9b54ca4d81058bd963ccdf2d78d5a0ed2d59d8d9174e402a526fbd8099",
      "sig": "l6kE7dJZbh9rfmE1ep5MUhJalFie2XWRxww5Tqzg7xvY2XSSZM36417HJML19tT3aY3XThVMnqljhYrKHTx8CQ==",
      "key_id": "ed25519:91a2fa3c6452f577"
    }
  }
}

--- audit evidence for this request
[
  {
    "audit_id": "ea8de60d42064d41a74ed9ac43e33b33",
    "body": {
      "classification": {
        "categories": [
          "government_id"
        ],
        "counted_findings": 1,
        "label": "contains_private_data",
        "rationale": "Found 1 finding(s): US_SSN x1."
      },
      "decision": {
        "action": "route_sovereign",
        "fail_closed": false,
        "rationale": "Regulated data (government IDs, financial, health) is answered by the sovereign model only.",
        "rule_id": "keep-regulated-in-boundary"
      },
      "policy": {
        "id": "default-sovereign-policy",
        "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51",
        "version": "1.0.0"
      },
      "request": {
        "client_id_claimed": "demo-script",
        "normalization_changed": false,
        "prompt_chars": 78,
        "prompt_hmac": "cef4c5e600c93361df2f139d78ed49a55540cc867258195d6477d82430eb3f8e"
      },
      "signals": {
        "detectors": [
          {
            "error": null,
            "name": "rules",
            "ok": true,
            "version": "1"
          },
          {
            "error": null,
            "name": "presidio",
            "ok": true,
            "version": "presidio-analyzer 2.2.366 / en_core_web_md 3.8.0"
          }
        ],
        "findings": [
          {
            "detector": "presidio",
            "end": 40,
            "entity_type": "US_SSN",
            "recognizer": "UsSsnRecognizer",
            "score": 0.85,
            "start": 29,
            "value_hmac": "833ac3a6e14cdcd27fca680b301379efebf7af9773ec6456769ca5c56cd7ff78"
          }
        ]
      }
    },
    "event": "decision",
    "hash": "04902c4b69136acab30eee4ab4dd2402696d3bb47ceaca5fa5236170bfd79d0e",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "d43e17166a2592f1fcf71fc86fc0dbc4608b61e6a9e74fb6c6d67f8959af0faa",
    "seq": 5,
    "sig": "bbxRVKECvYQwYUlirw2tvPxk6q9mBB9n6YJK73WZFyKhkBQYLN6S+2JME8Ylab4z/ZtiNhVeXHvbgBZJImQKCQ==",
    "ts": "2026-11-19T20:29:54.577425+00:00"
  },
  {
    "audit_id": "ea8de60d42064d41a74ed9ac43e33b33",
    "body": {
      "action": "route_sovereign",
      "egress": null,
      "model": {
        "called": true,
        "error": null,
        "in_boundary": true,
        "latency_ms": 7489,
        "model": "llama3.2:1b",
        "note": null,
        "provider": "ollama",
        "served_by": "llama3.2:1b",
        "stub": false
      },
      "reason": null,
      "redaction": null,
      "response": {
        "chars": 197,
        "hmac": "81d64515dd69b7d2f7ab4a8d76d515a2690ec33b9e51b3f2e2e8c1b50e81d1a2",
        "output_findings": {},
        "output_redactions": {}
      },
      "status": "completed"
    },
    "event": "outcome",
    "hash": "2e3cce9b54ca4d81058bd963ccdf2d78d5a0ed2d59d8d9174e402a526fbd8099",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "04902c4b69136acab30eee4ab4dd2402696d3bb47ceaca5fa5236170bfd79d0e",
    "seq": 6,
    "sig": "l6kE7dJZbh9rfmE1ep5MUhJalFie2XWRxww5Tqzg7xvY2XSSZM36417HJML19tT3aY3XThVMnqljhYrKHTx8CQ==",
    "ts": "2026-11-19T20:30:02.067130+00:00"
  }
]
```

</details>

### 4. Secret -> block, no model call

An AWS access key was found. `model` is `null` in the response and in the outcome record: no model was called.

<details>
<summary>Full output</summary>

```
--- request body
{
  "prompt": "Why does this fail? AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
}

--- response (HTTP 200)
{
  "audit_id": "e721260daaea4c71aaed48ad5e1dbde6",
  "decision": {
    "action": "block",
    "rule_id": "block-secrets",
    "rationale": "Credentials and secrets are never sent to any model.",
    "fail_closed": false
  },
  "classification": {
    "label": "contains_private_data",
    "categories": [
      "secret"
    ],
    "rationale": "Found 1 finding(s): AWS_ACCESS_KEY x1.",
    "findings": [
      {
        "entity_type": "AWS_ACCESS_KEY",
        "category": "secret",
        "start": 38,
        "end": 58,
        "score": 0.95,
        "detector": "rules",
        "recognizer": "aws-access-key-id",
        "counted": true
      }
    ]
  },
  "policy": {
    "id": "default-sovereign-policy",
    "version": "1.0.0",
    "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51"
  },
  "outcome": "blocked",
  "outcome_reason": "blocked_by_policy",
  "model": null,
  "forwarded_prompt": null,
  "response": "This request was blocked by the data protection policy. No model was called.",
  "receipts": {
    "decision": {
      "seq": 7,
      "hash": "cfea310af518b3c870e8ddbd7fa24b121617571b50b3c2e4555af17e54519489",
      "sig": "/02L4h1vFS9i4A4+ZFHBiPc6ltsPl5HJti3X7vLd5ePAXSHE+yA1aqBQGpxcY2fnzDYZdnGDLxvfquKnmqfgDA==",
      "key_id": "ed25519:91a2fa3c6452f577"
    },
    "outcome": {
      "seq": 8,
      "hash": "bf4e9b24e1e69851da93398fd590d983d7c6ec6efaba30d71318fb835f0fb02a",
      "sig": "JIWcggIZG11xwUvyrQFiRfOc6a2J1i6O+wU8mFq92BEik/22A/jx/caRrRhNuNoE5KzbFzN5ZXUrBaxRME0cDw==",
      "key_id": "ed25519:91a2fa3c6452f577"
    }
  }
}

--- audit evidence for this request
[
  {
    "audit_id": "e721260daaea4c71aaed48ad5e1dbde6",
    "body": {
      "classification": {
        "categories": [
          "secret"
        ],
        "counted_findings": 1,
        "label": "contains_private_data",
        "rationale": "Found 1 finding(s): AWS_ACCESS_KEY x1."
      },
      "decision": {
        "action": "block",
        "fail_closed": false,
        "rationale": "Credentials and secrets are never sent to any model.",
        "rule_id": "block-secrets"
      },
      "policy": {
        "id": "default-sovereign-policy",
        "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51",
        "version": "1.0.0"
      },
      "request": {
        "client_id_claimed": "demo-script",
        "normalization_changed": false,
        "prompt_chars": 58,
        "prompt_hmac": "aaaa46631b5eaf85b68bbe0c25f95a34a388ed0cd56530ddad147b1f3053fc5a"
      },
      "signals": {
        "detectors": [
          {
            "error": null,
            "name": "rules",
            "ok": true,
            "version": "1"
          },
          {
            "error": null,
            "name": "presidio",
            "ok": true,
            "version": "presidio-analyzer 2.2.366 / en_core_web_md 3.8.0"
          }
        ],
        "findings": [
          {
            "detector": "rules",
            "end": 58,
            "entity_type": "AWS_ACCESS_KEY",
            "recognizer": "aws-access-key-id",
            "score": 0.95,
            "start": 38,
            "value_hmac": "038db9ebe0936f6327ab4bb0dd08ec58e56121c9981586e2f53b9a04daa5f035"
          }
        ]
      }
    },
    "event": "decision",
    "hash": "cfea310af518b3c870e8ddbd7fa24b121617571b50b3c2e4555af17e54519489",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "2e3cce9b54ca4d81058bd963ccdf2d78d5a0ed2d59d8d9174e402a526fbd8099",
    "seq": 7,
    "sig": "/02L4h1vFS9i4A4+ZFHBiPc6ltsPl5HJti3X7vLd5ePAXSHE+yA1aqBQGpxcY2fnzDYZdnGDLxvfquKnmqfgDA==",
    "ts": "2026-11-19T20:30:02.080650+00:00"
  },
  {
    "audit_id": "e721260daaea4c71aaed48ad5e1dbde6",
    "body": {
      "action": "block",
      "egress": null,
      "model": null,
      "reason": "blocked_by_policy",
      "redaction": null,
      "response": null,
      "status": "blocked"
    },
    "event": "outcome",
    "hash": "bf4e9b24e1e69851da93398fd590d983d7c6ec6efaba30d71318fb835f0fb02a",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "cfea310af518b3c870e8ddbd7fa24b121617571b50b3c2e4555af17e54519489",
    "seq": 8,
    "sig": "JIWcggIZG11xwUvyrQFiRfOc6a2J1i6O+wU8mFq92BEik/22A/jx/caRrRhNuNoE5KzbFzN5ZXUrBaxRME0cDw==",
    "ts": "2026-11-19T20:30:02.081885+00:00"
  }
]
```

</details>

### 5. Low-confidence evidence only -> treated as private (fail closed)

Presidio scored this phone-like number at 0.4, below the confident score of 0.6. The label is `uncertain`, `fail_closed` is `true`, and the prompt stayed inside the boundary.

<details>
<summary>Full output</summary>

```
--- request body
{
  "prompt": "Call me on 212-555-0123 tomorrow."
}

--- response (HTTP 200)
{
  "audit_id": "17a9e9607de44f85ada3c96d788d0236",
  "decision": {
    "action": "route_sovereign",
    "rule_id": "protect-when-unsure",
    "rationale": "Detection failed or found only low-confidence evidence, so the prompt is treated as private.",
    "fail_closed": true
  },
  "classification": {
    "label": "uncertain",
    "categories": [
      "pii"
    ],
    "rationale": "Found 1 finding(s): PHONE_NUMBER x1. Every finding is below the confident score 0.6, so the prompt is treated as private.",
    "findings": [
      {
        "entity_type": "PHONE_NUMBER",
        "category": "pii",
        "start": 11,
        "end": 23,
        "score": 0.4,
        "detector": "presidio",
        "recognizer": "PhoneRecognizer",
        "counted": true
      }
    ]
  },
  "policy": {
    "id": "default-sovereign-policy",
    "version": "1.0.0",
    "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51"
  },
  "outcome": "completed",
  "outcome_reason": null,
  "model": {
    "provider": "ollama",
    "model": "llama3.2:1b",
    "in_boundary": true,
    "stub": false
  },
  "forwarded_prompt": "Call me on 212-555-0123 tomorrow.",
  "response": "I'm not capable of storing or retrieving your phone number, and I'm also not able to make or receive calls. I'm a text-based AI assistant, and our conversation will be limited to this chat. However, I can help you plan what to do tomorrow or provide information on a topic that interests you. What's on your mind?",
  "receipts": {
    "decision": {
      "seq": 9,
      "hash": "8b689925801d184d4bedf126b44d9dcea6e33048a9be926b22b6bc88c30ed68a",
      "sig": "FlWQ5g+k+yF8rZlBHbK7ZJVJfh2OmGs48kogBNKE2KGLGiLbWRjaDGFjqbszYBaOC1YdqkDS0KgzmJSTM94ZBA==",
      "key_id": "ed25519:91a2fa3c6452f577"
    },
    "outcome": {
      "seq": 10,
      "hash": "a6755c087567a50c74208c1a26975551302160606e0aa73b4b822ad6a40cb27c",
      "sig": "ACUjUhdjkWGQT6v7Y66d2kaUEooPay53ghhOu2dx1prasEaLuq0a8L8ckgsgDSXTuT27bhM9YIkaBC+XZJLHDQ==",
      "key_id": "ed25519:91a2fa3c6452f577"
    }
  }
}

--- audit evidence for this request
[
  {
    "audit_id": "17a9e9607de44f85ada3c96d788d0236",
    "body": {
      "classification": {
        "categories": [
          "pii"
        ],
        "counted_findings": 1,
        "label": "uncertain",
        "rationale": "Found 1 finding(s): PHONE_NUMBER x1. Every finding is below the confident score 0.6, so the prompt is treated as private."
      },
      "decision": {
        "action": "route_sovereign",
        "fail_closed": true,
        "rationale": "Detection failed or found only low-confidence evidence, so the prompt is treated as private.",
        "rule_id": "protect-when-unsure"
      },
      "policy": {
        "id": "default-sovereign-policy",
        "sha256": "ba46e14e428eff1af38885449aa5606da156e983952f8d07774d8fd0dbb76d51",
        "version": "1.0.0"
      },
      "request": {
        "client_id_claimed": "demo-script",
        "normalization_changed": false,
        "prompt_chars": 33,
        "prompt_hmac": "0e2ac4b480f64c5eca6fdf7ed825e0b605c030d9539811d159661af0de8fc7e0"
      },
      "signals": {
        "detectors": [
          {
            "error": null,
            "name": "rules",
            "ok": true,
            "version": "1"
          },
          {
            "error": null,
            "name": "presidio",
            "ok": true,
            "version": "presidio-analyzer 2.2.366 / en_core_web_md 3.8.0"
          }
        ],
        "findings": [
          {
            "detector": "presidio",
            "end": 23,
            "entity_type": "PHONE_NUMBER",
            "recognizer": "PhoneRecognizer",
            "score": 0.4,
            "start": 11,
            "value_hmac": "e5fa83d70dad949a9c865e4caef70fceed4453554ff7c3350b8f9a1559612283"
          }
        ]
      }
    },
    "event": "decision",
    "hash": "8b689925801d184d4bedf126b44d9dcea6e33048a9be926b22b6bc88c30ed68a",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "bf4e9b24e1e69851da93398fd590d983d7c6ec6efaba30d71318fb835f0fb02a",
    "seq": 9,
    "sig": "FlWQ5g+k+yF8rZlBHbK7ZJVJfh2OmGs48kogBNKE2KGLGiLbWRjaDGFjqbszYBaOC1YdqkDS0KgzmJSTM94ZBA==",
    "ts": "2026-11-19T20:30:02.097529+00:00"
  },
  {
    "audit_id": "17a9e9607de44f85ada3c96d788d0236",
    "body": {
      "action": "route_sovereign",
      "egress": null,
      "model": {
        "called": true,
        "error": null,
        "in_boundary": true,
        "latency_ms": 9445,
        "model": "llama3.2:1b",
        "note": null,
        "provider": "ollama",
        "served_by": "llama3.2:1b",
        "stub": false
      },
      "reason": null,
      "redaction": null,
      "response": {
        "chars": 313,
        "hmac": "1e606738c93c83f609bb9e78313d635e0e225746d8f8e6132385835b5b7bfe79",
        "output_findings": {},
        "output_redactions": {}
      },
      "status": "completed"
    },
    "event": "outcome",
    "hash": "a6755c087567a50c74208c1a26975551302160606e0aa73b4b822ad6a40cb27c",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "8b689925801d184d4bedf126b44d9dcea6e33048a9be926b22b6bc88c30ed68a",
    "seq": 10,
    "sig": "ACUjUhdjkWGQT6v7Y66d2kaUEooPay53ghhOu2dx1prasEaLuq0a8L8ckgsgDSXTuT27bhM9YIkaBC+XZJLHDQ==",
    "ts": "2026-11-19T20:30:11.543438+00:00"
  }
]
```

</details>

### 6. Malformed request (unknown field) -> rejected and audited

The body had a field the API does not accept. The request was rejected with HTTP 422 before inspection. It is still audited, but `prompt_hmac` is `null`: its content was not stored.

<details>
<summary>Full output</summary>

```
--- request body
{
  "prompt": "hello",
  "debug": true
}

--- response (HTTP 422)
{
  "audit_id": "ba7316497d5946b8b9cdedac8fb2b9d1",
  "decision": {
    "action": "block",
    "rule_id": "builtin:invalid-request",
    "rationale": "The request was rejected before inspection: invalid_request_body.",
    "fail_closed": true
  },
  "classification": {
    "label": "invalid_input",
    "categories": [],
    "rationale": "Detection did not run.",
    "findings": []
  },
  "policy": null,
  "outcome": "blocked",
  "outcome_reason": "invalid_request_body",
  "model": null,
  "forwarded_prompt": null,
  "response": null,
  "receipts": {
    "decision": {
      "seq": 11,
      "hash": "2228435293690b45a304f9e8df9b91cb9c368baa8045d32f14b2a8fd7ead0516",
      "sig": "TkNGqtPJ1l/C6YnL5AOAk1DIMjoGu72Ec4UhiZL8OEQ87KiV/PTVbF1GlenN852SyFNeK3UTIRBa0nqUXB4SAg==",
      "key_id": "ed25519:91a2fa3c6452f577"
    },
    "outcome": {
      "seq": 12,
      "hash": "0436d2f5c5f810d851459d0cfad72d16714fb4bd647a87dae6be640ab7628d0f",
      "sig": "DPC+wNxmE82azmv/4N3iSAqKbVAj9CGz5n9qVUgAKfJXByIUdgxijnuxFnlhFz5w34E2bdXyE9+TCt0W7CzjCg==",
      "key_id": "ed25519:91a2fa3c6452f577"
    }
  }
}

--- audit evidence for this request
[
  {
    "audit_id": "ba7316497d5946b8b9cdedac8fb2b9d1",
    "body": {
      "classification": {
        "categories": [],
        "counted_findings": 0,
        "label": "invalid_input",
        "rationale": "Detection did not run."
      },
      "decision": {
        "action": "block",
        "fail_closed": true,
        "rationale": "The request was rejected before inspection: invalid_request_body.",
        "rule_id": "builtin:invalid-request"
      },
      "policy": null,
      "request": {
        "client_id_claimed": "demo-script",
        "normalization_changed": false,
        "prompt_chars": null,
        "prompt_hmac": null,
        "rejected": "invalid_request_body"
      },
      "signals": {
        "detectors": [],
        "findings": []
      }
    },
    "event": "decision",
    "hash": "2228435293690b45a304f9e8df9b91cb9c368baa8045d32f14b2a8fd7ead0516",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "a6755c087567a50c74208c1a26975551302160606e0aa73b4b822ad6a40cb27c",
    "seq": 11,
    "sig": "TkNGqtPJ1l/C6YnL5AOAk1DIMjoGu72Ec4UhiZL8OEQ87KiV/PTVbF1GlenN852SyFNeK3UTIRBa0nqUXB4SAg==",
    "ts": "2026-11-19T20:30:11.549021+00:00"
  },
  {
    "audit_id": "ba7316497d5946b8b9cdedac8fb2b9d1",
    "body": {
      "action": "block",
      "egress": null,
      "model": null,
      "reason": "invalid_request_body",
      "redaction": null,
      "response": null,
      "status": "blocked"
    },
    "event": "outcome",
    "hash": "0436d2f5c5f810d851459d0cfad72d16714fb4bd647a87dae6be640ab7628d0f",
    "key_id": "ed25519:91a2fa3c6452f577",
    "prev_hash": "2228435293690b45a304f9e8df9b91cb9c368baa8045d32f14b2a8fd7ead0516",
    "seq": 12,
    "sig": "DPC+wNxmE82azmv/4N3iSAqKbVAj9CGz5n9qVUgAKfJXByIUdgxijnuxFnlhFz5w34E2bdXyE9+TCt0W7CzjCg==",
    "ts": "2026-11-19T20:30:11.549826+00:00"
  }
]
```

</details>

## 2. Verifying the audit log

The API can verify its own log:

```
--- GET /v1/audit/verify
{
  "ok": true,
  "records": 13,
  "head_seq": 12,
  "head_hash": "0436d2f5c5f810d851459d0cfad72d16714fb4bd647a87dae6be640ab7628d0f",
  "chain_problems": [],
  "incomplete_requests": [],
  "decisions_replayed": 6,
  "replay_problems": []
}
```

The same check from the command line, without the API. It needs only the log file, the public key and the policy snapshots:

```bash
make verify
```

```
records verified : 13
chain head       : seq 12  0436d2f5c5f810d851459d0cfad72d16714fb4bd647a87dae6be640ab7628d0f
decisions replayed: 6
RESULT: OK - the log is intact
```

"Decisions replayed" means that for each decision record the verifier rebuilt the signals from the record, loaded the policy version named by its SHA-256, ran the same classification and policy functions, and got the recorded action.

## 3. Tampering is detected

The script edits a *copy* of the log three ways and runs the verifier on each copy.

```bash
make tamper-demo
```

```
original log            : OK      13 records verified, 6 decisions replayed
record 11: "block" -> "allow"
  edited copy           : FAILED  at record 11: content does not match its hash
record 6: deleted
  edited copy           : FAILED  at record 6: expected seq 6, found 7
last 2 records: cut off
  edited copy           : OK      11 records verified, 5 decisions replayed
  with a caller's receipt: FAILED  record 12 is not in the log: the log was truncated
```

The third case is the known limit of a hash chain: cutting records off the end leaves a shorter chain that is still valid. It is caught by the receipt that every API response returns to the caller.

## 4. Failing closed, live

Three faults were injected into the running system. Each `$` line is what was done, followed by the control plane's answer.

- **A.** With the sovereign model stopped, a prompt that must stay inside is blocked. It is not sent to the external model.
- **B.** With an invalid policy file, even a harmless prompt is blocked.
- **C.** With the destination removed from the allowlist, the rule still says `allow`, but the egress gateway refuses, and the outcome record shows `"attempted": false`.
- **D.** With the policy restored, the same prompt is allowed again. No restart was needed.

```
### A. The sovereign model is down
$ docker compose stop ollama
$ POST /v1/inference  (a prompt with a government ID, which must stay in the boundary)
{
  "decision": {
    "action": "route_sovereign",
    "rule_id": "keep-regulated-in-boundary",
    "rationale": "Regulated data (government IDs, financial, health) is answered by the sovereign model only.",
    "fail_closed": false
  },
  "classification": {
    "label": "contains_private_data",
    "categories": [
      "government_id"
    ],
    "rationale": "Found 1 finding(s): US_SSN x1."
  },
  "outcome": "blocked",
  "outcome_reason": "sovereign_model_unavailable:connection",
  "model": {
    "provider": "ollama",
    "model": "llama3.2:1b",
    "in_boundary": true,
    "stub": false
  },
  "forwarded_prompt": null,
  "response": "This request must stay inside the trust boundary, but the sovereign model is unavailable, so it was blocked. It was not sent to any external model.",
  "audit_id": "e3935cca508e49b5a435227251062f58"
}
--- outcome record
{
  "audit_id": "e3935cca508e49b5a435227251062f58",
  "body": {
    "action": "route_sovereign",
    "egress": null,
    "model": {
      "called": true,
      "error": "connection",
      "in_boundary": true,
      "latency_ms": 19,
      "model": "llama3.2:1b",
      "note": null,
      "provider": "ollama",
      "served_by": null,
      "stub": false
    },
    "reason": "sovereign_model_unavailable:connection",
    "redaction": null,
    "response": null,
    "status": "blocked"
  },
  "event": "outcome",
  "hash": "91228227a0c8e6d1cf29cc016bfb22ea41b290caaabaffa3d964d0acb016ea9d",
  "key_id": "ed25519:91a2fa3c6452f577",
  "prev_hash": "a17fe280f7980ca82c76e749fafd12d9150e951bd5f79d0df633ab1e2b5353ca",
  "seq": 14,
  "sig": "PrprurWw7kp4uLD7bv6XqhiJLJ6clxGSLOeCVRVxPmpalesuXfCM6GJOZ/Bbi4DcYuBViGLII1vze4lXE+aTDw==",
  "ts": "2026-11-19T20:30:13.131178+00:00"
}
$ docker compose start ollama

### B. The policy file is invalid
$ echo "rules: this is not a valid policy" > policy/policy.yaml
$ POST /v1/inference  (a prompt with no private data at all)
{
  "decision": {
    "action": "block",
    "rule_id": "builtin:policy-unavailable",
    "rationale": "The policy is missing or invalid, so every request is blocked.",
    "fail_closed": true
  },
  "classification": {
    "label": "unknown_assume_private",
    "categories": [],
    "rationale": "Detection did not run."
  },
  "outcome": "blocked",
  "outcome_reason": "policy_unavailable",
  "model": null,
  "forwarded_prompt": null,
  "response": "This request was blocked because no valid data protection policy is loaded. No model was called.",
  "audit_id": "bd747edfba7b44f88f9a5c17249b7afa"
}
$ cp policy.backup.yaml policy/policy.yaml   (restore)

### C. The destination is removed from the egress allowlist
$ remove "- stub-external" from egress.allowed_destinations in policy/policy.yaml
$ POST /v1/inference  (a prompt with no private data: the rule says allow)
{
  "decision": {
    "action": "allow",
    "rule_id": "allow-clean",
    "rationale": "No private data was found, so the prompt may go to the external model.",
    "fail_closed": false
  },
  "classification": {
    "label": "no_private_data",
    "categories": [],
    "rationale": "No finding at or above the minimum score 0.35."
  },
  "outcome": "blocked",
  "outcome_reason": "egress_denied:destination_not_allowlisted",
  "model": null,
  "forwarded_prompt": null,
  "response": "This request was blocked because the policy does not allow sending to the external model. Nothing left the trust boundary.",
  "audit_id": "b6b92403dcb14005af680ec26b3e2a43"
}
--- outcome record
{
  "audit_id": "b6b92403dcb14005af680ec26b3e2a43",
  "body": {
    "action": "allow",
    "egress": {
      "allowed": false,
      "attempted": false,
      "denied_reason": "destination_not_allowlisted",
      "destination": "stub-external",
      "payload_chars": 46,
      "payload_sha256": "6c4bab8112592a4368b3601a52860a9bd5e959de0bab1326ae2e014fb3fb1875"
    },
    "model": {
      "called": false,
      "error": null,
      "in_boundary": false,
      "latency_ms": null,
      "model": "stub-echo",
      "note": null,
      "provider": "stub-external",
      "served_by": null,
      "stub": true
    },
    "reason": "egress_denied:destination_not_allowlisted",
    "redaction": null,
    "response": null,
    "status": "blocked"
  },
  "event": "outcome",
  "hash": "1b1344ff81cfc75b008fa79c78af8e8aa900b68faec4f255fdb73b3d21923745",
  "key_id": "ed25519:91a2fa3c6452f577",
  "prev_hash": "6d5209695100cfc30a76dd6ff1578bc8bdc4e82bbd61b964e5c3ee23df8485f7",
  "seq": 20,
  "sig": "3eiaTeEmHFRCKANHtnJt/McWFGW934CBX5VPaI1ocrILBnVoAiBG1TqsNDWfvMXn/WTz+J5pW/jotZhqry9QBw==",
  "ts": "2026-11-19T20:30:13.500689+00:00"
}
$ cp policy.backup.yaml policy/policy.yaml   (restore)

### D. After restoring the policy, a clean prompt is allowed again
{
  "decision": {
    "action": "allow",
    "rule_id": "allow-clean",
    "rationale": "No private data was found, so the prompt may go to the external model.",
    "fail_closed": false
  },
  "classification": {
    "label": "no_private_data",
    "categories": [],
    "rationale": "No finding at or above the minimum score 0.35."
  },
  "outcome": "completed",
  "outcome_reason": null,
  "model": {
    "provider": "stub-external",
    "model": "stub-echo",
    "in_boundary": false,
    "stub": true
  },
  "forwarded_prompt": "Explain what a hash chain is in two sentences.",
  "response": "[stub-external: no real model was called] I received: Explain what a hash chain is in two sentences.",
  "audit_id": "24d5568adc5f437195da46169d3acb6d"
}
```

After all of that the log still verifies. It now includes a `policy_loaded` record for each change of policy, and every decision replays against the policy version it was made under:

```
records verified : 24
chain head       : seq 23  f9a0b3bd4b622904c5d96f7e00cc00498143edce5527ddc2ea93a8e22793e998
decisions replayed: 10
RESULT: OK - the log is intact
```
