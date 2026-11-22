"""Deterministic pattern rules for secrets, credentials and health context.

These run without any model and without Presidio, so they keep working if the NER
detector fails. Scores are fixed per rule: specific formats score high, heuristics score
in the "uncertain" band so the policy keeps them in the boundary instead of blocking.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Collection
from dataclasses import dataclass

from control_plane.models import Finding

DETECTOR_NAME = "rules"
DETECTOR_VERSION = "1"

HIGH_ENTROPY_STRING = "HIGH_ENTROPY_STRING"
_ENTROPY_SCORE = 0.5
# Two shapes of "looks like key material", each with its own entropy floor in bits
# per character. Hex tops out at 4.0, so it needs a lower floor than base64.
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_HEX_MIN_ENTROPY = 3.0
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+_-]{32,}")
_BASE64_MIN_ENTROPY = 4.2


@dataclass(frozen=True)
class PatternRule:
    entity_type: str
    name: str
    pattern: re.Pattern[str]
    score: float


RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "PRIVATE_KEY",
        "pem-private-key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
            r".*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
        0.99,
    ),
    PatternRule(
        "AWS_ACCESS_KEY",
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        0.95,
    ),
    PatternRule(
        "GITHUB_TOKEN",
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
        0.95,
    ),
    PatternRule(
        "SLACK_TOKEN",
        "slack-token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
        0.95,
    ),
    PatternRule(
        "API_KEY",
        "sk-prefixed-key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
        0.9,
    ),
    PatternRule(
        "JWT",
        "json-web-token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        0.9,
    ),
    PatternRule(
        "CONNECTION_STRING",
        "url-with-credentials",
        re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@[^\s/]+"),
        0.9,
    ),
    PatternRule(
        "CREDENTIAL_ASSIGNMENT",
        "credential-assignment",
        re.compile(
            r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token"
            r"|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?[^\s\"']{6,}",
            re.IGNORECASE,
        ),
        0.8,
    ),
    PatternRule(
        "CREDENTIAL_ASSIGNMENT",
        "credential-phrase",
        re.compile(r"\b(?:password|passcode|pin)\s+(?:is|was)\s*:?\s*\S{4,}", re.IGNORECASE),
        0.6,
    ),
    PatternRule(
        "HEALTH_CONTEXT",
        "health-terms",
        re.compile(
            r"\b(?:diagnosed with|diagnosis of|medical record(?: number)?|MRN|patient id"
            r"|prescribed|prescription for|HIV[- ]positive|chemotherapy|blood type"
            r"|health insurance (?:id|number))\b",
            re.IGNORECASE,
        ),
        0.5,
    ),
)

# What the rules above find that grants access to something. No policy may send a prompt
# holding one of these out unchanged (see control_plane.policy.credential_leaks).
# HEALTH_CONTEXT and the entropy heuristic are not credentials.
CREDENTIAL_TYPES = frozenset(
    {
        "PRIVATE_KEY",
        "AWS_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "API_KEY",
        "JWT",
        "CONNECTION_STRING",
        "CREDENTIAL_ASSIGNMENT",
    }
)


class RuleDetector:
    name = DETECTOR_NAME
    version = DETECTOR_VERSION
    entity_types = frozenset({rule.entity_type for rule in RULES} | {HIGH_ENTROPY_STRING})

    def detect(self, text: str, entity_types: Collection[str]) -> list[Finding]:
        wanted = set(entity_types)
        findings = [
            Finding(rule.entity_type, m.start(), m.end(), rule.score, self.name, rule.name)
            for rule in RULES
            if rule.entity_type in wanted
            for m in rule.pattern.finditer(text)
        ]
        if HIGH_ENTROPY_STRING in wanted:
            findings.extend(self._high_entropy(text))
        return findings

    def _high_entropy(self, text: str) -> list[Finding]:
        spans = {m.span() for m in _HEX_TOKEN.finditer(text) if _is_random_hex(m.group())} | {
            m.span() for m in _BASE64_TOKEN.finditer(text) if _is_random_base64(m.group())
        }
        return [
            Finding(HIGH_ENTROPY_STRING, start, end, _ENTROPY_SCORE, self.name, "entropy")
            for start, end in sorted(spans)
        ]


def _is_random_hex(token: str) -> bool:
    # Digits only is a plain number; letters only is not hex-encoded data.
    mixed = any(c.isdigit() for c in token) and any(c.isalpha() for c in token)
    return mixed and shannon_entropy(token) >= _HEX_MIN_ENTROPY


def _is_random_base64(token: str) -> bool:
    # Random base64 has digits, lower case and upper case. Identifiers such as
    # snake_case names, slugs and UUIDs lack at least one of them.
    mixed = (
        any(c.isdigit() for c in token)
        and any(c.islower() for c in token)
        and any(c.isupper() for c in token)
    )
    return mixed and shannon_entropy(token) >= _BASE64_MIN_ENTROPY


def shannon_entropy(token: str) -> float:
    counts = Counter(token)
    total = len(token)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())
