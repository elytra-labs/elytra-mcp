"""MCP Secret & Credential Exfiltration Guard.

Scans outbound tool arguments and inbound tool outputs for high-entropy secrets,
API keys, cloud credentials, PEM private keys, and JWT tokens, redacting them
in-flight before they cross the MCP wire boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RedactionResult:
    """Result of scanning and redacting an arbitrary payload for secrets."""

    redacted_payload: Any
    secrets_found: int
    secret_types: list[str] = field(default_factory=list)


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "PRIVATE_KEY_PEM",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
            r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[^\n\r]*"
        ),
    ),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_PAT", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("STRIPE_LIVE_KEY", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("ANTHROPIC_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OPENAI_API_KEY", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b")),
    (
        "BEARER_JWT",
        re.compile(
            r"(?:Bearer\s+)?\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
)


class SecretRedactor:
    """Zero-dependency recursive secret scanner and redactor for MCP payloads."""

    def redact_text(self, text: str) -> tuple[str, int, list[str]]:
        """Scan a string and replace any matched secret patterns with `[MIRAGE_REDACTED:<TYPE>]`."""
        redacted = text
        count = 0
        detected_types: list[str] = []

        for secret_type, pattern in _SECRET_PATTERNS:
            matches = list(pattern.finditer(redacted))
            if matches:
                count += len(matches)
                if secret_type not in detected_types:
                    detected_types.append(secret_type)
                redacted = pattern.sub(f"[MIRAGE_REDACTED:{secret_type}]", redacted)

        return redacted, count, detected_types

    def redact(self, payload: Any) -> RedactionResult:
        """Recursively scan and redact strings, dicts, lists, and tuples."""
        total_found = 0
        types_seen: list[str] = []

        def _walk(node: Any) -> Any:
            nonlocal total_found
            if isinstance(node, str):
                cleaned, found, found_types = self.redact_text(node)
                total_found += found
                for t in found_types:
                    if t not in types_seen:
                        types_seen.append(t)
                return cleaned
            if isinstance(node, dict):
                return {k: _walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [_walk(item) for item in node]
            if isinstance(node, tuple):
                return tuple(_walk(item) for item in node)
            return node

        redacted_payload = _walk(payload)
        return RedactionResult(
            redacted_payload=redacted_payload,
            secrets_found=total_found,
            secret_types=types_seen,
        )
