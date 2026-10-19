"""MCP Tool Schema Pinning & Poisoning Guard.

Protects MCP clients from:
1. Tool Poisoning Attacks (TPA): Malicious prompt injections embedded inside
   tool `description` or `inputSchema` fields (e.g., `<IMPORTANT>`, hidden
   instructions to exfiltrate `~/.ssh/id_rsa`, unicode tag smuggling).
2. Rug-Pull Schema Drift: A remote MCP server initially presents a benign tool
   definition to win approval, then dynamically mutates its description or
   schema on subsequent `tools/list` responses.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SchemaVerificationResult:
    """Result of verifying an MCP tool definition against pinned schemas and poisoning heuristics."""

    server_id: str
    tool_name: str
    sha256_hash: str
    status: str  # "VERIFIED" | "DRIFT_DETECTED" | "POISON_SUSPECTED"
    allowed: bool
    drift_summary: str | None = None
    suspicious_patterns: list[str] = field(default_factory=list)
    description_preview: str = ""


_POISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("xml_important_tag", re.compile(r"<\s*important\b[^>]*>", re.IGNORECASE)),
    ("xml_system_tag", re.compile(r"<\s*(?:system|instruction|secret|hidden)\b[^>]*>", re.IGNORECASE)),
    ("ignore_instructions", re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.IGNORECASE)),
    ("concealment_directive", re.compile(r"\b(?:do\s+not\s+(?:mention|tell|inform|reveal)|hide\s+this\s+from\s+the\s+user)\b", re.IGNORECASE)),
    ("ssh_key_access", re.compile(r"(?:~\/\.ssh|id_rsa|id_ed25519|authorized_keys)", re.IGNORECASE)),
    ("sensitive_env_access", re.compile(r"(?:\.env\b|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)", re.IGNORECASE)),
    ("exfiltration_directive", re.compile(r"\b(?:exfiltrate|send\s+(?:the\s+)?contents\s+to|webhook\.site|requestbin|burpcollaborator)\b", re.IGNORECASE)),
    ("system_override", re.compile(r"\b(?:system\s+override|developer\s+mode\s+enabled|sudo\s+mode)\b", re.IGNORECASE)),
    ("unicode_tag_smuggling", re.compile(r"[\U000e0000-\U000e007f\u200b-\u200f\u202a-\u202e\u2060-\u2064]")),
)


class SchemaPinGuard:
    """Cryptographic TOFU (Trust-On-First-Use) pin store and tool-poisoning detector."""

    def __init__(self, initial_pins: dict[tuple[str, str], dict[str, Any]] | None = None) -> None:
        self._pins: dict[tuple[str, str], dict[str, Any]] = dict(initial_pins) if initial_pins else {}

    @staticmethod
    def compute_canonical_hash(tool_def: dict[str, Any]) -> str:
        """Compute deterministic SHA-256 hash over canonical `{name, description, inputSchema}`."""
        canonical_payload = {
            "name": str(tool_def.get("name", "")),
            "description": str(tool_def.get("description", "")),
            "inputSchema": tool_def.get("inputSchema") or tool_def.get("input_schema") or {},
        }
        serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def scan_for_poisoning(cls, tool_def: dict[str, Any]) -> list[str]:
        """Scan tool description and schema text for prompt-injection / tool-poisoning indicators."""
        description = str(tool_def.get("description", ""))
        input_schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
        schema_str = json.dumps(input_schema, sort_keys=True, ensure_ascii=False)
        combined_surface = f"{description}\n{schema_str}"

        findings: list[str] = []
        for label, pattern in _POISON_PATTERNS:
            if pattern.search(combined_surface):
                findings.append(label)
        return findings

    def verify_or_pin(self, server_id: str, tool_def: dict[str, Any]) -> SchemaVerificationResult:
        """Verify a tool against its pinned hash or pin on first clean sighting."""
        tool_name = str(tool_def.get("name", "unknown_tool"))
        description = str(tool_def.get("description", ""))
        preview = description[:120] + ("..." if len(description) > 120 else "")
        sha256_hash = self.compute_canonical_hash(tool_def)
        suspicious = self.scan_for_poisoning(tool_def)

        if suspicious:
            return SchemaVerificationResult(
                server_id=server_id,
                tool_name=tool_name,
                sha256_hash=sha256_hash,
                status="POISON_SUSPECTED",
                allowed=False,
                drift_summary=f"Tool poisoning indicators detected: {', '.join(suspicious)}",
                suspicious_patterns=suspicious,
                description_preview=preview,
            )

        key = (server_id, tool_name)
        existing = self._pins.get(key)
        if existing is None:
            self._pins[key] = {
                "server_id": server_id,
                "tool_name": tool_name,
                "sha256_hash": sha256_hash,
                "description": description,
                "inputSchema": tool_def.get("inputSchema") or tool_def.get("input_schema") or {},
            }
            return SchemaVerificationResult(
                server_id=server_id,
                tool_name=tool_name,
                sha256_hash=sha256_hash,
                status="VERIFIED",
                allowed=True,
                drift_summary=None,
                suspicious_patterns=[],
                description_preview=preview,
            )

        pinned_hash = str(existing["sha256_hash"])
        if pinned_hash != sha256_hash:
            old_desc = str(existing.get("description", ""))
            changed_parts: list[str] = []
            if old_desc != description:
                changed_parts.append("description mutated")
            old_schema = existing.get("inputSchema", {})
            new_schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
            if old_schema != new_schema:
                changed_parts.append("inputSchema mutated")
            reason = ", ".join(changed_parts) if changed_parts else "canonical payload mutated"
            return SchemaVerificationResult(
                server_id=server_id,
                tool_name=tool_name,
                sha256_hash=sha256_hash,
                status="DRIFT_DETECTED",
                allowed=False,
                drift_summary=(
                    f"MCP Rug-Pull detected for '{server_id}:{tool_name}' ({reason}): "
                    f"pinned={pinned_hash[:12]}... vs current={sha256_hash[:12]}..."
                ),
                suspicious_patterns=[],
                description_preview=preview,
            )

        return SchemaVerificationResult(
            server_id=server_id,
            tool_name=tool_name,
            sha256_hash=sha256_hash,
            status="VERIFIED",
            allowed=True,
            drift_summary=None,
            suspicious_patterns=[],
            description_preview=preview,
        )

    def verify_tools_list(
        self, server_id: str, tools: list[dict[str, Any]]
    ) -> list[SchemaVerificationResult]:
        """Verify a batch of MCP tool definitions returned by `tools/list`."""
        return [self.verify_or_pin(server_id, tool_def) for tool_def in tools]

    def list_pins(self) -> list[dict[str, Any]]:
        """Return a snapshot of all currently pinned tool schemas."""
        return [
            {
                "server_id": entry["server_id"],
                "tool_name": entry["tool_name"],
                "sha256_hash": entry["sha256_hash"],
                "description_preview": str(entry.get("description", ""))[:120],
            }
            for entry in self._pins.values()
        ]
