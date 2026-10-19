"""MIRAGE-MCP Security Engine Extensions.

Provides zero-dependency, sub-millisecond protection against:
1. MCP Tool Poisoning & Rug-Pull Schema Drift (`SchemaPinGuard`)
2. Credential & Secret Exfiltration across MCP boundaries (`SecretRedactor`)
"""

from mirage_mcp.security.schema_guard import SchemaPinGuard, SchemaVerificationResult
from mirage_mcp.security.secret_guard import RedactionResult, SecretRedactor

__all__ = [
    "RedactionResult",
    "SchemaPinGuard",
    "SchemaVerificationResult",
    "SecretRedactor",
]
