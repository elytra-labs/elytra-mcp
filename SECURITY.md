# Security policy

Elytra is under active development. Unreleased changes and scripted benchmark results do not constitute independent security certification or a promise of universal prompt-injection protection.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/elytra-labs/elytra-mcp/security/advisories/new) when that repository feature is enabled. If the private reporting flow is unavailable, open a minimal [issue requesting a private reporting channel](https://github.com/elytra-labs/elytra-mcp/issues/new), without exploit details or secrets. No security contact email or response-time commitment is currently published.

Include a sanitized reproduction, affected version/commit, integration and policy configuration, expected boundary, observed result, and any destination effects. Do not include provider keys, local administrative tokens, customer payloads, or reports involving accounts you are not authorized to assess.

See the [threat model](docs/THREAT_MODEL.md) for covered paths, trusted operator assumptions, limitations, and crash uncertainty. The supported update target is the latest published release; no long-term support branches are currently promised.

## Hosted management boundary

The optional cloud connector pins the enrolled origin and public signing key. Device credentials cannot approve their own actions. Cloud policies and exact-call decisions are signed and bound to device/workspace identity, management revision, local policy version, schema, arguments, and expiry. Privileged execution requires a fresh five-minute lease, bounded by both wall-clock expiry and elapsed monotonic time. The existing durable local claim prevents redispatch. A late cloud receipt is historical evidence, never new permission.

Hosted records use tenant RLS and server-side role checks. Raw MCP credentials, owner/run tokens, and full tool results remain local. Redaction can miss secrets; review data may still be sensitive. Free-tier capacity failures reduce cloud availability. Account administrators must keep providers on Free plans; the application never upgrades plans. OAuth and public deployment require separate live verification before opening enrollment.
