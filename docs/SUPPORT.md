# Support and incident reporting

Elytra is an early local product. For installation errors, integration requests, or reproducible bugs, use [GitHub issues](https://github.com/elytra-labs/elytra-mcp/issues). There is no advertised response-time or enterprise support guarantee.

Include the release/commit, operating system, Python version, command, supported integration, expected behavior, observed behavior, and a minimal sanitized reproduction. Remove administrative tokens, provider credentials, customer data, and raw source payloads. Do not paste the local credential or an unreviewed database into an issue.

For suspected security vulnerabilities, follow [SECURITY.md](../SECURITY.md). For unexpected destination actions, disable the affected connection, preserve sanitized run/action identifiers and timestamps, inspect the destination directly, and reconcile uncertain actions before retrying. Return to the previous host configuration if the integration prevents ordinary work.

Public issue reports are not private support channels. Use GitHub's private vulnerability reporting flow when available; do not post a working exploit against a third party or customer secrets publicly.
