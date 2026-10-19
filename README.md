# Elytra

Local guardrails for coding agents. Elytra checks what Claude Code, Codex, Grok and Antigravity do (shell commands, file edits, web access and MCP tool calls) and holds consequential actions for your decision before they run.

Everything runs on your machine: the runtime, the console and the decision records. There is no account to create.

[Website](https://elytra-gray.vercel.app) · [Documentation](https://elytra-gray.vercel.app/docs) · [Security model](https://elytra-gray.vercel.app/security) · [PyPI](https://pypi.org/project/elytra-mcp/)

Elytra is early access software. Read [what it does and does not establish](docs/THREAT_MODEL.md) before relying on it.

## Install

Python 3.11 or newer, on macOS or Linux.

```sh
pipx install elytra-mcp    # or: python3 -m pip install elytra-mcp
elytra setup               # guided, asks before it changes anything
# restart your agent, then work as usual
```

```sh
elytra open        # review held actions in the local console
elytra status      # what is protected
elytra uninstall   # restore every agent configuration exactly
```

## How it works

```
 coding agent ──hook──▶ elytra hook ──┐
      │                               ├──▶ local runtime ──▶ allow · ask · hold · block
      └──MCP──▶ elytra proxy ─────────┘        │
                    │                          └──▶ console + desktop notification
                    └──▶ your MCP server (unchanged, keeps its own credentials)
```

- **Agent hooks** (`src/mirage_mcp/hooks/`): one short-lived process per tool call. Shell commands, file edits and web access are classified into reads, untrusted web reads, edits, unrecognized commands (treated as writes), sends, and deletes or history rewrites.
- **MCP proxy** (`src/mirage_mcp/proxy/`): wraps local stdio MCP servers. Unknown, changed or suspicious tools wait for your review.
- **Runtime** (`src/mirage_mcp/runtime/`): a loopback-only service with a SQLite ledger. Each call is decided against your guardrail preset and rules. An allowed call gets a single-use permit bound to its exact arguments. Anything read from outside (an issue, a page, an email) marks the session as untrusted for what follows.
- **Console** (`ui/`): React app served by the runtime at `http://127.0.0.1:8765/app/`. The same `ui/` builds the public website.

| Preset | Behavior |
| --- | --- |
| Balanced (default) | Reads run. Writes run in a clean session. Writes after untrusted content, sends, and deletes ask you. Sending data out after untrusted reads is blocked. |
| Cautious | Every write and send asks you. |
| Autonomous | Only destructive actions ask you. Sending data out after untrusted reads is blocked. |

Claude Code and Grok show their own prompt with Elytra's reason. Codex, Antigravity, and agents running with permissions bypassed wait up to ten minutes while Elytra sends a desktop notification; an action nobody approves is denied.

## Limits

- Shell classification is a heuristic. A disguised command, or a script the agent writes and runs, may only be recognized as an unrecognized command, which is treated as a write.
- Self-protection is best-effort. Elytra denies agents reading its credentials or calling its local API, but any process running as you can read your files.
- Coverage is per agent process, not per conversation.
- If the runtime is not running, actions go through with a visible warning, unless you set up with `--fail-closed`.

## Python integration

Orchestrators that create runs explicitly can use the SDK:

```python
from mirage_mcp.sdk import RuntimeClient

owner = RuntimeClient()
run = owner.create_run(intent="Inspect an issue", grants=[])
scoped = owner.for_run(run["run_id"], run["run_token"])
async with scoped.proxy("github", ["python", "your_mcp_server.py"]) as tools:
    await tools.call_tool("get_issue", {"number": 218})
```

See the [integration guide](https://elytra-gray.vercel.app/docs#integration) for exact grants, approvals and the stdio bridge.

## Develop

Requires Python 3.11+ and Node.js 22.12+.

```sh
git clone https://github.com/elytra-labs/elytra-mcp.git
cd elytra-mcp
python3 -m venv .venv && . .venv/bin/activate
(cd ui && npm ci && npm run build)    # the console is bundled into the package
python -m pip install -e '.[dev]'
python -m pytest tests -q
```

Run the runtime in the foreground with `elytra up --open`, and the UI with hot reload with `cd ui && npm run dev` (it proxies `/api` to the runtime).

| Path | Contents |
| --- | --- |
| `src/mirage_mcp/runtime/` | Decisions, policies, guardrail presets, the SQLite ledger |
| `src/mirage_mcp/hooks/` | Agent hook entry point and the action classifier |
| `src/mirage_mcp/proxy/` | MCP stdio proxy and host sessions |
| `src/mirage_mcp/cli/` | `elytra` commands, setup and uninstall, agent integrations |
| `src/mirage_mcp/server/` | Loopback HTTP API, console pairing, notifications |
| `src/mirage_mcp/catalog/` | Suggested classifications for well-known MCP servers |
| `src/mirage_mcp/cloud/` | Client for the optional hosted workspace |
| `ui/` | Local console and public website |
| `tests/`, `benchmarks/` | Tests and recorded fixture evaluations |

The optional hosted workspace (team dashboard, remote approvals) is a separate service and is not part of this repository.

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

Apache-2.0, see [LICENSE](LICENSE). Releases up to 0.4.0a1 were published under MIT. "Elytra" and the Elytra logo are trademarks of the project; see [TRADEMARKS.md](TRADEMARKS.md).
