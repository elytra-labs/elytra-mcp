# Elytra

Local guardrails for coding agents. Elytra checks what Claude Code, Codex, Grok and Antigravity do (shell commands, file edits, web access and MCP tool calls) and holds consequential actions for your decision before they run.

Everything runs on your machine: the runtime, the console and the decision records. An account is optional.

[Website](https://elytra-labs.vercel.app) · [Documentation](https://elytra-labs.vercel.app/docs) · [Security model](https://elytra-labs.vercel.app/security) · [PyPI](https://pypi.org/project/elytra-mcp/)

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

- **Agent hooks** (`src/mirage_mcp/hooks/`): one short-lived process per tool call. Shell commands, file edits and web access are classified into fixed actions (reads, secret reads, untrusted web reads, tests and builds, edits, installs, sensitive files, pushes, pull requests, sends, downloaded code, deletes and history rewrites), and what reads return is inspected for prompt injection.
- **MCP proxy** (`src/mirage_mcp/proxy/`): wraps local stdio MCP servers. Unknown, changed or suspicious tools wait for your review.
- **Runtime** (`src/mirage_mcp/runtime/`): a loopback-only service with a SQLite ledger. Each call is decided against your guardrail preset and rules. An allowed call gets a single-use permit bound to its exact arguments. Anything read from outside (an issue, a page, an email) marks the session as untrusted for what follows, at a level set by whether Elytra could inspect it and what it found.
- **Console** (`ui/`): React app served by the runtime at `http://127.0.0.1:8765/app/`. The same `ui/` builds the public website.

| Preset | Behavior |
| --- | --- |
| Balanced (default) | Reads, tests and builds run. Edits, installs, commits and pushes to working branches run in a clean session. After untrusted content, unrecognized commands and installs ask you, and so do edits unless Elytra inspected that content and found it clean. Sends, protected branches, merges, sensitive files, downloaded scripts and deletes ask you. Sending data out after untrusted reads, or sending secrets, is blocked. |
| Cautious | Reads run. Every change and send asks you. Sending data out after untrusted reads, or sending secrets, is blocked. |
| Autonomous | Agents act freely. Deletes, sensitive files and downloaded scripts ask you. Sending data out after untrusted reads, or sending secrets, is blocked. |

In every preset, content that looks like instructions aimed at AI agents makes every change in that session ask, and after the agent reads secrets, sends, pushes and new pull requests ask.

Check a setup with `elytra doctor`. See how any command would be decided with `elytra explain "git push origin main"`.

Claude Code and Grok show their own prompt with Elytra's reason. Codex, Antigravity, and agents running with permissions bypassed wait up to ten minutes while Elytra sends a desktop notification; an action nobody approves is denied.

## Approve from your phone

Codex, Antigravity and agents running with permissions bypassed wait up to ten minutes when Elytra holds an action. To decide from another device, link a free account (GitHub or Google sign-in):

```sh
pipx install 'elytra-mcp[cloud]'   # the link needs the cloud extra
elytra link
```

Held actions then appear in your dashboard at https://elytra-labs.vercel.app/app/. Your guardrails, history and decisions stay on your machine; only redacted summaries of held actions are sent, never tool results or credentials. A decision is signed, bound to that exact action and checked by your machine before anything runs. If the link is down, the action keeps waiting for you. `elytra unlink` stops it.

## Limits

- Shell classification is a heuristic. A disguised command, or a script the agent writes and runs, may only be recognized as an unrecognized command, which is treated as a change.
- Self-protection is best-effort. Elytra denies agents reading its credentials or calling its local API, but any process running as you can read your files.
- Agent hooks follow each conversation. Wrapped MCP servers cannot tell conversations apart, so what they read counts for every conversation in that agent process.
- Content inspection is a heuristic. A page with no injection markers can still steer a local edit in Balanced; review diffs before merging, or use Cautious.
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

See the [integration guide](https://elytra-labs.vercel.app/docs#integration) for exact grants, approvals and the stdio bridge.

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
