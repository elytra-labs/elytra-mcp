# Elytra

Local guardrails for coding agents. Elytra checks what Claude Code, Codex, Grok and Antigravity do (shell commands, file edits, web access and MCP tool calls) and holds consequential actions for your decision before they run.

Elytra is early access software. Everything runs on your machine: the runtime, the console and the decision records. An account is optional.

Website and documentation: https://elytra-labs.vercel.app

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

## What setup does

1. Runs the local runtime as a background service (launchd on macOS, `systemd --user` on Linux).
2. Installs action hooks for Claude Code, Codex (a local plugin you trust once), Grok and Antigravity.
3. Wraps local stdio MCP servers for Claude Code, Cursor, Claude Desktop, Windsurf, VS Code, Antigravity, Codex and Grok, with a backup of each configuration.
4. Offers suggested classifications for recognized MCP servers. Unlisted or changed tools wait for your review.
5. Applies a guardrail preset.

| Preset | Behavior |
| --- | --- |
| Balanced (default) | Reads, tests and builds run. Edits, installs, commits and pushes to working branches run in a clean session. After untrusted content, unrecognized commands and installs ask you, and so do edits unless Elytra inspected that content and found it clean. Sends, protected branches, merges, sensitive files, downloaded scripts and deletes ask you. Sending data out after untrusted reads, or sending secrets, is blocked. |
| Cautious | Reads run. Every change and send asks you. Sending data out after untrusted reads, or sending secrets, is blocked. |
| Autonomous | Agents act freely. Deletes, sensitive files and downloaded scripts ask you. Sending data out after untrusted reads, or sending secrets, is blocked. |

In every preset, content that looks like instructions aimed at AI agents makes every change in that session ask, and after the agent reads secrets, sends, pushes and new pull requests ask.

Agent actions are classified as reads, secret reads, untrusted web reads (official documentation sites count as trusted), tests and builds, edits, package installs, sensitive-file changes, unrecognized commands (treated as changes), pushes to working or protected branches, pull requests, sends, downloaded code, and deletes or history rewrites.

Check a setup with `elytra doctor`. See how any command would be decided with `elytra explain "git push origin main"`.

When an action needs you, Claude Code and Grok show their own prompt with Elytra's reason. Codex, Antigravity, and any agent running with permissions bypassed wait up to ten minutes while Elytra sends a desktop notification; an action nobody approves is denied.

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
- Remote HTTP MCP servers are not proxied; their calls are seen through agent hooks.

Read [what Elytra does and does not establish](https://elytra-labs.vercel.app/security) before relying on it.

## Python integration

Orchestrators that create runs explicitly can use the SDK directly:

```python
from mirage_mcp.sdk import RuntimeClient

owner = RuntimeClient()
run = owner.create_run(intent="Inspect an issue", grants=[])
scoped = owner.for_run(run["run_id"], run["run_token"])
```

See the [documentation](https://elytra-labs.vercel.app/docs#integration) for exact grants, approvals and the stdio bridge.

## Upgrade and uninstall

```sh
pipx upgrade elytra-mcp && elytra service restart
elytra uninstall && pipx uninstall elytra-mcp
```

Local records in `~/.elytra` remain until you delete them.

Source: https://github.com/elytra-labs/elytra-mcp · Apache-2.0 licensed. "Elytra" and the Elytra logo are trademarks; see TRADEMARKS.md in the repository.
