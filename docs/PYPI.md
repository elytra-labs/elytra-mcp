# Elytra

Local guardrails for coding agents. Elytra checks what Claude Code, Codex, Grok and Antigravity do (shell commands, file edits, web access and MCP tool calls) and holds consequential actions for your decision before they run.

Elytra is early access software. Everything runs on your machine: the runtime, the console and the decision records. There is no account to create.

Website and documentation: https://elytra-gray.vercel.app

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
| Balanced (default) | Reads run. Writes run in a clean session. Writes after the agent reads untrusted content, sends, and deletes ask you. Sending data out after untrusted reads is blocked. |
| Cautious | Every write and send asks you. |
| Autonomous | Only destructive actions ask you. Sending data out after untrusted reads is blocked. |

Agent actions are classified as reads, untrusted web reads, edits, unrecognized commands (treated as writes), sends (push, post, publish, upload), and deletes or history rewrites.

When an action needs you, Claude Code and Grok show their own prompt with Elytra's reason. Codex, Antigravity, and any agent running with permissions bypassed wait up to ten minutes while Elytra sends a desktop notification; an action nobody approves is denied.

## Limits

- Shell classification is a heuristic. A disguised command, or a script the agent writes and runs, may only be recognized as an unrecognized command, which is treated as a write.
- Self-protection is best-effort. Elytra denies agents reading its credentials or calling its local API, but any process running as you can read your files.
- Coverage is per agent process, not per conversation.
- If the runtime is not running, actions go through with a visible warning, unless you set up with `--fail-closed`.
- Remote HTTP MCP servers are not proxied; their calls are seen through agent hooks.

Read [what Elytra does and does not establish](https://elytra-gray.vercel.app/security) before relying on it.

## Python integration

Orchestrators that create runs explicitly can use the SDK directly:

```python
from mirage_mcp.sdk import RuntimeClient

owner = RuntimeClient()
run = owner.create_run(intent="Inspect an issue", grants=[])
scoped = owner.for_run(run["run_id"], run["run_token"])
```

See the [documentation](https://elytra-gray.vercel.app/docs#integration) for exact grants, approvals and the stdio bridge.

## Upgrade and uninstall

```sh
pipx upgrade elytra-mcp && elytra service restart
elytra uninstall && pipx uninstall elytra-mcp
```

Local records in `~/.elytra` remain until you delete them.

Source: https://github.com/elytra-labs/elytra-mcp · Apache-2.0 licensed. "Elytra" and the Elytra logo are trademarks; see TRADEMARKS.md in the repository.
