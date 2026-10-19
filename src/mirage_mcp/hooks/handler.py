"""PreToolUse / PostToolUse hook for Claude Code, Codex, Grok and Antigravity.

One short-lived process per tool call. It classifies the call, asks the local
runtime under the agent's host session, and answers in the calling agent's
hook format. Elytra never grants extra permission: an allowed call returns no
opinion, so the agent's own approval and sandbox rules still apply.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from mirage_mcp.hooks.classify import SERVER, classify

HOSTS_DIR = Path.home() / ".elytra" / "hosts"
INDEX = "index.json"
GATEWAY = "http://127.0.0.1:8765"
# Agents that report their permission mode, so a native "ask" is known to reach a person.
# Antigravity does not report it (a skip-permissions run would auto-approve an ask), so it waits for Elytra.
ASK_CAPABLE = {"claude-code", "grok"}
NON_INTERACTIVE_MODES = {"bypassPermissions", "dontAsk"}


@dataclass
class HookCall:
    agent: str
    tool_name: str
    tool_input: dict
    call_id: str
    permission_mode: str | None


@dataclass
class Verdict:
    decision: str  # "none", "deny", "ask"
    reason: str = ""
    message: str = ""  # shown to the user without blocking
    benign: bool = False  # a read or no-op Elytra allowed (Antigravity needs an explicit decision)


def detect(payload: dict, hint: str | None) -> HookCall:
    if "toolCall" in payload:
        agent = "antigravity"
        call = payload.get("toolCall") or {}
        name, tool_input = call.get("name", ""), call.get("args") or {}
        use_id = f"{payload.get('conversationId', '')}-{payload.get('stepIdx', '')}"
    elif "hookEventName" in payload or "toolName" in payload:
        agent = "grok"
        name, tool_input = payload.get("toolName", ""), payload.get("toolInput") or {}
        use_id = payload.get("toolUseId") or payload.get("promptId") or ""
    else:
        agent = hint or ("codex" if "turn_id" in payload else "claude-code")
        name, tool_input = payload.get("tool_name", ""), payload.get("tool_input") or {}
        use_id = payload.get("tool_use_id") or ""
    mode = payload.get("permission_mode") or payload.get("permissionMode")
    safe_id = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(use_id))[:180] or "unknown"
    return HookCall(agent, str(name), tool_input if isinstance(tool_input, dict) else {}, "hook_" + safe_id, mode)


def render(agent: str, event: str, verdict: Verdict) -> str:
    """Hook stdout for the calling agent. Empty string means no opinion."""
    if agent == "antigravity":
        if event == "post":
            return "{}"
        if verdict.decision in {"deny", "ask"}:
            return json.dumps({"decision": "deny", "reason": verdict.reason})
        # Antigravity requires a decision; no decision denies. "allow" auto-approves, so it is used only for
        # reads and no-ops. Other actions Elytra allowed go to Antigravity's own permission flow ("ask").
        if verdict.benign:
            return json.dumps({"decision": "allow"})
        return json.dumps({"decision": "ask", "reason": verdict.message or "Allowed by your Elytra guardrails"})
    if event == "post" or verdict.decision == "none":
        return json.dumps({"systemMessage": verdict.message}) if verdict.message else ""
    if verdict.decision == "ask" and agent not in ASK_CAPABLE:
        verdict = Verdict("deny", verdict.reason)
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": verdict.decision,
                                              "permissionDecisionReason": verdict.reason}})


def load_host(agent: str, home: Path | None = None) -> dict | None:
    folder = (home / ".elytra" / "hosts") if home else HOSTS_DIR
    try:
        index = json.loads((folder / INDEX).read_text())
    except (OSError, ValueError):
        return None
    entry = index.get(agent) or (index.get("claude-code") if agent == "grok" else None)
    if not entry:
        return None
    try:
        token = (folder / f"{entry['host_id']}.token").read_text().strip()
    except OSError:
        return None
    return {**entry, "host_token": token}


def _normalize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", name)


def decide(call: HookCall, host: dict | None, open_session: Callable[[dict], object], sleep=time.sleep) -> Verdict:
    from mirage_mcp.sdk import RuntimeAPIError

    action = classify(call.tool_name, call.tool_input)
    if action.kind == "protected":
        return Verdict("deny", f"Elytra: {action.reason}.")
    if action.kind == "ignore":
        return Verdict("none", benign=True)
    if not host:
        return Verdict("none")
    if action.kind == "mcp" and _normalize(action.server) in {_normalize(s) for s in host.get("wrapped_servers", [])}:
        return Verdict("none")  # The Elytra MCP proxy already enforces this server.
    server, tool = (action.server, action.tool) if action.kind == "mcp" else (SERVER, action.tool)
    interactive = call.agent in ASK_CAPABLE and call.permission_mode not in NON_INTERACTIVE_MODES
    try:
        client = open_session(host)
        if action.kind == "mcp":
            client.observe_tool(server, tool)
        decision = client.evaluate(server, tool, action.arguments, call.call_id, notify=not interactive)
        if decision["decision"] == "ALLOW":
            client.claim(call.call_id, decision["permit"], action.arguments)
            return Verdict("none", benign=action.kind == "builtin" and action.tool in {"read_local", "web_read"})
        reason = decision.get("reason") or "Not authorized by Elytra"
        label = f"{server}.{tool}"
        if decision["decision"] == "BLOCK":
            if reason.startswith("Tool is unknown"):
                if interactive:
                    return Verdict("ask", f"Elytra has not classified {label}. Approve only if you expect this action; classify it in the Elytra console to stop being asked.")
                return Verdict("deny", f"Elytra: {label} is not classified yet. Classify it in the Elytra console (Tool integrity), then retry.")
            return Verdict("deny", f"Elytra blocked {label}: {reason}.")
        # Held for a decision.
        if interactive:
            try:
                client.cancel(call.call_id)
            except RuntimeAPIError:
                pass
            return Verdict("ask", f"Elytra: {reason}. {label} needs your decision.")
        deadline = time.monotonic() + float(host.get("approval_window", 600))
        while time.monotonic() < deadline:
            sleep(1.0)
            status = client.call_status(call.call_id)
            if status["decision"] == "ALLOW":
                client.claim(call.call_id, status["permit"], action.arguments)
                return Verdict("none")
            if status["decision"] != "STEP_UP":
                return Verdict("deny", f"Elytra: {label} was not approved ({status.get('reason', status.get('status', 'denied'))}).")
        try:
            client.cancel(call.call_id)
        except RuntimeAPIError:
            pass
        return Verdict("deny", f"Elytra: {label} waited for approval and expired. Review it in the Elytra console, then retry.")
    except RuntimeAPIError as exc:
        if exc.status == 0:
            if host.get("fail_closed"):
                return Verdict("deny", "Elytra runtime is not running, and this agent is set to fail closed. Start it with `elytra service start`.")
            return Verdict("none", message="Elytra runtime is not running; this action was not checked.")
        return Verdict("deny", f"Elytra could not evaluate this action: {exc}")


def complete(call: HookCall, host: dict | None, open_session: Callable[[dict], object]) -> None:
    from mirage_mcp.sdk import RuntimeAPIError
    if not host:
        return
    action = classify(call.tool_name, call.tool_input)
    if action.kind not in {"builtin", "mcp"}:
        return
    try:
        open_session(host).complete(call.call_id, {"recorded_by": "elytra-hook"})
    except (RuntimeAPIError, KeyError, ValueError):
        pass  # Calls that were not claimed (no opinion, cancelled, deferred) have nothing to complete.


def _open(host: dict):
    from mirage_mcp.proxy.host_session import HostSessionClient, host_session_key
    return HostSessionClient(host["host_id"], host["host_token"], host_session_key(), host.get("gateway", GATEWAY))


def run(event: str, stdin: str, hint: str | None = None, home: Path | None = None, open_session=_open) -> str:
    try:
        payload = json.loads(stdin or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    call = detect(payload, hint)
    host = load_host(call.agent, home)
    if event == "post":
        complete(call, host, open_session)
        return render(call.agent, "post", Verdict("none"))
    return render(call.agent, "pre", decide(call, host, open_session))
