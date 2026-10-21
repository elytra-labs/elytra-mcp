"""PreToolUse / PostToolUse hook for Claude Code, Codex, Grok and Antigravity.

One short-lived process per tool call. It classifies the call, asks the local
runtime under the agent's host session, and answers in the calling agent's
hook format. Elytra never grants extra permission: an allowed call returns no
opinion, so the agent's own approval and sandbox rules still apply.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
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
SESSION_TTL = 300  # Reuse a conversation's session for this long before checking the host process again.
READS = {"read_local", "web_read", "web_read_trusted"}
RESPONSE_KEYS = ("tool_response", "toolResponse", "tool_output", "toolOutput", "output", "response", "result")


class _Record:
    """Minimal value object. Plain classes keep the hook's start-up fast (dataclasses import inspect)."""
    __slots__ = ()

    def __eq__(self, other):
        return type(other) is type(self) and all(getattr(self, k) == getattr(other, k) for k in self.__slots__)

    def __repr__(self):
        return f"{type(self).__name__}(" + ", ".join(f"{k}={getattr(self, k)!r}" for k in self.__slots__) + ")"


class HookCall(_Record):
    __slots__ = ("agent", "tool_name", "tool_input", "call_id", "permission_mode", "cwd", "conversation", "response")

    def __init__(self, agent: str, tool_name: str, tool_input: dict, call_id: str, permission_mode: str | None,
                 cwd: str = "", conversation: str = "", response: object = None):
        self.agent, self.tool_name, self.tool_input, self.call_id = agent, tool_name, tool_input, call_id
        self.permission_mode, self.cwd, self.conversation, self.response = permission_mode, cwd, conversation, response


class Verdict(_Record):
    """decision is "none", "deny" or "ask". message is shown without blocking; benign marks a read or no-op
    Elytra allowed (Antigravity needs an explicit decision)."""
    __slots__ = ("decision", "reason", "message", "benign")

    def __init__(self, decision: str, reason: str = "", message: str = "", benign: bool = False):
        self.decision, self.reason, self.message, self.benign = decision, reason, message, benign


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
    roots = payload.get("workspace_roots") or payload.get("workspaceRoots") or []
    cwd = payload.get("cwd") or payload.get("workingDirectory") or (roots[0] if isinstance(roots, list) and roots else "") or ""
    conversation = payload.get("session_id") or payload.get("sessionId") or payload.get("conversation_id") or payload.get("conversationId") or ""
    response = next((payload[k] for k in RESPONSE_KEYS if k in payload), None)
    return HookCall(agent, str(name), tool_input if isinstance(tool_input, dict) else {}, "hook_" + safe_id, mode,
                    str(cwd)[:4096], str(conversation)[:200], response)


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


def _describe(call: HookCall, action, label: str) -> str:
    """Name the action the way the person would: the command, the file, or the MCP tool."""
    command = call.tool_input.get("command") or call.tool_input.get("cmd")
    if isinstance(command, list):
        command = " ".join(str(part) for part in command)
    if isinstance(command, str) and command.strip():
        text = " ".join(command.split())
        return "`" + (text if len(text) <= 80 else text[:77] + "...") + "`"
    path = call.tool_input.get("file_path") or call.tool_input.get("path")
    if action.kind == "builtin" and isinstance(path, str) and path:
        verb = {"edit_files": "Editing", "delete_files": "Deleting"}.get(action.tool, "Changing")
        return f"{verb} {Path(path).name}"
    url = call.tool_input.get("url")
    if action.kind == "builtin" and isinstance(url, str) and url:
        return f"Fetching {url[:80]}"
    return label


def decide(call: HookCall, host: dict | None, open_session: Callable[[dict], object], sleep=time.sleep) -> Verdict:
    from mirage_mcp.sdk import RuntimeAPIError

    action = classify(call.tool_name, call.tool_input, {"cwd": call.cwd} if call.cwd else None)
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
        decision = client.evaluate(server, tool, action.arguments, call.call_id, notify=not interactive, claim=True)
        if decision["decision"] == "ALLOW":
            return Verdict("none", benign=action.kind == "builtin" and action.tool in {"read_local", "web_read"})
        reason = decision.get("reason") or "Not authorized by Elytra"
        label = f"{server}.{tool}"
        what = _describe(call, action, label)
        if decision["decision"] == "BLOCK":
            if reason.startswith("Tool is unknown"):
                if interactive:
                    return Verdict("ask", f"Elytra has not classified {label}. Approve only if you expect this action; classify it in the Elytra console to stop being asked.")
                return Verdict("deny", f"Elytra: {label} is not classified yet. Classify it in the Elytra console (Tool integrity), then retry.")
            return Verdict("deny", f"Elytra blocked {what}. {reason}.")
        # Held for a decision.
        if interactive:
            try:
                client.cancel(call.call_id)
            except RuntimeAPIError:
                pass
            return Verdict("ask", f"Elytra: {what}. {reason}.")
        deadline = time.monotonic() + float(host.get("approval_window", 600))
        while time.monotonic() < deadline:
            sleep(1.0)
            status = client.call_status(call.call_id)
            if status["decision"] == "ALLOW":
                client.claim(call.call_id, status["permit"], action.arguments)
                return Verdict("none")
            if status["decision"] != "STEP_UP":
                return Verdict("deny", f"Elytra: {what} was not approved ({status.get('reason', status.get('status', 'denied'))}).")
        try:
            client.cancel(call.call_id)
        except RuntimeAPIError:
            pass
        return Verdict("deny", f"Elytra: {what} waited for your decision and expired. Review it in the Elytra console, then retry.")
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
    action = classify(call.tool_name, call.tool_input, {"cwd": call.cwd} if call.cwd else None)
    if action.kind not in {"builtin", "mcp"}:
        return
    try:
        client = open_session(host)
        client.complete(call.call_id, {"recorded_by": "elytra-hook"})
    except (RuntimeAPIError, KeyError, ValueError, RuntimeError):
        return  # Calls that were not claimed (no opinion, cancelled, deferred) have nothing to complete.
    # Inspect what a read brought into the agent's context. Findings raise the session's taint; a clean
    # untrusted read is marked as inspected. Results are never sent anywhere, only the verdict and a snippet.
    if call.response is not None and (action.kind == "mcp" or action.tool in READS):
        from mirage_mcp.security.injection_guard import scan
        try:
            client.report_scan(call.call_id, scan(call.response))
        except (RuntimeAPIError, KeyError, ValueError, RuntimeError):
            pass


def _conversation_cache(host: dict, conversation: str, home: Path | None = None) -> Path:
    digest = hashlib.sha256(f"{host['host_id']}:{conversation}".encode()).hexdigest()[:32]
    return ((home / ".elytra" / "hosts") if home else HOSTS_DIR) / "sessions" / f"{digest}.json"


def _open(host: dict, conversation: str = "", home: Path | None = None):
    """The agent's session: one per conversation when the agent reports one, else one per agent process.

    A conversation's session is cached (0600) so later calls skip identifying the host process; it is
    reopened when the runtime rejects it or after SESSION_TTL.
    """
    from mirage_mcp.proxy.host_session import HostSessionClient, host_session_key
    gateway = host.get("gateway", GATEWAY)
    if not conversation:
        return HostSessionClient(host["host_id"], host["host_token"], host_session_key(), gateway)
    key = hashlib.sha256(f"{host['host_id']}:conversation:{conversation}".encode()).hexdigest()[:32]
    cache = _conversation_cache(host, conversation, home)
    resume = None
    try:
        if time.time() - cache.stat().st_mtime < SESSION_TTL:
            saved = json.loads(cache.read_text())
            if saved.get("host_id") == host["host_id"] and saved.get("gateway") == gateway:
                resume = saved
    except (OSError, ValueError):
        resume = None

    def remember(session: dict):
        try:
            cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temp = cache.with_suffix(".tmp")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump({"host_id": host["host_id"], "gateway": gateway, "run_id": session["run_id"], "run_token": session["run_token"],
                           "approval_window": session.get("approval_window")}, stream)
            os.replace(temp, cache)
        except OSError:
            pass  # Caching is an optimization; the session still works.

    return HostSessionClient(host["host_id"], host["host_token"], key, gateway, parent_key=host_session_key, resume=resume, on_open=remember)


def run(event: str, stdin: str, hint: str | None = None, home: Path | None = None, open_session=None) -> str:
    try:
        payload = json.loads(stdin or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    call = detect(payload, hint)
    host = load_host(call.agent, home)
    if open_session is None:
        open_session = lambda h: _open(h, call.conversation, home)
    if event == "post":
        complete(call, host, open_session)
        return render(call.agent, "post", Verdict("none"))
    return render(call.agent, "pre", decide(call, host, open_session))
