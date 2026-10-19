"""Install and remove Elytra's action hooks in coding agents, and wrap CLI-managed MCP servers.

Hooks: Claude Code (~/.claude/settings.json, also read by Grok), Grok
(~/.grok/hooks/elytra.json), Antigravity (~/.gemini/config/hooks.json, a named
"elytra" entry) and Codex (a local plugin marketplace). Every change is marked
so uninstall removes only Elytra's entries and leaves the user's own hooks.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from mirage_mcp.cli import hosts as host_files

MARK = "mirage_mcp.hooks"
CODEX_MARKETPLACE = "elytra-local"
CODEX_PLUGIN = "elytra"


@dataclass(frozen=True)
class Agent:
    kind: str
    label: str
    binary: str
    home_dir: str  # presence of ~/<home_dir> also counts as installed


AGENTS = (
    Agent("claude-code", "Claude Code", "claude", ".claude"),
    Agent("codex", "Codex", "codex", ".codex"),
    Agent("grok", "Grok", "grok", ".grok"),
    Agent("antigravity", "Antigravity", "agy", ".gemini"),
)


def installed_agents(home: Path | None = None) -> list[Agent]:
    home = home or Path.home()
    return [a for a in AGENTS if shutil.which(a.binary) or (home / a.home_dir).is_dir()]


def hook_command(event: str, agent: str | None = None) -> str:
    parts = [sys.executable, "-m", MARK, event]
    if agent:
        parts += ["--agent", agent]
    return shlex.join(parts)


def _ours(group: dict) -> bool:
    return any(MARK in str(h.get("command", "")) for h in group.get("hooks", []) if isinstance(h, dict))


def _read_json(path: Path) -> dict:
    if not path.exists() or not path.read_text().strip():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        host_files.backup(path)
        host_files.write(path, data)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")


# Claude-format hook blocks (Claude Code settings, Grok hook files) -----------------

def _claude_blocks(timeout: int, agent: str | None = None) -> dict:
    return {
        "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": hook_command("pre", agent), "timeout": timeout}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": hook_command("post", agent), "timeout": 30}]}],
    }


def _merge_claude_hooks(data: dict, blocks: dict) -> dict:
    hooks = data.setdefault("hooks", {})
    for event, groups in blocks.items():
        existing = [g for g in hooks.get(event, []) if isinstance(g, dict) and not _ours(g)]
        hooks[event] = existing + groups
    return data


def _strip_claude_hooks(data: dict) -> bool:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    changed = False
    for event in list(hooks):
        groups = hooks[event] if isinstance(hooks[event], list) else []
        kept = [g for g in groups if not (isinstance(g, dict) and _ours(g))]
        if len(kept) != len(groups):
            changed = True
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
    if changed and not hooks:
        del data["hooks"]
    return changed


def _run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=120)


class HookInstaller:
    def __init__(self, home: Path | None = None, runner=_run):
        self.home = home or Path.home()
        self.run = runner

    # Paths
    @property
    def claude_settings(self) -> Path:
        return self.home / ".claude" / "settings.json"

    @property
    def grok_hooks(self) -> Path:
        return self.home / ".grok" / "hooks" / "elytra.json"

    @property
    def antigravity_hooks(self) -> Path:
        return self.home / ".gemini" / "config" / "hooks.json"

    @property
    def codex_marketplace(self) -> Path:
        return self.home / ".elytra" / "codex-marketplace"

    def install(self, kind: str, approval_window: int) -> str:
        timeout = approval_window + 30
        if kind == "claude-code":
            _write_json(self.claude_settings, _merge_claude_hooks(_read_json(self.claude_settings), _claude_blocks(timeout)))
            return "Restart Claude Code to load the hooks."
        if kind == "grok":
            # Grok also reads ~/.claude/settings.json; identical handlers are deduplicated.
            _write_json(self.grok_hooks, {"hooks": _claude_blocks(timeout)})
            return "Restart Grok, then run /hooks to confirm Elytra's hooks loaded."
        if kind == "antigravity":
            data = _read_json(self.antigravity_hooks)
            data["elytra"] = {"enabled": True, **{event: [{"matcher": "*", "hooks": [{"type": "command", "command": hook_command(event_key, "antigravity"), "timeout": t}]}]
                                                  for event, event_key, t in (("PreToolUse", "pre", timeout), ("PostToolUse", "post", 30))}}
            _write_json(self.antigravity_hooks, data)
            return "Restart Antigravity to load the hooks."
        if kind == "codex":
            self._write_codex_marketplace(timeout)
            for command in (["codex", "plugin", "marketplace", "add", str(self.codex_marketplace)],
                            ["codex", "plugin", "add", f"{CODEX_PLUGIN}@{CODEX_MARKETPLACE}"]):
                result = self.run(command)
                if result.returncode != 0 and "already" not in (result.stderr + result.stdout).lower():
                    raise RuntimeError(f"`{' '.join(command[:4])}` failed: {(result.stderr or result.stdout).strip()[:300]}")
            return "Open Codex and approve Elytra's hooks when it asks you to trust them."
        raise ValueError(f"Unknown agent {kind}")

    def uninstall(self, kind: str) -> bool:
        if kind == "claude-code":
            data = _read_json(self.claude_settings) if self.claude_settings.exists() else {}
            if _strip_claude_hooks(data):
                host_files.write(self.claude_settings, data)
                return True
            return False
        if kind == "grok":
            if self.grok_hooks.exists():
                self.grok_hooks.unlink()
                return True
            return False
        if kind == "antigravity":
            data = _read_json(self.antigravity_hooks) if self.antigravity_hooks.exists() else {}
            if data.pop("elytra", None) is not None:
                host_files.write(self.antigravity_hooks, data)
                return True
            return False
        if kind == "codex":
            removed = False
            for command in (["codex", "plugin", "remove", f"{CODEX_PLUGIN}@{CODEX_MARKETPLACE}"],
                            ["codex", "plugin", "marketplace", "remove", CODEX_MARKETPLACE]):
                if shutil.which("codex") or self.run is not _run:
                    removed = self.run(command).returncode == 0 or removed
            if self.codex_marketplace.exists():
                shutil.rmtree(self.codex_marketplace)
                removed = True
            # `codex plugin remove` can leave an empty cache folder behind.
            cache = self.home / ".codex" / "plugins" / "cache" / CODEX_MARKETPLACE
            if cache.is_dir() and not any(cache.iterdir()):
                cache.rmdir()
            return removed
        return False

    def installed(self, kind: str) -> bool:
        try:
            if kind == "claude-code":
                return any(_ours(g) for g in _read_json(self.claude_settings).get("hooks", {}).get("PreToolUse", []))
            if kind == "grok":
                return self.grok_hooks.exists()
            if kind == "antigravity":
                return "elytra" in _read_json(self.antigravity_hooks)
            if kind == "codex":
                return (self.codex_marketplace / "plugins" / CODEX_PLUGIN / "hooks" / "hooks.json").exists()
        except (OSError, ValueError):
            return False
        return False

    def _write_codex_marketplace(self, timeout: int) -> None:
        root = self.codex_marketplace
        plugin = root / "plugins" / CODEX_PLUGIN
        (root / ".agents" / "plugins").mkdir(parents=True, exist_ok=True)
        (plugin / ".codex-plugin").mkdir(parents=True, exist_ok=True)
        (plugin / "hooks").mkdir(parents=True, exist_ok=True)
        files = {
            root / ".agents" / "plugins" / "marketplace.json": {
                "name": CODEX_MARKETPLACE, "description": "Elytra guardrails installed by elytra setup",
                "owner": {"name": "Elytra", "url": "https://elytra-labs.vercel.app"},
                "plugins": [{"name": CODEX_PLUGIN, "description": "Checks Codex's shell, file and web actions against your Elytra guardrails",
                             "source": f"./plugins/{CODEX_PLUGIN}", "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                             "version": "0.4.0", "category": "security", "tags": ["security", "guardrails"]}],
            },
            plugin / ".codex-plugin" / "plugin.json": {
                "name": CODEX_PLUGIN, "description": "Elytra guardrails for Codex actions", "version": "0.4.0",
                "author": {"name": "Elytra", "url": "https://elytra-labs.vercel.app"}, "homepage": "https://github.com/elytra-labs/elytra-mcp",
            },
            plugin / "hooks" / "hooks.json": {"hooks": {
                "PreToolUse": [{"hooks": [{"type": "command", "command": hook_command("pre", "codex"), "timeout": timeout}]}],
                "PostToolUse": [{"hooks": [{"type": "command", "command": hook_command("post", "codex"), "timeout": 30}]}],
            }},
        }
        for path, content in files.items():
            path.write_text(json.dumps(content, indent=2) + "\n")


# Host credential index used by the hook process ------------------------------------

def hosts_dir(home: Path | None = None) -> Path:
    return (home or Path.home()) / ".elytra" / "hosts"


def read_index(home: Path | None = None) -> dict:
    try:
        return json.loads((hosts_dir(home) / "index.json").read_text())
    except (OSError, ValueError):
        return {}


def save_credential(kind: str, credential: dict, *, approval_window: int, fail_closed: bool, gateway: str,
                    wrapped_servers: list[str], home: Path | None = None) -> None:
    folder = hosts_dir(home)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(folder, 0o700)
    token_path = folder / f"{credential['host_id']}.token"
    if not token_path.exists():
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(credential["host_token"] + "\n")
    index = read_index(home)
    index[kind] = {"host_id": credential["host_id"], "approval_window": approval_window, "fail_closed": fail_closed,
                   "gateway": gateway, "wrapped_servers": sorted(set(wrapped_servers))}
    path = folder / "index.json"
    tmp = folder / ".index.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(index, stream, indent=2)
    os.replace(tmp, path)


def load_credential(kind: str, home: Path | None = None) -> dict | None:
    entry = read_index(home).get(kind)
    if not entry:
        return None
    try:
        token = (hosts_dir(home) / f"{entry['host_id']}.token").read_text().strip()
    except OSError:
        return None
    return {"host_id": entry["host_id"], "host_token": token}


def forget_credentials(home: Path | None = None) -> list[str]:
    folder = hosts_dir(home)
    ids = [entry["host_id"] for entry in read_index(home).values() if isinstance(entry, dict) and "host_id" in entry]
    if folder.exists():
        shutil.rmtree(folder)
    return ids


# CLI-managed MCP servers (Codex and Grok keep them in TOML) ----------------------------

SAFE_FIELDS = {"command", "args", "env", "enabled", "name", "scope", "transport", "type"}


def cli_servers(kind: str, runner=_run, home: Path | None = None) -> list[dict]:
    """Stdio servers as the agent's own CLI reports them: name, command, args, env, extra fields."""
    if kind == "grok":
        result = runner(["grok", "mcp", "list", "--json"])
        if result.returncode != 0:
            return []
        entries = json.loads(result.stdout or "[]")
        return [e for e in entries if isinstance(e, dict) and e.get("command") and e.get("scope", "user") == "user"]
    if kind == "codex":
        import tomllib
        path = (home or Path.home()) / ".codex" / "config.toml"
        try:
            servers = tomllib.loads(path.read_text()).get("mcp_servers") or {}
        except (OSError, ValueError):
            return []
        return [{"name": name, **entry} for name, entry in servers.items() if isinstance(entry, dict) and entry.get("command")]
    return []


def wrap_cli_server(kind: str, server: dict, host_id: str, host_token: str, gateway: str, runner=_run) -> str | None:
    """Re-register a server through Elytra's proxy with the agent's CLI. Returns why it was skipped, or None."""
    extra = set(server) - SAFE_FIELDS
    if extra:
        return f"uses {', '.join(sorted(extra))}, which `{kind} mcp add` cannot reproduce; its calls are still checked by the hook"
    if server.get("enabled") is False:
        return "disabled"
    if MARK.replace(".hooks", ".cli.main") in " ".join(map(str, server.get("args", []))):
        return "already protected"
    launcher, prefix = host_files.proxy_launch(server["name"], host_id, gateway)
    env = {**(server.get("env") or {}), "ELYTRA_HOST_TOKEN": host_token}
    env_flags = [flag for key, value in env.items() for flag in ("--env" if kind == "codex" else "-e", f"{key}={value}")]
    if kind == "codex":
        runner(["codex", "mcp", "remove", server["name"]])
        command = ["codex", "mcp", "add", *env_flags, server["name"], "--", launcher, *prefix, server["command"], *server.get("args", [])]
    else:
        command = ["grok", "mcp", "add", *env_flags, server["name"], launcher, "--", *prefix, server["command"], *server.get("args", [])]
    result = runner(command)
    if result.returncode != 0:
        return "the agent's CLI refused the change: " + (result.stderr or result.stdout).strip()[:200]
    return None


def restore_cli_server(kind: str, original: dict, runner=_run) -> bool:
    env_flags = [flag for key, value in (original.get("env") or {}).items() for flag in ("--env" if kind == "codex" else "-e", f"{key}={value}")]
    if kind == "codex":
        runner(["codex", "mcp", "remove", original["name"]])
        command = ["codex", "mcp", "add", *env_flags, original["name"], "--", original["command"], *original.get("args", [])]
    else:
        command = ["grok", "mcp", "add", *env_flags, original["name"], original["command"], "--", *original.get("args", [])]
    return runner(command).returncode == 0


def originals_path(kind: str, home: Path | None = None) -> Path:
    return hosts_dir(home) / f"{kind}-mcp-originals.json"


def save_originals(kind: str, servers: list[dict], home: Path | None = None) -> None:
    path = originals_path(kind, home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing = {s["name"]: s for s in load_originals(kind, home)}
    existing.update({s["name"]: s for s in servers})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(list(existing.values()), stream, indent=2)


def load_originals(kind: str, home: Path | None = None) -> list[dict]:
    try:
        return json.loads(originals_path(kind, home).read_text())
    except (OSError, ValueError):
        return []
