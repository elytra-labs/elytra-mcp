"""Find agent hosts' MCP configurations and route their stdio servers through Elytra.

Wrapping keeps each server's original launch entry under ``_elytra_original``
so ``elytra uninstall`` restores it exactly. Remote (HTTP/SSE) servers are
reported, not changed: they do not run through a local stdio bridge.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ORIGINAL = "_elytra_original"
HOST_MARK = "_elytra_host"


@dataclass(frozen=True)
class HostSpec:
    kind: str
    label: str
    files: tuple[str, ...]  # relative to home (~) or the working directory (./)


HOSTS = (
    HostSpec("claude-code", "Claude Code", ("~/.claude.json", "./.mcp.json")),
    HostSpec("cursor", "Cursor", ("~/.cursor/mcp.json", "./.cursor/mcp.json")),
    HostSpec("claude-desktop", "Claude Desktop", ("~/Library/Application Support/Claude/claude_desktop_config.json", "~/.config/Claude/claude_desktop_config.json")),
    HostSpec("windsurf", "Windsurf", ("~/.codeium/windsurf/mcp_config.json",)),
    HostSpec("vscode", "VS Code", ("./.vscode/mcp.json",)),
    HostSpec("antigravity", "Antigravity", ("~/.gemini/config/mcp_config.json",)),
)


@dataclass
class ServerEntry:
    name: str
    entry: dict
    location: str  # human-readable place in the file

    @property
    def stdio(self) -> bool:
        return isinstance(self.entry.get("command"), str) and self.entry.get("type", "stdio") == "stdio"

    @property
    def wrapped(self) -> bool:
        return ORIGINAL in self.entry or "_mirage_original" in self.entry

    @property
    def launch(self) -> tuple[str, list[str]]:
        original = self.entry.get(ORIGINAL) or self.entry
        return original.get("command", ""), list(original.get("args", []))


@dataclass
class HostConfig:
    spec: HostSpec
    path: Path
    data: dict
    servers: list[ServerEntry] = field(default_factory=list)


def _resolve(pattern: str, home: Path, cwd: Path) -> Path:
    if pattern.startswith("~/"):
        return home / pattern[2:]
    return cwd / pattern[2:]


def _server_maps(data: dict) -> list[tuple[str, dict]]:
    """Every server map in a host file: top-level, plus Claude Code's per-project maps."""
    maps = []
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            maps.append((key, data[key]))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, settings in projects.items():
            if isinstance(settings, dict) and isinstance(settings.get("mcpServers"), dict):
                maps.append((f"project {project}", settings["mcpServers"]))
    return maps


def discover(home: Path | None = None, cwd: Path | None = None) -> list[HostConfig]:
    home, cwd = home or Path.home(), cwd or Path.cwd()
    found: list[HostConfig] = []
    seen: set[Path] = set()
    for spec in HOSTS:
        for pattern in spec.files:
            path = _resolve(pattern, home, cwd)
            if path in seen or not path.is_file() or path.is_symlink():
                continue
            seen.add(path)
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            config = HostConfig(spec, path, data)
            for location, servers in _server_maps(data):
                for name, entry in servers.items():
                    if isinstance(entry, dict):
                        config.servers.append(ServerEntry(name, entry, location))
            if config.servers:
                found.append(config)
    return found


def proxy_launch(server_name: str, host_id: str, gateway: str) -> tuple[str, list[str]]:
    # An absolute interpreter path works even when a GUI host has a minimal PATH.
    return sys.executable, ["-m", "mirage_mcp.cli.main", "proxy", "--server-name", server_name,
                            "--host-id", host_id, "--gateway", gateway, "--"]


def wrap_entry(server: ServerEntry, host_id: str, host_token: str, gateway: str) -> bool:
    entry = server.entry
    if server.wrapped or not server.stdio:
        return False
    command, args = entry["command"], entry.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError(f"{server.name}: unsupported launch arguments")
    entry[ORIGINAL] = {key: entry[key] for key in ("command", "args", "env") if key in entry}
    launcher, prefix = proxy_launch(server.name, host_id, gateway)
    entry["command"] = launcher
    entry["args"] = [*prefix, command, *args]
    entry["env"] = {**entry.get("env", {}), "ELYTRA_HOST_TOKEN": host_token}
    entry[HOST_MARK] = host_id
    return True


def unwrap_entry(entry: dict) -> str | None:
    """Restore an entry. Returns the host id it was bound to, if any."""
    original = entry.pop(ORIGINAL, None) or entry.pop("_mirage_original", None)
    host_id = entry.pop(HOST_MARK, None)
    if original is None:
        return None
    for key in ("command", "args", "env"):
        if key in original:
            entry[key] = original[key]
        else:
            entry.pop(key, None)
    return host_id or ""


def backup(path: Path) -> Path:
    target = path.with_name(path.name + ".elytra.bak")
    if not target.exists():
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(path.read_text())
    return target


def write(path: Path, data: dict) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing to replace symlinked configuration {path}")
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, name = tempfile.mkstemp(prefix=".elytra-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # The file now holds a host credential: never widen permissions, and drop group/other access.
        os.chmod(name, mode & 0o700 or 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
