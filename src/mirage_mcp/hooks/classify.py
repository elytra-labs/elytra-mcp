"""Classify an agent's built-in tool call (shell, file edit, web) as an Elytra action.

Agents act mostly through built-in tools, not MCP. A PreToolUse hook hands
each call here; the result names a fixed, Elytra-shipped action whose
category the guardrail presets understand. Shell parsing is heuristic: an
unrecognized command is treated as a write, never as a read.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

SERVER = "agent"

# action -> (category, description). Names containing delete/destroy match the
# destructive guardrail patterns, so they always need a decision.
ACTIONS: dict[str, tuple[str, str]] = {
    "read_local": ("SOURCE_TRUSTED", "Read local files or run a read-only command"),
    "web_read": ("SOURCE_UNTRUSTED", "Fetch web pages, search the web, or read from a remote service"),
    "edit_files": ("SINK_PRIVILEGED_WRITE", "Create, edit, or move local files"),
    "run_command": ("SINK_PRIVILEGED_WRITE", "Run a shell command Elytra does not recognize"),
    "send_data": ("SINK_EXFILTRATION", "Send data to a remote destination (upload, post, push, publish)"),
    "delete_files": ("SINK_PRIVILEGED_WRITE", "Delete files or records"),
    "destroy_history": ("SINK_EXFILTRATION", "Rewrite or discard version history (force push, hard reset, clean)"),
}
SEVERITY = {"read_local": 1, "web_read": 2, "edit_files": 3, "run_command": 3, "send_data": 4, "delete_files": 5, "destroy_history": 5}


@dataclass
class Action:
    kind: str  # "builtin", "mcp", "protected", "ignore"
    server: str = SERVER
    tool: str = ""
    arguments: dict = field(default_factory=dict)
    reason: str = ""


# Tool names across Claude Code, Codex, Grok and Antigravity.
READ_TOOLS = {"read", "glob", "grep", "ls", "listdir", "notebookread", "read_file", "list_dir", "grep_search", "find_by_name",
              "view_file", "view_file_outline", "view_code_item", "codebase_search", "view_image", "search_files"}
WEB_TOOLS = {"webfetch", "websearch", "web_fetch", "web_search", "read_url_content", "search_web", "browser_navigate", "fetch_url"}
EDIT_TOOLS = {"write", "edit", "multiedit", "notebookedit", "apply_patch", "write_file", "edit_file", "search_replace",
              "write_to_file", "replace_file_content", "multi_replace_file_content", "create_file", "delete_file"}
SHELL_TOOLS = {"bash", "shell", "exec_command", "local_shell", "unified_exec", "run_terminal_command", "run_command", "container.exec"}
IGNORE_TOOLS = {"todowrite", "todoread", "task", "agent", "exitplanmode", "enterplanmode", "askuserquestion", "skill", "toolsearch",
                "update_plan", "spawn_subagent", "write_todos", "notify_user", "task_boundary", "command_status"}

READ_VERBS = {"ls", "cat", "head", "tail", "less", "more", "wc", "grep", "egrep", "fgrep", "rg", "ag", "fd", "tree", "pwd", "echo",
              "printf", "which", "whereis", "type", "file", "stat", "du", "df", "date", "uname", "whoami", "id", "ps", "jq", "yq",
              "sort", "uniq", "cut", "tr", "diff", "cmp", "basename", "dirname", "realpath", "readlink", "sha256sum", "shasum", "md5",
              "md5sum", "test", "[", "true", "false", "sleep", "nl", "column", "cd", "export", "set", "source", ".", "env", "printenv",
              "hostname", "uptime", "awk", "sed", "find", "xxd", "hexdump", "od", "strings", "man", "help", "history", "alias"}
NETWORK_VERBS = {"curl", "wget", "http", "https", "xh", "httpie"}
REMOTE_SEND_VERBS = {"scp", "sftp", "ftp", "nc", "ncat", "netcat", "telnet", "ssh", "mail", "sendmail", "mutt"}
PUBLISH = {("npm", "publish"), ("yarn", "publish"), ("pnpm", "publish"), ("twine", "upload"), ("cargo", "publish"),
           ("docker", "push"), ("gem", "push"), ("poetry", "publish"), ("gh", "release")}
DELETE_VERBS = {"rm", "rmdir", "unlink", "shred", "trash", "dropdb"}
GIT_READ = {"status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "grep", "describe", "shortlog", "reflog", "remote", "config", "branch", "tag", "stash"}
GIT_FETCH = {"fetch", "pull", "clone", "ls-remote", "submodule"}
GIT_WRITE = {"add", "commit", "merge", "rebase", "checkout", "switch", "cherry-pick", "revert", "mv", "init", "apply", "am", "worktree", "restore"}
SQL_DESTRUCTIVE = re.compile(r"\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from)\b", re.I)
SPLIT = re.compile(r"\|\||&&|;|\||\n|`|\$\(|\)")
REDIRECT = re.compile(r"(?<![<>&0-9])\d?>>?\s*(?!&|/dev/null)(\S+)")
URL = re.compile(r"https?://[^\s'\"]+")


def _home() -> str:
    return str(Path.home())


def protected_reason(text: str) -> str | None:
    """Best-effort self-protection: the agent must not read Elytra's secrets or reach its API."""
    home = _home()
    lowered = text.replace("${HOME}", home).replace("$HOME", home).replace("~/", home + "/")
    if f"{home}/.elytra" in lowered or "/.elytra/" in lowered or lowered.rstrip("/").endswith("/.elytra"):
        return "Elytra's local credentials and records are off limits to agents"
    if re.search(r"(127\.0\.0\.1|localhost|\[::1\]):8765\b", lowered):
        return "Agents may not call the local Elytra API"
    return None


SETTINGS_FILES = (".claude/settings.json", ".claude/settings.local.json", ".codex/config.toml", ".grok/config.toml",
                  ".grok/hooks/", ".gemini/config/hooks.json", ".cursor/hooks.json")


def touches_agent_settings(text: str) -> bool:
    return any(path in text for path in SETTINGS_FILES)


def _segment(tokens: list[str], raw: str) -> str:
    """Classify one command segment (no pipes or separators)."""
    while tokens and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]) or tokens[0] in {"sudo", "env", "time", "nohup", "command", "exec", "nice", "xargs", "then", "do", "else", "if", "while", "!"}):
        tokens = tokens[1:]
    if not tokens:
        return "read_local"
    verb = os.path.basename(tokens[0])
    args = tokens[1:]
    sub = args[0] if args else ""
    if REDIRECT.search(raw):
        return "edit_files"
    if verb in DELETE_VERBS:
        return "delete_files"
    if verb == "find":
        return "delete_files" if "-delete" in args else "run_command" if any(a in {"-exec", "-execdir", "-ok"} for a in args) else "read_local"
    if verb == "sed":
        return "edit_files" if any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args) else "read_local"
    if verb == "git":
        flags = set(args)
        if sub == "push":
            return "destroy_history" if flags & {"-f", "--force", "--force-with-lease", "--mirror", "--delete", "-d"} or any(a.startswith("+") for a in args[1:]) else "send_data"
        if sub == "reset" and "--hard" in flags or sub == "clean" and any(a.startswith("-") and "f" in a for a in args[1:]):
            return "destroy_history"
        if sub == "branch" and flags & {"-D", "-d", "--delete"}:
            return "delete_files"
        if sub == "checkout" and "--" in args and "." in args:
            return "destroy_history"
        if sub in GIT_FETCH:
            return "web_read"
        if sub in {"stash", "tag", "remote", "config", "branch"}:
            listing = len(args) == 1 or args[1] in {"list", "-l", "--list", "-v", "-vv", "-a", "-r", "show", "--get", "--show-current", "get-url"}
            return "read_local" if listing else "edit_files"
        if sub in GIT_READ:
            return "read_local"
        return "edit_files" if sub in GIT_WRITE else "run_command"
    if verb == "gh":
        second = args[1] if len(args) > 1 else ""
        if sub in {"issue", "pr", "repo", "run", "release", "workflow", "search", "gist"} and second in {"view", "list", "diff", "checks", "status", "clone", "download", "watch"} or sub == "search":
            return "web_read"
        if sub == "api":
            return "send_data" if any(a in {"-X", "--method", "-f", "-F", "--field", "--raw-field", "--input"} for a in args) else "web_read"
        return "send_data" if sub in {"issue", "pr", "release", "gist", "secret", "variable", "repo"} else "run_command"
    if verb in NETWORK_VERBS:
        sends = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "-T", "--upload-file", "--json", "--post-data", "--post-file", "--body-data", "--body-file"}
        method = next((args[i + 1].upper() for i, a in enumerate(args[:-1]) if a in {"-X", "--request", "--method"}), "GET")
        if any(a in sends or a.startswith(("--data", "--form", "--post-")) for a in args) or method not in {"GET", "HEAD", "OPTIONS"}:
            return "send_data"
        return "web_read"
    if verb in REMOTE_SEND_VERBS:
        return "send_data"
    if verb == "rsync":
        return "send_data" if any(":" in a and not a.startswith("-") for a in args) else "edit_files"
    if (verb, sub) in PUBLISH:
        return "send_data"
    if verb in {"kubectl", "oc"} and sub == "delete" or verb == "terraform" and sub == "destroy" or verb == "docker" and sub in {"rm", "rmi", "prune"} or (verb == "docker" and sub == "system" and "prune" in args):
        return "delete_files"
    if verb in {"psql", "mysql", "sqlite3", "duckdb"} and SQL_DESTRUCTIVE.search(raw):
        return "delete_files"
    if verb in {"mv", "cp", "mkdir", "touch", "ln", "chmod", "chown", "tee", "install", "patch"}:
        return "edit_files"
    if verb in READ_VERBS:
        return "read_local"
    return "run_command"


def classify_shell(command: str) -> str:
    if not command.strip():
        return "read_local"
    worst = "read_local"
    for raw in SPLIT.split(command):
        raw = raw.strip()
        if not raw:
            continue
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError:
            tokens = None
        action = _segment(tokens, raw) if tokens is not None else "run_command"
        if SEVERITY[action] > SEVERITY[worst]:
            worst = action
    if SQL_DESTRUCTIVE.search(command) and SEVERITY[worst] < SEVERITY["delete_files"] and re.search(r"\b(psql|mysql|sqlite3|duckdb)\b", command):
        worst = "delete_files"
    return worst


def _command_text(tool_input: dict) -> str:
    value = tool_input.get("command", tool_input.get("cmd", tool_input.get("CommandLine", tool_input.get("commandLine", ""))))
    if isinstance(value, list):
        parts = [str(v) for v in value]
        # ["bash", "-lc", "script"] -> script
        if len(parts) >= 3 and os.path.basename(parts[0]) in {"bash", "sh", "zsh"} and parts[1] in {"-c", "-lc", "-lic"}:
            return parts[2]
        return shlex.join(parts)
    return str(value or "")


def _path_text(tool_input: dict) -> str:
    keys = ("file_path", "path", "notebook_path", "AbsolutePath", "TargetFile", "filePath", "target_file", "pattern", "Directory")
    return " ".join(str(tool_input[k]) for k in keys if isinstance(tool_input.get(k), str))


def _mcp_name(name: str) -> tuple[str, str] | None:
    if name.startswith("mcp__"):
        server, _, tool = name[5:].partition("__")
        return (server, tool) if server and tool else None
    if "__" in name and not name.startswith("_"):
        server, _, tool = name.partition("__")
        return (server, tool) if server and tool else None
    return None


def classify(tool_name: str, tool_input: dict) -> Action:
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    name = str(tool_name or "")
    key = name.lower()
    mcp = _mcp_name(name)
    text = " ".join([_command_text(tool_input), _path_text(tool_input), str(tool_input.get("url", tool_input.get("Url", "")))])
    reason = protected_reason(text)
    if reason:
        return Action("protected", reason=reason)
    if mcp:
        return Action("mcp", server=mcp[0], tool=mcp[1], arguments={"tool": name})
    if key in IGNORE_TOOLS:
        return Action("ignore")
    if key in SHELL_TOOLS:
        command = _command_text(tool_input)
        action = classify_shell(command)
        if action != "read_local" and touches_agent_settings(command):
            return Action("protected", reason="Agents may not change their own hook or permission settings")
        return Action("builtin", tool=action, arguments={"command": command[:4000]})
    if key in EDIT_TOOLS:
        path = _path_text(tool_input)
        if touches_agent_settings(path):
            return Action("protected", reason="Agents may not change their own hook or permission settings")
        return Action("builtin", tool="delete_files" if key == "delete_file" else "edit_files", arguments={"path": path[:1000]})
    if key in WEB_TOOLS:
        target = str(tool_input.get("url", tool_input.get("Url", tool_input.get("query", tool_input.get("Query", "")))))
        return Action("builtin", tool="web_read", arguments={"target": target[:1000]})
    if key in READ_TOOLS:
        return Action("builtin", tool="read_local", arguments={"path": _path_text(tool_input)[:1000]})
    # Unknown built-in tools are treated as consequential, never as reads.
    return Action("builtin", tool="run_command", arguments={"tool": name[:200]})
