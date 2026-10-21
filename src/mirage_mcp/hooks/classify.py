"""Classify an agent's built-in tool call (shell, file edit, web) as an Elytra action.

Agents act mostly through built-in tools, not MCP. A PreToolUse hook hands each
call here; the result names a fixed, Elytra-shipped action whose category the
guardrail presets understand. Shell commands are tokenized like a shell would
(operators, quotes, redirects, command and process substitution); wrappers such
as sudo, env, timeout and xargs are seen through; inline scripts (`bash -c`,
`python -c`, base64 decoded into a shell) are classified by what they contain.
Parsing is still heuristic: anything Elytra cannot place is a command it does not
recognize, which is treated as a change, never as a read.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import shlex
from pathlib import Path

SERVER = "agent"

# action -> (category, description). Names containing delete/destroy also match the
# destructive guardrail patterns.
ACTIONS: dict[str, tuple[str, str]] = {
    "read_local": ("SOURCE_TRUSTED", "Read local files or run a read-only command"),
    "read_secrets": ("SOURCE_TRUSTED", "Read credentials or secrets (.env files, keys, tokens)"),
    "web_read_trusted": ("SOURCE_TRUSTED", "Read official documentation or a package registry"),
    "web_read": ("SOURCE_UNTRUSTED", "Fetch web pages, issues, pull requests or other remote content"),
    "run_checks": ("SINK_PRIVILEGED_WRITE", "Run tests, builds, linters, formatters or a dev server"),
    "edit_files": ("SINK_PRIVILEGED_WRITE", "Create, edit or move files in the project"),
    "install_packages": ("SINK_PRIVILEGED_WRITE", "Install or add packages"),
    "run_command": ("SINK_PRIVILEGED_WRITE", "Run a command Elytra does not recognize"),
    "push_branch": ("SINK_PRIVILEGED_WRITE", "Push to a working branch"),
    "pr_create": ("SINK_PRIVILEGED_WRITE", "Open or update a pull request"),
    "edit_sensitive": ("SINK_PRIVILEGED_WRITE", "Change shell startup files, credentials, git hooks, CI or files outside the project"),
    "push_protected": ("SINK_PRIVILEGED_WRITE", "Push to a protected branch, or push tags"),
    "pr_merge": ("SINK_PRIVILEGED_WRITE", "Merge or approve a pull request"),
    "delete_files": ("SINK_PRIVILEGED_WRITE", "Delete files, records or resources"),
    "send_data": ("SINK_EXFILTRATION", "Send data or change something remote (upload, post, publish, deploy)"),
    "run_remote_code": ("SINK_EXFILTRATION", "Run code downloaded from the internet"),
    "destroy_history": ("SINK_EXFILTRATION", "Rewrite or discard version history or uncommitted work"),
    "send_secrets": ("SINK_EXFILTRATION", "Send credentials or secret files somewhere"),
}
SEVERITY = {"read_local": 1, "read_secrets": 2, "web_read_trusted": 2, "web_read": 3, "run_checks": 4, "edit_files": 5,
            "pr_create": 5, "install_packages": 6, "run_command": 6, "push_branch": 6, "edit_sensitive": 8, "push_protected": 8,
            "pr_merge": 8, "send_data": 9, "delete_files": 9, "run_remote_code": 10, "destroy_history": 10, "send_secrets": 11}


class Action:
    """kind is "builtin", "mcp", "protected" or "ignore". A plain class: dataclasses would slow every hook start."""
    __slots__ = ("kind", "server", "tool", "arguments", "reason")

    def __init__(self, kind: str, server: str = SERVER, tool: str = "", arguments: dict | None = None, reason: str = ""):
        self.kind, self.server, self.tool, self.arguments, self.reason = kind, server, tool, arguments if arguments is not None else {}, reason

    def __eq__(self, other):
        return isinstance(other, Action) and all(getattr(self, k) == getattr(other, k) for k in self.__slots__)

    def __repr__(self):
        return f"Action({self.kind!r}, server={self.server!r}, tool={self.tool!r}, arguments={self.arguments!r}, reason={self.reason!r})"


# Tool names across Claude Code, Codex, Grok, Antigravity, Cursor and Gemini CLI.
READ_TOOLS = {"read", "glob", "grep", "ls", "listdir", "notebookread", "read_file", "list_dir", "grep_search", "find_by_name",
              "view_file", "view_file_outline", "view_code_item", "codebase_search", "view_image", "search_files", "read_many_files",
              "list_directory", "search_file_content", "glob_search"}
WEB_TOOLS = {"webfetch", "websearch", "web_fetch", "web_search", "read_url_content", "search_web", "browser_navigate", "fetch_url",
             "google_web_search"}
EDIT_TOOLS = {"write", "edit", "multiedit", "notebookedit", "apply_patch", "write_file", "edit_file", "search_replace", "replace",
              "write_to_file", "replace_file_content", "multi_replace_file_content", "create_file", "delete_file"}
SHELL_TOOLS = {"bash", "shell", "exec_command", "local_shell", "unified_exec", "run_terminal_command", "run_command", "container.exec",
               "run_shell_command"}
IGNORE_TOOLS = {"todowrite", "todoread", "task", "agent", "exitplanmode", "enterplanmode", "askuserquestion", "skill", "toolsearch",
                "update_plan", "spawn_subagent", "write_todos", "notify_user", "task_boundary", "command_status", "save_memory"}

READ_VERBS = {"ls", "cat", "head", "tail", "less", "more", "wc", "grep", "egrep", "fgrep", "rg", "ag", "fd", "tree", "pwd", "echo",
              "printf", "which", "whereis", "type", "file", "stat", "du", "df", "date", "uname", "whoami", "id", "ps", "jq", "yq",
              "sort", "uniq", "cut", "tr", "diff", "cmp", "basename", "dirname", "realpath", "readlink", "sha256sum", "shasum", "md5",
              "md5sum", "test", "[", "[[", "true", "false", "sleep", "nl", "column", "cd", "export", "set", "source", ".", "hostname",
              "uptime", "awk", "sed", "find", "xxd", "hexdump", "od", "strings", "man", "help", "history", "alias", "bat", "lsof",
              "top", "htop", "free", "vm_stat", "sw_vers", "ifconfig", "ping", "dig", "nslookup", "host", "nproc", "seq", "expr",
              "comm", "join", "paste", "fold", "fmt", "rev", "tac", "zcat", "gzip", "gunzip", "file", "locale", "getconf", "read",
              "local", "declare", "unset", "shift", "wait", "jobs", "pushd", "popd", "dirs", "umask", "ulimit", "trap", "exit", "return"}
SECRET_READERS = {"cat", "head", "tail", "less", "more", "bat", "strings", "xxd", "od", "hexdump", "base64", "grep", "rg", "egrep",
                  "awk", "sed", "tar", "zip", "gzip", "cut", "sort", "jq", "yq", "source", "."}
NETWORK_VERBS = {"curl", "wget", "http", "https", "xh", "httpie", "curlie", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"}
REMOTE_SEND_VERBS = {"scp", "sftp", "ftp", "nc", "ncat", "netcat", "telnet", "ssh", "mail", "sendmail", "mutt", "socat"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"}
INTERPRETERS = SHELLS | {"python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "pwsh", "powershell", "deno", "bun", "tsx", "ts-node", "osascript", "iex", "invoke-expression"}
DELETE_VERBS = {"rm", "rmdir", "unlink", "shred", "trash", "dropdb", "dropuser", "srm"}
ARTIFACT_DIRS = {"dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit", "node_modules", ".cache", "coverage", ".coverage",
                 ".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache", ".turbo", ".parcel-cache", ".tox", ".nox", "htmlcov",
                 ".gradle", ".angular", "storybook-static", ".expo", ".vercel/output", "tmp", ".tmp", "logs"}
CHECK_SCRIPTS = {"test", "t", "lint", "build", "typecheck", "type-check", "types", "tsc", "check", "format", "fmt", "prettier",
                 "e2e", "coverage", "verify", "compile", "dev", "start", "serve", "preview", "watch", "storybook", "ci", "validate",
                 "clean", "test-unit", "unit", "integration", "spec"}
CHECK_TOOLS = {"tsc", "eslint", "prettier", "biome", "stylelint", "jest", "vitest", "mocha", "ava", "tap", "ruff", "black", "isort",
               "flake8", "pylint", "mypy", "pyright", "pytest", "py.test", "tox", "nox", "gofmt", "goimports", "golangci-lint",
               "rubocop", "rspec", "phpunit", "phpstan", "swiftlint", "swiftformat", "ktlint", "shellcheck", "hadolint", "rustfmt",
               "clippy-driver", "markdownlint", "yamllint", "cspell", "knip", "depcheck", "standard", "xo", "oxlint", "dprint",
               "next", "nuxt", "astro", "remix", "svelte-check", "vue-tsc", "playwright", "cypress", "pre-commit", "coverage"}
NPM_LIKE = {"npm", "pnpm", "yarn", "bun"}
PIP_LIKE = {"pip", "pip3", "pipx", "uv", "poetry", "conda", "mamba", "micromamba", "pdm", "hatch", "rye", "pipenv"}
INSTALL_VERBS = {"install", "i", "add", "ci", "update", "upgrade", "up", "sync", "lock", "get", "require", "fetch"}
DEPLOY_VERBS = {("vercel", None), ("netlify", "deploy"), ("firebase", "deploy"), ("fly", "deploy"), ("flyctl", "deploy"),
                ("wrangler", "deploy"), ("wrangler", "publish"), ("heroku", None), ("railway", "up"), ("serverless", "deploy"),
                ("sls", "deploy"), ("eb", "deploy"), ("render", "deploy"), ("surge", None), ("pulumi", "up")}
SQL_DESTRUCTIVE = re.compile(r"\b(drop\s+(table|database|schema|index|view|user)|truncate(\s+table)?\s+\w|delete\s+from|alter\s+table\s+\S+\s+drop)\b", re.I)
REDIS_DESTRUCTIVE = re.compile(r"\b(flushall|flushdb|del|unlink)\b", re.I)
SECRET_NAME = re.compile(r"(?i)(key|token|secret|passw(or)?d|pass|credential|auth|private|cookie|session)")
SECRET_VARIABLE = re.compile(r"\$\{?[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|AUTH|PRIVATE|COOKIE|SESSION)[A-Za-z0-9_]*\}?", re.I)
URL = re.compile(r"https?://[^\s'\"<>|;&)]+")
SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
PROCESS_SUBST = re.compile(r"[<>]\(([^()]*)\)")
WRAPPERS = {  # wrapper -> options that take a value
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user", "--group", "--host", "--prompt", "--chdir"},
    "doas": {"-u", "-C"}, "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}, "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k", "--signal", "--kill-after"}, "nohup": set(), "time": {"-f", "-o"},
    "command": set(), "exec": {"-a"}, "stdbuf": {"-i", "-o", "-e"}, "caffeinate": {"-t", "-w"}, "xargs": {"-I", "-i", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--delimiter", "--max-args", "--max-procs", "--replace", "--arg-file"},
    "watch": {"-n", "-d", "--interval"}, "chrt": set(), "taskset": set(), "builtin": set(), "then": set(), "do": set(), "else": set(),
    "if": set(), "while": set(), "until": set(), "!": set(), "{": set(), "unbuffer": set(), "script": {"-q"}, "systemd-run": {"--unit", "-p"},
}
SECRET_BASENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", ".netrc", ".npmrc", ".pypirc", ".git-credentials",
                    "kubeconfig", ".vault-token", "credentials.json", "client_secret.json", "token.json", ".htpasswd", "master.key"}
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".kdbx", ".ppk", ".gpg", ".asc")
SECRET_FRAGMENTS = ("/.ssh/", "/.aws/credentials", "/.kube/config", "/.docker/config.json", "/.config/gh/hosts", "/.gnupg/",
                    "/secrets/", "/.secrets/", "service-account", "serviceaccount")
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")
SENSITIVE_HOME = (".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".gitconfig",
                  ".npmrc", ".pypirc", ".netrc", ".yarnrc", ".condarc", ".git-credentials", ".tmux.conf", ".vimrc", ".inputrc")
SENSITIVE_FRAGMENTS = ("/.ssh/", "/.aws/", "/.gnupg/", "/.kube/", "/.docker/", "/.config/", "/library/launchagents/",
                       "/library/launchdaemons/", "/.local/bin/", "/.oh-my-zsh/", "/.cargo/config", "/.m2/settings")
PROJECT_SENSITIVE = (".git/hooks/", ".git/config", ".github/workflows/", ".github/actions/", ".gitlab-ci.yml", ".circleci/",
                     "azure-pipelines.yml", "bitbucket-pipelines.yml", "jenkinsfile", ".husky/", ".envrc", ".npmrc", ".yarnrc",
                     ".yarnrc.yml", "pip.conf", ".pip/", ".vscode/tasks.json", ".devcontainer/", ".pre-commit-config.yaml",
                    ".gitmodules", ".buildkite/", ".travis.yml", "cloudbuild.yaml", "lefthook.yml", ".lefthook.yml")


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
                  ".grok/hooks/", ".gemini/config/hooks.json", ".gemini/settings.json", ".cursor/hooks.json", ".elytra.toml")


def touches_agent_settings(text: str) -> bool:
    return any(path in text for path in SETTINGS_FILES)


# Paths ---------------------------------------------------------------------------------

def _expand(path: str) -> str:
    home = _home()
    if path.startswith("~/") or path == "~":
        path = home + path[1:]
    return path.replace("${HOME}", home).replace("$HOME", home)


def is_secret_path(path: str) -> bool:
    path = _expand(path.strip().strip("'\""))
    if not path or path.endswith(".pub"):
        return False
    lowered = path.lower()
    lowered = "/" + (lowered[2:] if lowered.startswith("./") else lowered.lstrip("/"))
    name = os.path.basename(lowered)
    if name == ".env" or name.startswith(".env.") and not name.endswith(SAFE_ENV_SUFFIXES) or name.endswith(".env") and name != ".env.example":
        return True
    if name in SECRET_BASENAMES or name.endswith(SECRET_SUFFIXES) or "secret" in name and not name.endswith((".md", ".py", ".ts", ".js", ".go", ".rs")):
        return True
    return any(fragment in lowered for fragment in SECRET_FRAGMENTS) and not lowered.endswith(("/known_hosts", "/.ssh/config"))


def _project_root(context: dict) -> str | None:
    if "project_root" in context:
        return context["project_root"]
    cwd = context.get("cwd")
    if not cwd:
        return None
    from mirage_mcp.hooks import context as hook_context
    context["project_root"] = hook_context.project_root(cwd)
    return context["project_root"]


def is_sensitive_path(path: str, context: dict | None = None) -> bool:
    """Files whose change persists beyond the task: shell startup, credentials, git hooks, CI, or anything outside the project."""
    context = context if context is not None else {}
    raw = _expand(path.strip().strip("'\""))
    if not raw:
        return False
    lowered = raw.lower()
    home = _home().lower()
    name = os.path.basename(lowered.rstrip("/"))
    if lowered.startswith("/etc/") or lowered.startswith("/private/etc/") or lowered.startswith(("/usr/", "/library/", "/system/")):
        return True
    if lowered.startswith(home + "/") and (name in SENSITIVE_HOME and os.path.dirname(lowered.rstrip("/")) == home or
                                           any(fragment in lowered[len(home):].rstrip("/") + "/" for fragment in SENSITIVE_FRAGMENTS)):
        return True
    relative = lowered[2:] if lowered.startswith("./") else lowered
    if any(fragment in "/" + relative for fragment in ("/" + f for f in PROJECT_SENSITIVE)) or name in {"jenkinsfile", ".envrc"}:
        return True
    from mirage_mcp.hooks import context as hook_context
    cwd = context.get("cwd")
    if raw.startswith("/") and cwd and not hook_context.is_temp(raw):
        if hook_context.inside(raw, cwd):
            return False
        root = _project_root(context)
        return not (root and hook_context.inside(raw, root))
    if not raw.startswith("/") and cwd and ".." in Path(raw).parts:
        resolved = os.path.normpath(os.path.join(cwd, raw))
        root = _project_root(context)
        return not hook_context.inside(resolved, root or cwd) and not hook_context.is_temp(resolved)
    return False


def _web_action(url: str) -> str:
    from mirage_mcp.security.trusted_sources import is_trusted_url
    return "web_read_trusted" if url and is_trusted_url(url) else "web_read"


# Shell ---------------------------------------------------------------------------------

def _worst(actions) -> str:
    worst = "read_local"
    for action in actions:
        if action and SEVERITY[action] > SEVERITY[worst]:
            worst = action
    return worst


def _decode_base64(text: str) -> str | None:
    text = text.strip().strip("'\"")
    if len(text) < 4 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", text):
        return None
    try:
        decoded = base64.b64decode(text + "=" * (-len(text) % 4), validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded.strip() and all(ch.isprintable() or ch in "\n\t" for ch in decoded) else None


def _resolve_literal(command: str) -> str | None:
    """What a substitution like $(echo curl) or $(echo X | base64 -d) evaluates to, when it is literal."""
    parts = [p.strip() for p in command.split("|")]
    try:
        first = shlex.split(parts[0])
    except ValueError:
        return None
    if not first or first[0] not in {"echo", "printf"}:
        return None
    value = " ".join(a for a in first[1:] if not a.startswith("-"))
    for stage in parts[1:]:
        if re.fullmatch(r"base64\s+(-d|--decode|-D)", stage):
            value = _decode_base64(value)
            if value is None:
                return None
        else:
            return None
    return value


def _is_fetch(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return bool(re.match(r"\s*(curl|wget|http|xh)\b", command))
    tokens = _strip_wrappers(tokens)
    return bool(tokens) and os.path.basename(tokens[0]) in NETWORK_VERBS


def _strip_wrappers(tokens: list[str]) -> list[str]:
    while tokens:
        head = os.path.basename(tokens[0]) if not tokens[0].startswith("-") else tokens[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            tokens = tokens[1:]
            continue
        if head not in WRAPPERS:
            break
        valued = WRAPPERS[head]
        tokens = tokens[1:]
        if head == "timeout" and tokens and not tokens[0].startswith("-"):
            tokens = tokens[1:]  # the duration
        while tokens and tokens[0].startswith("-") and tokens[0] != "-":
            option = tokens.pop(0)
            if option == "--":
                break
            if option in valued:
                if tokens:
                    tokens.pop(0)
            elif head == "timeout" and tokens and not tokens[0].startswith("-") and option in {"-s", "-k"}:
                tokens.pop(0)
        if head == "timeout" and tokens and re.fullmatch(r"\d+(\.\d+)?[smhd]?", tokens[0]):
            tokens = tokens[1:]
        if head == "env":
            while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
                tokens = tokens[1:]
    return tokens


def _segments(command: str) -> list[tuple[list[str], bool, list[tuple[str, str]]]]:
    """Split a command line into simple commands: (words, piped_from_previous, redirects)."""
    result = []
    heredoc = None
    for line in command.split("\n"):
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        marker = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        if marker:
            heredoc = marker.group(2)
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError:
            return []
        words: list[str] = []
        redirects: list[tuple[str, str]] = []
        piped = False
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in {"|", "|&", "||", "&&", ";", "&", ";;", "(", ")", "{", "}"}:
                if words or redirects:
                    result.append((words, piped, redirects))
                piped = token in {"|", "|&"}
                words, redirects = [], []
            elif set(token) <= set("<>&") and ("<" in token or ">" in token):
                target = tokens[index + 1] if index + 1 < len(tokens) else ""
                if words and re.fullmatch(r"\d", words[-1]):
                    words.pop()  # 2>file: the descriptor number is not an argument
                if not (token.endswith("&") and re.fullmatch(r"\d|-", target or "")):
                    redirects.append((token, target))
                index += 1
            else:
                words.append(token)
            index += 1
        if words or redirects:
            result.append((words, piped, redirects))
    return result


def classify_shell(command: str, context: dict | None = None) -> str:
    context = context if context is not None else {}
    if not command.strip():
        return "read_local"
    depth = context.get("_depth", 0)
    if depth > 4:
        return "run_command"
    inner_context = {**context, "_depth": depth + 1}
    extra: list[str] = []
    substitutions: list[str] = []

    def keep(match: re.Match) -> str:
        inner = match.group(1) if match.group(1) is not None else match.group(2)
        substitutions.append(inner)
        literal = _resolve_literal(inner)
        if literal is not None and depth < 4:
            return shlex.quote(literal) if " " not in literal.strip() else literal
        return f"__ELYTRA_SUBST_{len(substitutions) - 1}__"

    processed = SUBST.sub(keep, PROCESS_SUBST.sub(lambda m: substitutions.append(m.group(1)) or f"__ELYTRA_PSUBST_{len(substitutions) - 1}__", command))
    for inner in substitutions:
        literal = _resolve_literal(inner)
        if literal is None:
            extra.append(classify_shell(inner, inner_context))
    segments = _segments(processed)
    if not segments:
        return "run_command"
    actions = []
    downloads: set[str] = set()
    for position, (words, piped, redirects) in enumerate(segments):
        previous = segments[position - 1][0] if position else []
        action = _segment(words, redirects, inner_context, substitutions)
        # Fetched content piped into an interpreter is remote code; a literal decoded into a shell is what it decodes to.
        head = _strip_wrappers(list(words))
        verb = os.path.basename(head[0]) if head else ""
        if piped and verb in INTERPRETERS and position:
            chain = [segments[i][0] for i in range(position)]
            producer = _strip_wrappers(list(chain[-1]))
            if producer and os.path.basename(producer[0]) in {"base64", "openssl"} and position >= 2:
                source = _strip_wrappers(list(chain[-2]))
                decoded = _decode_base64(" ".join(a for a in source[1:] if not a.startswith("-"))) if source and source[0] in {"echo", "printf"} else None
                action = classify_shell(decoded, inner_context) if decoded else "run_command"
                if decoded and any(_is_fetch(part) for part in decoded.split("|")) and re.search(r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", decoded):
                    action = "run_remote_code"
            elif producer and os.path.basename(producer[0]) in NETWORK_VERBS:
                action = "run_remote_code"
            elif any(_is_fetch(" ".join(segment)) for segment in chain):
                action = "run_remote_code"
        if verb in INTERPRETERS | {"eval", "source", "."} and any(w.startswith("__ELYTRA_") and _is_fetch(substitutions[int(re.findall(r"\d+", w)[0])])
                                                                  for w in words if re.search(r"__ELYTRA_(P?SUBST)_\d+__", w)):
            action = "run_remote_code"
        if previous and piped and action in {"send_data"} and _segment(previous, [], inner_context, substitutions) == "read_secrets":
            action = "send_secrets"
        if verb in NETWORK_VERBS:
            for flag, value in zip(head, head[1:]):
                if flag in {"-o", "--output", "-O", "--output-document"}:
                    downloads.add(value.lstrip("./"))
            if verb == "wget" and not any(flag in {"-O", "-qO-", "-O-", "--output-document"} for flag in head):
                for url in URL.findall(" ".join(head)):
                    downloads.add(os.path.basename(url.rstrip("/")))
        executed = [w.lstrip("./") for w in head[:2]] if verb in INTERPRETERS or (head and head[0].startswith("./")) else []
        if downloads and (set(executed) & downloads or verb in {"chmod"} and set(a.lstrip("./") for a in head[1:]) & downloads):
            action = "run_remote_code" if verb != "chmod" else action
        actions.append(action)
    return _worst(actions + extra)


def _arguments(words: list[str]) -> list[str]:
    return [w for w in words[1:] if not w.startswith("-")]


def _redirect_action(redirects, context) -> str | None:
    worst = None
    for operator, target in redirects:
        if ">" in operator:
            if target in {"/dev/null", "/dev/stdout", "/dev/stderr", "&1", "&2", "-"} or target.startswith("/dev/fd/"):
                continue
            action = "edit_sensitive" if is_sensitive_path(target, context) else "edit_files"
            worst = _worst([worst or "read_local", action])
        elif "<" in operator and is_secret_path(target):
            worst = _worst([worst or "read_local", "read_secrets"])
    return worst


def _segment(words: list[str], redirects, context: dict, substitutions: list[str]) -> str:
    """Classify one simple command."""
    tokens = _strip_wrappers(list(words))
    redirect = _redirect_action(redirects, context)
    if not tokens:
        return redirect or "read_local"
    base = _command(tokens, context, substitutions, redirects)
    if redirect and base in {"send_data"} and redirect == "read_secrets":
        return "send_secrets"
    return _worst([base, redirect])


def _command(tokens: list[str], context: dict, substitutions: list[str], redirects) -> str:
    verb = os.path.basename(tokens[0])
    args = tokens[1:]
    positional = [a for a in args if not a.startswith("-")]
    sub = positional[0] if positional else ""
    joined = " ".join(tokens)
    if re.fullmatch(r"__ELYTRA_P?SUBST_\d+__", verb):
        # A verb Elytra cannot resolve. Judge by what the arguments do.
        if URL.search(joined) and any(a in {"-d", "--data", "--data-binary", "-F", "-T", "--upload-file", "-X"} or a.startswith("--data") for a in args):
            return "send_secrets" if any(is_secret_path(a.lstrip("@")) for a in args if a.startswith("@") or "=@" in a) or ".env" in joined else "send_data"
        return "run_command"
    if len(args) == 1 and args[0] in {"--version", "-v", "-V", "version", "--help", "-h", "help"} and verb not in {"rm", "sudo"}:
        return "read_local"

    # Interpreters and shells with inline code.
    if verb in SHELLS:
        for i, a in enumerate(args):
            if a in {"-c", "-lc", "-ic", "-lic", "-cl"} or re.fullmatch(r"-[a-z]*c", a):
                script = args[i + 1] if i + 1 < len(args) else ""
                if re.fullmatch(r"__ELYTRA_P?SUBST_\d+__", script.strip()):
                    inner = substitutions[int(re.findall(r"\d+", script)[0])]
                    return "run_remote_code" if _is_fetch(inner) else classify_shell(inner, context)
                return classify_shell(script, context)
        return "run_command"
    if verb in {"eval"}:
        script = " ".join(args)
        if re.fullmatch(r"__ELYTRA_P?SUBST_\d+__", script.strip()):
            inner = substitutions[int(re.findall(r"\d+", script)[0])]
            return "run_remote_code" if _is_fetch(inner) else "run_command"
        return classify_shell(script, context)
    if verb in {"python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun"} and any(a in {"-c", "-e", "--eval", "-E", "-r"} for a in args):
        flag = next(i for i, a in enumerate(args) if a in {"-c", "-e", "--eval", "-E", "-r"})
        return _code_action(args[flag + 1] if flag + 1 < len(args) else "", context)
    if verb in {"python", "python2", "python3"} and len(args) >= 2 and args[0] == "-m":
        return _python_module(args[1], args[2:], context, substitutions, redirects)

    if verb == "git":
        return _git(args, context)
    if verb == "gh":
        return _gh(args, positional, context)
    if verb in NPM_LIKE or verb in {"npx", "pnpx", "bunx"}:
        return _node_packages(verb, args, positional, context)
    if verb in PIP_LIKE:
        return _python_packages(verb, args, positional, context, substitutions, redirects)
    if verb in NETWORK_VERBS:
        return _network(verb, args)
    if verb in REMOTE_SEND_VERBS:
        sources = [a for a in args if is_secret_path(a)] + [t for o, t in redirects if "<" in o and is_secret_path(t)]
        return "send_secrets" if sources else "send_data"
    if verb == "rsync":
        remote = any(":" in a and not a.startswith("-") and not a.startswith("/") for a in args)
        if remote:
            return "send_secrets" if any(is_secret_path(a) for a in positional[:-1]) else "send_data"
        return "edit_sensitive" if positional and is_sensitive_path(positional[-1], context) else "edit_files"
    if verb in DELETE_VERBS:
        targets = [a for a in args if not a.startswith("-")]
        if verb == "rm" and targets and all(_artifact(t) for t in targets):
            return "run_checks"
        return "delete_files"
    if verb == "find":
        if "-delete" in args:
            return "delete_files"
        for marker in ("-exec", "-execdir", "-ok", "-okdir"):
            if marker in args:
                start = args.index(marker) + 1
                end = next((i for i in range(start, len(args)) if args[i] in {";", "\\;", "+"}), len(args))
                return _worst(["read_local", _segment(args[start:end], [], context, substitutions)])
        return "read_local"
    if verb == "sed":
        if any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args):
            files = positional[1:] if positional else []
            return "edit_sensitive" if any(is_sensitive_path(f, context) for f in files) else "edit_files"
        return "read_local"
    if verb in {"mv", "cp", "install", "ln", "tee", "touch", "mkdir", "patch", "truncate", "dd", "chmod", "chown", "chgrp", "rename", "unzip", "tar", "zip"}:
        return _file_change(verb, args, positional, context)
    if verb in {"turbo", "lerna", "nx", "moon", "rush"}:
        words = [p for p in positional if p not in {"run", "run-many", "exec", "affected"}]
        tasks = [w.split(":")[-1] for w in words[:1]] if verb != "nx" else [w.split(":")[-1] for w in words[:1]]
        if verb == "nx" and positional[:1] == ["run"] and len(positional) > 1:
            tasks = [positional[1].split(":")[-1]]
        return "run_checks" if tasks and all(t in CHECK_SCRIPTS or t.split(":")[0] in CHECK_SCRIPTS for t in tasks) else "run_command"
    if verb in {"make", "gmake"}:
        if "-C" in args or "--directory" in args:
            index = args.index("-C") if "-C" in args else args.index("--directory")
            positional = [p for i, p in enumerate(args) if not p.startswith("-") and i != index + 1]
        targets = [p for p in positional if "=" not in p]
        if "-n" in args or "--dry-run" in args:
            return "read_local"
        return "run_checks" if not targets or all(t in {"test", "tests", "check", "build", "lint", "fmt", "format", "all", "compile", "typecheck", "clean", "ci", "dev", "run-tests", "unit", "verify", "html", "docs", "doc", "coverage"} for t in targets) else "run_command"
    if verb in {"cargo"}:
        if sub in {"test", "build", "check", "clippy", "fmt", "bench", "doc", "nextest", "clean", "miri", "llvm-cov", "tarpaulin"}:
            return "run_checks"
        if sub in {"add", "install", "update", "fetch", "generate-lockfile"}:
            return "install_packages"
        if sub in {"publish", "yank", "owner"}:
            return "send_data"
        if sub in {"tree", "metadata", "search", "version", "locate-project", "pkgid", "verify-project"}:
            return "read_local"
        return "run_command"
    if verb == "go":
        if sub in {"test", "build", "vet", "fmt", "generate", "fix"}:
            return "run_checks"
        if sub in {"get", "install"} or sub == "mod" and len(positional) > 1 and positional[1] in {"tidy", "download", "vendor"}:
            return "install_packages"
        if sub in {"list", "env", "version", "doc"} or sub == "mod" and len(positional) > 1 and positional[1] in {"graph", "why", "verify"}:
            return "read_local"
        return "run_command"
    if verb in {"gradle", "gradlew", "mvn", "mvnw"}:
        tasks = [p for p in positional if not p.startswith(":") or True]
        if any(t.split(":")[-1] in {"publish", "deploy", "release", "uploadArchives"} for t in tasks):
            return "send_data"
        return "run_checks" if tasks and all(t.split(":")[-1] in {"test", "build", "check", "assemble", "compile", "compileJava", "verify", "package", "lint", "clean", "jar", "spotlessApply", "spotlessCheck", "ktlintCheck", "detekt", "install"} for t in tasks) else "run_command"
    if verb in {"dotnet"}:
        return "run_checks" if sub in {"test", "build", "format", "restore", "clean"} else "install_packages" if sub == "add" else "run_command"
    if verb in {"swift"}:
        return "run_checks" if sub in {"build", "test", "format"} else "run_command"
    if verb in {"bundle"}:
        if sub == "exec" and len(positional) > 1:
            return _command(args[args.index("exec") + 1:], context, substitutions, redirects)
        return "install_packages" if sub in {"install", "update", "add"} else "run_command"
    if verb in {"rake"}:
        return "run_checks" if not positional or positional[0] in {"test", "spec", "lint", "build", "rubocop"} else "run_command"
    if verb in {"deno"}:
        return "run_checks" if sub in {"test", "lint", "fmt", "check", "bench"} else "install_packages" if sub in {"install", "add"} else "run_command"
    if verb in CHECK_TOOLS:
        if verb in {"next", "nuxt", "astro", "remix"} and sub not in {"build", "lint", "dev", "start", "check", "info"}:
            return "run_command"
        if verb in {"playwright", "cypress"} and sub not in {"test", "run", "show-report"}:
            return "install_packages" if sub == "install" else "run_command"
        return "run_checks"
    if verb == "docker" or verb == "podman":
        return _docker(args, positional)
    if verb in {"docker-compose"}:
        return _docker(["compose", *args], ["compose", *positional])
    if verb in {"kubectl", "oc", "kubecolor"}:
        return _kubectl(args, positional)
    if verb == "helm":
        if sub in {"install", "upgrade", "rollback"}:
            return "send_data"
        if sub in {"uninstall", "delete", "del"}:
            return "delete_files"
        if sub == "repo" and len(positional) > 1 and positional[1] in {"add", "remove", "update"}:
            return "edit_sensitive"
        return "read_local"
    if verb in {"terraform", "tofu", "terragrunt"}:
        if sub == "destroy" or sub == "state" and len(positional) > 1 and positional[1] in {"rm", "mv"}:
            return "delete_files"
        if sub in {"apply", "import", "taint", "untaint", "force-unlock"}:
            return "send_data"
        if sub in {"fmt", "validate"}:
            return "run_checks"
        if sub in {"init", "get"}:
            return "install_packages"
        return "run_command"
    if verb == "pulumi":
        return "delete_files" if sub == "destroy" else "send_data" if sub in {"up", "update", "import", "refresh"} else "run_command"
    if verb == "aws":
        return _aws(args, positional, redirects)
    if verb in {"gcloud", "az"}:
        return _cloud(verb, positional)
    if verb == "gsutil":
        if sub in {"rm", "rb"}:
            return "delete_files"
        if sub in {"cp", "mv", "rsync"}:
            if positional and positional[-1].startswith("gs://"):
                return "send_secrets" if any(is_secret_path(p) for p in positional[1:-1]) else "send_data"
            return "read_local"
        return "read_local"
    for deploy, action in DEPLOY_VERBS:
        if verb == deploy and (action is None or sub == action):
            if verb == "vercel" and sub in {"dev", "env", "link", "login", "whoami", "ls", "list", "inspect", "logs", "pull"}:
                return "read_local" if sub in {"whoami", "ls", "list", "inspect", "logs"} else "run_command"
            return "send_data"
    if verb == "sqlite3" and positional[1:] and all(p in {".schema", ".tables", ".indexes", ".dbinfo", ".fullschema"} or p.startswith((".schema ", "select ", "SELECT ")) for p in positional[1:]):
        return "read_local"
    if verb in {"psql", "mysql", "mariadb", "sqlite3", "duckdb", "mongosh", "mongo", "cqlsh", "clickhouse-client", "sqlcmd"}:
        return "delete_files" if SQL_DESTRUCTIVE.search(" ".join(tokens)) or re.search(r"dropDatabase\(\)|\.drop\(\)|deleteMany\(", " ".join(tokens)) else "run_command"
    if verb == "redis-cli":
        return "delete_files" if REDIS_DESTRUCTIVE.search(" ".join(positional)) else "run_command"
    if verb == "crontab":
        return "read_local" if args in (["-l"], []) and not positional else "edit_sensitive"
    if verb == "launchctl":
        return "read_local" if sub in {"list", "print", "blame", "version"} else "edit_sensitive"
    if verb == "systemctl":
        return "edit_sensitive" if sub in {"enable", "link", "edit", "set-default", "mask", "preset"} else "read_local" if sub in {"status", "list-units", "list-timers", "is-active", "is-enabled", "show", "cat"} else "run_command"
    if verb == "defaults":
        return "read_local" if sub in {"read", "domains", "find", "read-type"} else "edit_sensitive"
    if verb in {"security"}:
        return "read_secrets" if sub.startswith("find-") and "-w" in args else "read_local" if sub.startswith(("find-", "list-", "show-", "dump-")) else "edit_sensitive"
    if verb in {"op", "vault", "bw", "lpass", "pass", "doppler", "infisical"}:
        return "read_secrets" if sub in {"read", "get", "item", "kv", "show", "secrets", "run", "inject", "export"} else "run_command"
    if verb in {"printenv"}:
        return "read_secrets"
    if verb == "env" and not tokens[1:]:
        return "read_secrets"
    if verb in {"echo", "printf"} and any(SECRET_VARIABLE.search(a) for a in args):
        return "read_secrets"
    if verb in SECRET_READERS and any(is_secret_path(a) for a in positional):
        return "read_secrets"
    if verb in {"source", "."}:
        return "read_secrets" if positional and is_secret_path(positional[0]) else "read_local"
    if verb in {"base64", "openssl"}:
        return "read_secrets" if any(is_secret_path(a) for a in positional) else "read_local"
    if verb in {"open", "xdg-open"}:
        return "run_command"
    if (verb, sub) in {("twine", "upload"), ("gem", "push"), ("flit", "publish"), ("vsce", "publish"), ("ovsx", "publish"), ("pod", "trunk"), ("dart", "pub"), ("mix", "hex.publish")}:
        return "send_data"
    if (verb, sub) in {("gem", "install"), ("brew", "install"), ("brew", "upgrade"), ("brew", "reinstall"), ("apt", "install"), ("apt-get", "install"),
                       ("yum", "install"), ("dnf", "install"), ("apk", "add"), ("port", "install"), ("choco", "install"), ("winget", "install"),
                       ("scoop", "install"), ("asdf", "install"), ("mise", "install"), ("nix-env", "-i"), ("composer", "require"), ("composer", "install")}:
        return "install_packages"
    if verb in {"brew", "apt", "apt-get", "gem"} and sub in {"list", "info", "search", "show", "outdated", "doctor", "config", "--version"}:
        return "read_local"
    if verb in {"python", "python3"} and positional[:1] == ["manage.py"] and len(positional) > 1 and positional[1] in {"test", "check", "makemigrations --check"}:
        return "run_checks"
    if verb in INTERPRETERS:
        return "run_command"
    if verb in READ_VERBS:
        return "read_local"
    return "run_command"


def _artifact(target: str) -> bool:
    target = target.strip("'\"")
    if target.startswith(("/", "~", "$")) or ".." in target.split("/"):
        return False
    path = target.rstrip("/")
    parts = [p for p in path.split("/") if p not in {"", "."}]
    if not parts:
        return False
    return parts[-1] in ARTIFACT_DIRS or path in ARTIFACT_DIRS or parts[-1].endswith(".egg-info") or (len(parts) >= 2 and parts[0] == "node_modules" and parts[-1] == ".cache")


def _file_change(verb: str, args: list[str], positional: list[str], context: dict) -> str:
    if verb in {"tar", "zip"}:
        creating = verb == "zip" or any(re.fullmatch(r"-?[a-zA-Z]*c[a-zA-Z]*", a) for a in args[:1]) or "--create" in args
        if creating and any(is_secret_path(p) for p in positional):
            return "read_secrets"
        target = next((args[i + 1] for i, a in enumerate(args) if a in {"-C", "--directory"} and i + 1 < len(args)), None)
        return "edit_sensitive" if target and is_sensitive_path(target, context) else "edit_files"
    if verb in {"truncate", "dd"} and verb == "truncate":
        return "delete_files" if any(a in {"-s", "--size"} for a in args) else "edit_files"
    if verb == "dd":
        out = next((a[3:] for a in args if a.startswith("of=")), "")
        return "edit_sensitive" if out and is_sensitive_path(out, context) else "edit_files"
    if verb == "unzip":
        target = next((args[i + 1] for i, a in enumerate(args) if a == "-d" and i + 1 < len(args)), None)
        return "edit_sensitive" if target and is_sensitive_path(target, context) else "edit_files"
    targets = positional[-1:] if verb in {"cp", "mv", "install", "ln"} else positional
    if verb in {"chmod", "chown", "chgrp"}:
        targets = positional[1:]
    if verb == "tee":
        targets = positional
    if any(is_sensitive_path(t, context) for t in targets):
        return "edit_sensitive"
    return "edit_files"


def _code_action(code: str, context: dict) -> str:
    actions = ["run_command"]
    for match in re.finditer(r"(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen)|execSync|exec|spawnSync|system|Runtime\.getRuntime\(\)\.exec)\s*\(\s*\[?\s*(['\"])(.+?)\1", code):
        actions.append(classify_shell(match.group(2), context))
    if re.search(r"shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs)\(|\.unlink\(|rmSync|rmdirSync|unlinkSync|fs\.rm\(|fs\.promises\.rm|File\.delete|FileUtils\.rm|\bunlink\b", code):
        actions.append("delete_files")
    sends = re.search(r"urlopen\([^)]*data\s*=|Request\([^)]*data\s*=|requests\.(post|put|patch|delete)|httpx\.(post|put|patch|delete)|method\s*[:=]\s*['\"](POST|PUT|PATCH|DELETE)|smtplib|socket\.|net\.connect|\.sendall\(|ftplib|paramiko|Net::HTTP\.post|curl_exec", code)
    if sends or re.search(r"urlopen\([^)]*,\s*(data=)?[^)]*open\(", code):
        secret = re.search(r"\.env\b|id_rsa|id_ed25519|credentials|\.aws|\.ssh|secret", code)
        actions.append("send_secrets" if secret else "send_data")
    if re.search(r"(urlopen|requests\.get|fetch|http\.get|urllib)\b.*\b(exec|eval)\s*\(", code, re.S):
        actions.append("run_remote_code")
    if re.search(r"open\([^)]*['\"]w|writeFileSync|writeFile\(|write_text|write_bytes|File\.write", code):
        paths = re.findall(r"(?:open|writeFileSync|writeFile|Path|File\.write)\(\s*['\"]([^'\"]+)['\"]", code)
        actions.append("edit_sensitive" if any(is_sensitive_path(p, context) for p in paths) else "edit_files")
    return _worst(actions)


def _python_module(module: str, rest: list[str], context: dict, substitutions, redirects) -> str:
    if module in {"pytest", "unittest", "mypy", "ruff", "black", "isort", "flake8", "pylint", "pyright", "tox", "nox", "coverage",
                  "doctest", "compileall", "py_compile", "build", "pre_commit"}:
        return "run_checks"
    if module == "pip":
        return _python_packages("pip", rest, [r for r in rest if not r.startswith("-")], context, substitutions, redirects)
    if module in {"venv", "virtualenv"}:
        return "edit_files"
    if module == "http.server":
        return "run_command"
    if module == "json.tool":
        return "read_local"
    return "run_command"


def _python_packages(verb: str, args: list[str], positional: list[str], context: dict, substitutions, redirects) -> str:
    sub = positional[0] if positional else ""
    if verb in {"uv", "poetry", "pdm", "hatch", "rye", "pipenv", "pipx"} and sub in {"run", "exec"} and len(positional) > 1:
        start = args.index(sub) + 1
        inner = [a for a in args[start:] if a != "--"]
        while inner and inner[0].startswith("-"):
            inner = inner[1:]
        return _segment(inner, redirects, context, substitutions) if inner else "run_command"
    if verb == "uv" and sub == "pip" and len(positional) > 1:
        sub = positional[1]
    if verb == "uv" and sub == "tool" and len(positional) > 1:
        sub = positional[1]
    if sub in {"install", "add", "sync", "lock", "update", "upgrade", "download", "inject", "ensurepath"} or verb == "pipx" and sub in {"install", "upgrade", "reinstall"}:
        return "install_packages"
    if sub in {"uninstall", "remove", "rm"}:
        return "edit_files"
    if sub == "config" and len(positional) > 1 and positional[1] in {"set", "unset", "edit"}:
        return "edit_sensitive"
    if sub in {"list", "show", "freeze", "check", "search", "index", "config", "debug", "inspect", "tree", "env", "info", "version", "--version"}:
        return "read_local"
    if sub in {"venv", "init", "new", "create"}:
        return "edit_files"
    if sub in {"publish", "upload"}:
        return "send_data"
    if sub in {"build"}:
        return "run_checks"
    return "run_command"


NODE_VALUED = {"--prefix", "-C", "--dir", "--filter", "-F", "--cwd", "--workspace", "-w", "--registry", "--loglevel", "--cache"}


def _node_packages(verb: str, args: list[str], positional: list[str], context: dict) -> str:
    rest, skipped = [], False
    for index, arg in enumerate(args):
        if skipped:
            skipped = False
            continue
        if arg in NODE_VALUED:
            skipped = True
            continue
        rest.append(arg)
    if verb == "yarn" and rest[:1] == ["workspace"] and len(rest) > 2:
        rest = rest[2:]  # yarn workspace <name> <command>
    if verb == "yarn" and rest[:2] == ["workspaces", "foreach"]:
        rest = [a for a in rest[2:] if not a.startswith("-")]
    args = rest
    positional = [a for a in args if not a.startswith("-")]
    sub = positional[0] if positional else ""
    if verb in {"npx", "pnpx", "bunx"} or sub in {"dlx", "exec", "x"} and verb in {"pnpm", "yarn", "bun", "npm"}:
        rest = positional if verb in {"npx", "pnpx", "bunx"} else positional[1:]
        tool = rest[0] if rest else ""
        name = tool.split("@")[0] if not tool.startswith("@") else "@" + tool[1:].split("@")[0]
        if name in {"rimraf", "del-cli", "trash-cli", "rm"}:
            targets = rest[1:]
            return "run_checks" if targets and all(_artifact(t) for t in targets) else "delete_files"
        if name in CHECK_TOOLS or name in {"tsc", "eslint", "prettier", "vitest", "jest"}:
            return "run_checks" if not (name in {"next", "nuxt", "astro", "playwright", "cypress"} and len(rest) > 1 and rest[1] not in {"build", "lint", "dev", "start", "test", "run", "check"}) else "run_command"
        return "install_packages"  # Downloads and runs a package.
    if sub in {"install", "i", "add", "ci", "update", "upgrade", "up", "link", "rebuild", "dedupe", "prune"} or (verb in {"yarn", "pnpm", "bun"} and not sub and not args):
        return "install_packages"
    if sub in {"uninstall", "remove", "rm", "un", "r"}:
        return "edit_files"
    if sub in {"publish", "unpublish", "deprecate", "dist-tag", "owner", "access", "token"}:
        return "send_data"
    if sub == "config":
        return "edit_sensitive" if len(positional) > 1 and positional[1] in {"set", "delete", "edit", "rm"} else "read_local"
    if sub in {"set"} and verb == "npm":
        return "edit_sensitive"
    if sub in {"view", "info", "show", "search", "outdated", "audit", "whoami", "ping", "dist-tags", "doctor"}:
        return "web_read_trusted"
    if sub in {"ls", "list", "why", "explain", "root", "bin", "prefix", "pack", "query", "licenses", "version", "--version", "-v", "help", "fund"}:
        return "read_local"
    script = None
    if sub in {"test", "t", "tst", "start", "stop", "restart"} and verb != "bun":
        script = "test" if sub in {"t", "tst"} else sub
    elif sub in {"run", "run-script", "rum", "urn"} and len(positional) > 1:
        script = positional[1]
    elif sub == "test" and verb == "bun":
        return "run_checks"
    elif verb in {"pnpm", "yarn", "bun"} and sub:
        script = sub
    if script:
        base = script.split(":")[0]
        return "run_checks" if script in CHECK_SCRIPTS or base in CHECK_SCRIPTS else "run_command"
    return "run_command"


def _network(verb: str, args: list[str]) -> str:
    sends = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "-T", "--upload-file", "--json",
             "--post-data", "--post-file", "--body-data", "--body-file", "--form-string"}
    method = next((args[i + 1].upper() for i, a in enumerate(args[:-1]) if a in {"-X", "--request", "--method"}), "GET")
    if verb in {"http", "https", "xh", "httpie"}:
        word = next((a.upper() for a in args if not a.startswith("-")), "")
        if word in {"POST", "PUT", "PATCH", "DELETE"}:
            method = word
        if any("=" in a and not a.startswith(("-", "http")) for a in args):
            method = method if method != "GET" else "POST"
    values = [args[i + 1] for i, a in enumerate(args[:-1]) if a in sends] + [a.split("=", 1)[1] for a in args if a.startswith("--") and "=" in a and a.split("=", 1)[0] in sends]
    if any(a in sends or a.startswith(("--data", "--form", "--post-", "--body-", "--upload-file")) for a in args) or method not in {"GET", "HEAD", "OPTIONS"}:
        secret = any(is_secret_path(v.split("@", 1)[1] if "@" in v else v) for v in values if "@" in v or v.startswith(".")) or \
            any(is_secret_path(v.split("=", 1)[1]) for v in values if "=@" in v)
        return "send_secrets" if secret else "send_data"
    urls = URL.findall(" ".join(args))
    return _web_action(urls[0]) if urls else "web_read"


def _git(args: list[str], context: dict) -> str:
    rest = list(args)
    while rest and rest[0].startswith("-"):
        option = rest.pop(0)
        if option in {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"} and rest:
            rest.pop(0)
    if not rest:
        return "read_local"
    sub, tail = rest[0], rest[1:]
    flags = set(tail)
    positional = [a for a in tail if not a.startswith("-")]
    if sub == "push":
        return _git_push(tail, context)
    if sub == "reset":
        return "destroy_history" if "--hard" in flags or "--merge" in flags or "--keep" in flags else "edit_files"
    if sub == "clean":
        return "read_local" if any(a in {"-n", "--dry-run"} or re.fullmatch(r"-[a-z]*n[a-z]*", a) for a in tail) else "destroy_history"
    if sub in {"checkout", "restore"}:
        if sub == "restore":
            return "edit_files" if "--staged" in flags and "--worktree" not in flags and "-W" not in flags else "destroy_history"
        if "--" in tail or positional and positional[0] == "." or "-f" in flags or "--force" in flags:
            return "destroy_history" if ("--" in tail and tail.index("--") < len(tail) - 1) or "." in positional or "-f" in flags or "--force" in flags else "edit_files"
        return "edit_files"
    if sub == "stash":
        action = positional[0] if positional else "push"
        return {"list": "read_local", "show": "read_local", "drop": "destroy_history", "clear": "destroy_history"}.get(action, "edit_files")
    if sub == "branch":
        if flags & {"-D", "-d", "--delete"}:
            from mirage_mcp.hooks import context as hook_context
            return "destroy_history" if any(hook_context.is_protected(p, context.get("protected_branches") or hook_context.DEFAULT_PROTECTED) for p in positional) else "delete_files"
        if flags & {"-f", "--force", "-M", "-C"}:
            return "destroy_history"
        listing = not positional or flags & {"-l", "--list", "-a", "-r", "-v", "-vv", "--show-current", "--contains", "--merged", "--no-merged"}
        return "read_local" if listing else "edit_files"
    if sub == "tag":
        if flags & {"-d", "--delete"}:
            return "delete_files"
        return "read_local" if not positional or flags & {"-l", "--list", "-n", "--contains", "--points-at"} else "edit_files"
    if sub in {"update-ref", "filter-branch", "filter-repo", "replace"}:
        return "destroy_history"
    if sub == "reflog":
        return "destroy_history" if positional and positional[0] in {"expire", "delete"} else "read_local"
    if sub == "gc":
        return "destroy_history" if any(a.startswith("--prune") for a in tail) else "run_checks"
    if sub == "config":
        reading = flags & {"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--show-scope"} or len(positional) <= 1 and not flags & {"--unset", "--unset-all", "--add", "--replace-all", "--remove-section", "--rename-section", "-e", "--edit"}
        if reading:
            return "read_local"
        key = positional[0].lower() if positional else ""
        if flags & {"--global", "--system"} or key.startswith(("core.hookspath", "core.sshcommand", "core.fsmonitor", "url.", "remote.", "credential.", "alias.", "core.pager", "core.editor", "includeif", "include.")):
            return "edit_sensitive"
        return "edit_files"
    if sub == "remote":
        return "edit_sensitive" if positional and positional[0] in {"add", "set-url", "rename"} else "edit_files" if positional and positional[0] in {"remove", "rm", "prune"} else "read_local"
    if sub in {"fetch", "pull", "clone", "ls-remote", "submodule", "lfs", "sparse-checkout"}:
        return "read_local"
    if sub == "rm":
        return "edit_files" if "--cached" in flags else "delete_files"
    if sub in {"status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "grep", "describe", "shortlog", "whatchanged",
               "cat-file", "ls-tree", "for-each-ref", "name-rev", "merge-base", "count-objects", "check-ignore", "version", "help",
               "show-ref", "rev-list", "range-diff", "var", "cherry", "notes", "bisect", "worktree"}:
        return "read_local" if sub != "worktree" or positional and positional[0] == "list" else "edit_files"
    if sub in {"add", "commit", "merge", "rebase", "cherry-pick", "revert", "mv", "init", "apply", "am", "switch", "pull", "format-patch", "mergetool", "stage"}:
        return "edit_files"
    if sub == "send-email" or sub == "request-pull":
        return "send_data"
    return "run_command"


def _git_push(args: list[str], context: dict) -> str:
    flags = set(a.split("=")[0] for a in args if a.startswith("-"))
    positional = [a for a in args if not a.startswith("-")]
    i = 0
    while i < len(args):  # options that take a value
        if args[i] in {"--repo", "--receive-pack", "--exec", "-o", "--push-option", "--signed"} and i + 1 < len(args):
            if args[i + 1] in positional:
                positional.remove(args[i + 1])
            i += 1
        i += 1
    if flags & {"-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror", "--prune"} or any(p.startswith("+") for p in positional[1:]):
        return "destroy_history"
    remote = positional[0] if positional else "origin"
    if "://" in remote or re.match(r"^[\w.-]+@[\w.-]+:", remote) or remote.endswith(".git") and "/" in remote:
        return "send_data"
    refspecs = positional[1:]
    from mirage_mcp.hooks import context as hook_context
    patterns = context.get("protected_branches") or hook_context.DEFAULT_PROTECTED
    if flags & {"-d", "--delete"} or any(r.startswith(":") for r in refspecs):
        targets = [r.lstrip(":") for r in refspecs]
        return "destroy_history" if any(hook_context.is_protected(t, patterns) for t in targets) else "delete_files"
    if flags & {"--tags", "--follow-tags", "--all"} or any(r.startswith("refs/tags/") or re.fullmatch(r"v?\d+(\.\d+)+.*", r) for r in refspecs):
        return "push_protected"
    if not refspecs or any(r.split(":")[-1] in {"HEAD", "@", ""} for r in refspecs):
        branch = context.get("branch")
        if branch is None and context.get("cwd"):
            branch = hook_context.current_branch(context["cwd"])
        destinations = [branch] if not refspecs else [branch if r.split(":")[-1] in {"HEAD", "@", ""} else r.split(":")[-1] for r in refspecs]
    else:
        destinations = [r.split(":")[-1] for r in refspecs]
    return "push_protected" if any(hook_context.is_protected(d, patterns) for d in destinations) else "push_branch"


def _gh(args: list[str], positional: list[str], context: dict) -> str:
    sub = positional[0] if positional else ""
    second = positional[1] if len(positional) > 1 else ""
    if sub == "auth":
        return "read_secrets" if second == "token" else "read_local" if second in {"status"} else "edit_sensitive"
    if sub == "search":
        return "web_read"
    if sub == "api":
        method = next((args[i + 1].upper() for i, a in enumerate(args[:-1]) if a in {"-X", "--method"}), None)
        if method in {"DELETE"}:
            return "delete_files"
        return "send_data" if method in {"POST", "PUT", "PATCH"} or any(a in {"-f", "-F", "--field", "--raw-field", "--input"} for a in args) else "web_read"
    if second in {"view", "list", "diff", "checks", "status", "watch", "download", "browse"} or sub in {"browse", "status"}:
        return "web_read"
    if sub == "pr":
        if second in {"create", "ready", "edit", "reopen"}:
            return "pr_create"
        if second == "merge" or second == "review" and ("--approve" in args or "-a" in args):
            return "pr_merge"
        if second == "checkout":
            return "edit_files"
        return "send_data"
    if sub in {"repo", "clone"} and second in {"clone", "fork", "sync"} or sub == "clone":
        return "read_local"
    if sub in {"repo", "release", "gist", "label", "secret", "variable", "ruleset", "cache"} and second in {"delete", "remove", "rm"}:
        return "delete_files"
    if sub == "gist" and second in {"create", "new", "edit"}:
        return "send_secrets" if any(is_secret_path(p) for p in positional[2:]) else "send_data"
    if sub in {"issue", "release", "repo", "secret", "variable", "workflow", "run", "label", "ruleset", "codespace", "project"}:
        return "send_data"
    if sub in {"extension", "config", "alias"}:
        return "edit_sensitive" if second in {"install", "set", "upgrade"} else "read_local"
    return "run_command"


def _docker(args: list[str], positional: list[str]) -> str:
    sub = positional[0] if positional else ""
    second = positional[1] if len(positional) > 1 else ""
    if sub in {"ps", "images", "inspect", "logs", "version", "info", "stats", "top", "history", "port", "diff", "events", "search"}:
        return "read_local"
    if sub in {"image", "container", "volume", "network", "system", "builder", "context", "buildx"}:
        if second in {"ls", "list", "inspect", "df", "history", "info", "version"}:
            return "read_local"
        if second in {"rm", "prune", "remove"}:
            return "delete_files"
    if sub in {"rm", "rmi", "prune", "kill"}:
        return "delete_files"
    if sub == "push":
        return "send_data"
    if sub == "login":
        return "edit_sensitive"
    if sub == "pull":
        return "install_packages"
    if sub in {"compose", "stack"}:
        if second in {"down"} and any(a in {"-v", "--volumes", "--rmi"} for a in args):
            return "delete_files"
        if second in {"ps", "logs", "config", "ls", "images", "top", "version"}:
            return "read_local"
        if second == "push":
            return "send_data"
        return "run_command"
    return "run_command"


def _kubectl(args: list[str], positional: list[str]) -> str:
    sub = positional[0] if positional else ""
    second = positional[1] if len(positional) > 1 else ""
    if sub == "get" and second.startswith("secret"):
        return "read_secrets"
    if sub in {"get", "describe", "logs", "top", "explain", "version", "api-resources", "api-versions", "cluster-info", "diff", "events", "wait"}:
        return "read_local"
    if sub == "auth":
        return "read_local"
    if sub == "config":
        return "read_local" if second in {"view", "get-contexts", "current-context", "get-clusters", "get-users"} else "edit_sensitive"
    if sub == "delete":
        return "delete_files"
    if sub in {"apply", "create", "patch", "replace", "scale", "rollout", "set", "edit", "annotate", "label", "expose", "run", "autoscale", "cordon", "drain", "taint", "cp", "exec", "port-forward"}:
        return "send_data"
    return "run_command"


def _aws(args: list[str], positional: list[str], redirects) -> str:
    service = positional[0] if positional else ""
    operation = positional[1] if len(positional) > 1 else ""
    if service == "s3":
        if operation in {"rm", "rb"}:
            return "delete_files"
        if operation in {"cp", "mv", "sync"}:
            paths = positional[2:]
            if paths and paths[-1].startswith("s3://"):
                return "send_secrets" if any(is_secret_path(p) for p in paths[:-1]) else "send_data"
            return "read_local"
        return "read_local"
    if service == "configure":
        if operation == "get":
            return "read_secrets" if len(positional) > 2 and SECRET_NAME.search(positional[2]) else "read_local"
        return "read_local" if operation in {"list", "list-profiles"} else "edit_sensitive"
    if service == "sts" or operation.startswith(("describe-", "list-", "get-", "head-", "lookup-", "search-", "batch-get-", "scan", "query")) or operation in {"help", "wait"}:
        return "read_secrets" if operation in {"get-secret-value", "get-parameter", "get-parameters", "get-session-token", "get-login-password"} else "read_local"
    if operation.startswith(("delete-", "terminate-", "remove-", "deregister-", "purge-", "detach-", "revoke-", "disable-")):
        return "delete_files"
    return "send_data" if operation else "run_command"


def _cloud(verb: str, positional: list[str]) -> str:
    words = set(positional)
    if words & {"delete", "remove", "destroy", "purge"}:
        return "delete_files"
    if verb == "gcloud" and "auth" in words and words & {"print-access-token", "print-identity-token", "application-default"}:
        return "read_secrets" if words & {"print-access-token", "print-identity-token"} else "edit_sensitive"
    if verb == "az" and "account" in words and "get-access-token" in words:
        return "read_secrets"
    if "config" in words and words & {"set", "unset"} or "login" in words:
        return "edit_sensitive"
    if words & {"list", "describe", "show", "get", "get-iam-policy", "read", "browse", "version", "info", "logs", "tail"}:
        return "read_local"
    if words & {"deploy", "create", "update", "set", "add", "start", "stop", "restart", "ssh", "scp", "submit", "run", "upload", "import", "publish", "apply"}:
        return "send_data"
    return "run_command"


# Tools ---------------------------------------------------------------------------------

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
    keys = ("file_path", "path", "notebook_path", "AbsolutePath", "TargetFile", "filePath", "target_file", "pattern", "Directory", "absolute_path")
    return " ".join(str(tool_input[k]) for k in keys if isinstance(tool_input.get(k), str))


def _edit_paths(tool_input: dict) -> list[str]:
    paths = [str(tool_input[k]) for k in ("file_path", "path", "notebook_path", "AbsolutePath", "TargetFile", "filePath", "target_file", "absolute_path")
             if isinstance(tool_input.get(k), str)]
    patch = tool_input.get("patch") or tool_input.get("input") or ""
    if isinstance(patch, str):
        paths += re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", patch, re.M)
        paths += re.findall(r"^\*\*\* Move to: (.+)$", patch, re.M)
    for edit in tool_input.get("edits", []) if isinstance(tool_input.get("edits"), list) else []:
        if isinstance(edit, dict) and isinstance(edit.get("file_path"), str):
            paths.append(edit["file_path"])
    return paths


def _mcp_name(name: str) -> tuple[str, str] | None:
    if name.startswith("mcp__"):
        server, _, tool = name[5:].partition("__")
        return (server, tool) if server and tool else None
    if "__" in name and not name.startswith("_"):
        server, _, tool = name.partition("__")
        return (server, tool) if server and tool else None
    return None


def classify(tool_name: str, tool_input: dict, context: dict | None = None) -> Action:
    """Classify one tool call. `context` may carry cwd, branch and protected_branches; facts not given are looked up lazily."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    context = dict(context or {})
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
        action = classify_shell(command, context)
        if action != "read_local" and touches_agent_settings(command):
            return Action("protected", reason="Agents may not change their own hook or permission settings")
        return Action("builtin", tool=action, arguments={"command": command[:4000]})
    if key in EDIT_TOOLS:
        paths = _edit_paths(tool_input)
        joined = " ".join(paths) or _path_text(tool_input)
        if touches_agent_settings(joined):
            return Action("protected", reason="Agents may not change their own hook or permission settings")
        patch = tool_input.get("patch") or tool_input.get("input") or ""
        deleting = key == "delete_file" or isinstance(patch, str) and "*** Delete File:" in patch
        action = "edit_sensitive" if any(is_sensitive_path(p, context) for p in paths) else "delete_files" if deleting else "edit_files"
        return Action("builtin", tool=action, arguments={"path": joined[:1000]})
    if key in WEB_TOOLS:
        target = str(tool_input.get("url", tool_input.get("Url", tool_input.get("query", tool_input.get("Query", "")))))
        action = _web_action(target) if target.startswith(("http://", "https://")) else "web_read"
        return Action("builtin", tool=action, arguments={"target": target[:1000]})
    if key in READ_TOOLS:
        path = _path_text(tool_input)
        return Action("builtin", tool="read_secrets" if path and is_secret_path(path.split()[0]) else "read_local", arguments={"path": path[:1000]})
    # Unknown built-in tools are treated as consequential, never as reads.
    return Action("builtin", tool="run_command", arguments={"tool": name[:200]})
