"""Host-session identity for agent hosts such as Claude Code or Cursor.

A host launches each MCP server as a child process. Servers launched by the
same host process share one session, so untrusted context read through one
server applies to writes through another. Separate host processes never share
a session. This relies on operating-system process grouping and is weaker than
an explicit run supplied by a trusted orchestrator.
"""
from __future__ import annotations

import hashlib
import os
import subprocess

from mirage_mcp.sdk import RuntimeAPIError, RuntimeClient

_SHELLS = {"sh", "bash", "zsh", "dash", "fish", "env", "cmd", "cmd.exe", "powershell", "pwsh"}


def _ps(pid: int, fields: str) -> str:
    result = subprocess.run(["ps", "-o", fields + "=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
    return result.stdout.strip()


def host_process(start: int | None = None) -> int:
    """The nearest ancestor that is not a wrapper shell (hosts sometimes launch servers via `sh -c`)."""
    pid = start or os.getppid()
    for _ in range(4):
        comm = _ps(pid, "comm")
        command = os.path.basename(comm.split()[0]) if comm else ""
        if command.lstrip("-") not in _SHELLS:
            return pid
        parent = _ps(pid, "ppid")
        if not parent.isdigit() or int(parent) <= 1:
            return pid
        pid = int(parent)
    return pid


def host_session_key(pid: int | None = None) -> str:
    host = host_process(pid)
    started = _ps(host, "lstart")
    if not started:
        raise RuntimeError("Cannot identify the agent host process for this session")
    return hashlib.sha256(f"{os.getuid()}:{host}:{started}".encode()).hexdigest()[:32]


class HostSessionClient:
    """Run-scoped client that reopens its host session if the runtime restarted.

    Only operations that precede dispatch (registering tools, evaluating a new
    call) are retried after reopening. A claim, completion or cancellation is
    bound to the run that issued it and is never replayed against a new run.
    """

    _RETRYABLE = {"register_tools", "evaluate", "observe_tool"}

    def __init__(self, host_id: str, host_token: str, session_key: str, base_url: str, parent_key=None, resume: dict | None = None, on_open=None):
        """`parent_key` (a value or a callable computed only when needed) makes this a conversation inside a host process.
        `resume` reuses an already opened session without contacting the runtime; it reopens on first rejection."""
        self._args = (host_id, host_token, session_key)
        self._base_url = base_url
        self._parent_key = parent_key
        self._on_open = on_open
        if resume:
            self._client = RuntimeClient(base_url=base_url, token=host_token).for_run(resume["run_id"], resume["run_token"])
            self._client.session = resume
        else:
            self._open()

    def _open(self):
        parent = self._parent_key() if callable(self._parent_key) else self._parent_key
        self._client = RuntimeClient.host_session(*self._args, base_url=self._base_url, parent_key=parent)
        if self._on_open:
            self._on_open(self._client.session)

    @property
    def session(self) -> dict:
        return self._client.session

    def _reopen(self):
        self._open()

    def __getattr__(self, name):
        target = getattr(self._client, name)
        if name not in self._RETRYABLE or not callable(target):
            return target

        def call(*args, **kwargs):
            try:
                return getattr(self._client, name)(*args, **kwargs)
            except RuntimeAPIError as exc:
                if exc.status != 403:
                    raise
                self._reopen()
                return getattr(self._client, name)(*args, **kwargs)
        return call
