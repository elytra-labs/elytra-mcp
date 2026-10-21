"""Desktop notifications for calls held for an operator decision.

Text is passed as process arguments, never interpolated into a script, so a
tool or server name cannot inject AppleScript. Disable with
ELYTRA_NOTIFICATIONS=0.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, Sequence

Runner = Callable[[Sequence[str]], None]

_APPLESCRIPT = ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv) sound name \"Glass\"", "-e", "end run"]


def _spawn(command: Sequence[str]) -> None:
    subprocess.Popen(list(command), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)


class DesktopNotifier:
    def __init__(self, runner: Runner | None = None, platform: str | None = None, enabled: bool | None = None, interval: float = 20.0):
        self._runner = runner or _spawn
        self._platform = platform or sys.platform
        self._enabled = (os.environ.get("ELYTRA_NOTIFICATIONS", "1") != "0") if enabled is None else enabled
        self._interval = interval
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def _command(self, title: str, body: str) -> list[str] | None:
        if self._platform == "darwin":
            return ["/usr/bin/osascript", *_APPLESCRIPT, title, body]
        if self._platform.startswith("linux") and shutil.which("notify-send"):
            return ["notify-send", "--app-name=Elytra", title, body]
        return None

    def notify_event(self, event: dict) -> bool:
        """Notify once per run per interval when a call is held, and always when content looks like a prompt injection."""
        decision = event.get("decision")
        injection = decision == "INJECTION_SUSPECTED"
        if not self._enabled or not injection and (decision != "STEP_UP_REQUIRED" or event.get("notify") is False):
            return False
        run_id = str(event.get("run_id", ""))
        now = time.monotonic()
        with self._lock:
            key = run_id + (":injection" if injection else "")
            if now - self._last.get(key, -1e9) < self._interval:
                return False
            self._last[key] = now
        reason = str(event.get("reason") or "").strip().rstrip(".")[:180]
        if injection:
            command = self._command("Elytra: possible prompt injection", f"{reason}. Changes in that session now need your OK.")
        else:
            tool = f"{event.get('server_id', '')}.{event.get('tool_name', '')}"[:120]
            command = self._command("Elytra: decision needed", f"{tool}: {reason or 'held for your decision'}. Review it with elytra open.")
        if not command:
            return False
        try:
            self._runner(command)
        except OSError:
            return False
        return True
