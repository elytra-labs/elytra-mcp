"""Run the local runtime as a per-user background service (launchd or systemd --user)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Sequence
from urllib.request import ProxyHandler, build_opener

LABEL = "dev.elytra.runtime"
Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]


def _run(command: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(command), capture_output=True, text=True, timeout=30)


def runtime_command() -> list[str]:
    return [sys.executable, "-m", "mirage_mcp.cli.main", "up"]


def healthy(gateway: str = "http://127.0.0.1:8765", timeout: float = 2) -> bool:
    try:
        with build_opener(ProxyHandler({})).open(gateway.rstrip("/") + "/api/v1/health", timeout=timeout) as response:
            return response.status == 200
    except Exception:
        return False


def wait_healthy(gateway: str = "http://127.0.0.1:8765", seconds: float = 20) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if healthy(gateway):
            return True
        time.sleep(0.4)
    return False


class Service:
    def __init__(self, home: Path | None = None, platform: str | None = None, runner: Runner | None = None):
        self.home = home or Path.home()
        self.platform = platform or sys.platform
        self.run = runner or _run
        self.log = self.home / ".elytra" / "runtime.log"

    @property
    def supported(self) -> bool:
        return self.platform == "darwin" or self.platform.startswith("linux")

    @property
    def path(self) -> Path:
        if self.platform == "darwin":
            return self.home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
        return self.home / ".config" / "systemd" / "user" / "elytra.service"

    def definition(self) -> str:
        command = runtime_command()
        if self.platform == "darwin":
            args = "".join(f"\n      <string>{part}</string>" for part in command)
            return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>{args}
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>HOME</key>
      <string>{self.home}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{self.log}</string>
    <key>StandardErrorPath</key>
    <string>{self.log}</string>
  </dict>
</plist>
"""
        quoted = " ".join(json.dumps(part) for part in command)
        return f"""[Unit]
Description=Elytra local runtime

[Service]
Environment={json.dumps("HOME=" + str(self.home))}
ExecStart={quoted}
Restart=on-failure

[Install]
WantedBy=default.target
"""

    def install(self) -> str:
        if not self.supported:
            raise RuntimeError("Background service is supported on macOS and Linux. Run `elytra up` instead.")
        if any(not part for part in runtime_command()) or any("<" in part or "&" in part for part in [*runtime_command(), str(self.home)]):
            raise RuntimeError("Unsupported interpreter path for a service definition")
        self.log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(self.definition())
        os.chmod(self.path, 0o644)
        self.start()
        return str(self.path)

    def start(self) -> None:
        if self.platform == "darwin":
            uid = os.getuid()
            self.run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"])
            result = self.run(["launchctl", "bootstrap", f"gui/{uid}", str(self.path)])
        else:
            self.run(["systemctl", "--user", "daemon-reload"])
            result = self.run(["systemctl", "--user", "enable", "--now", "elytra.service"])
        if result.returncode != 0:
            raise RuntimeError("Could not start the Elytra service: " + (result.stderr or result.stdout).strip()[:300])

    def stop(self) -> None:
        if self.platform == "darwin":
            self.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"])
        else:
            self.run(["systemctl", "--user", "disable", "--now", "elytra.service"])

    def uninstall(self) -> bool:
        if not self.path.exists():
            return False
        self.stop()
        self.path.unlink()
        return True

    def installed(self) -> bool:
        return self.path.exists()
