"""Wall-clock cost of Elytra's hook per agent tool call.

Spawns the hook process exactly as an agent does (`python -m mirage_mcp.hooks pre`,
JSON on stdin) against a live runtime, and reports p50/p95 for a read and an edit.

    python -m benchmarks.hook_latency [--calls 30] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OWNER = "owner-" + "c" * 48


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def measure(calls: int = 30) -> dict:
    from mirage_mcp.cli import agents
    from mirage_mcp.sdk import RuntimeClient
    from mirage_mcp.server import ControlPlaneServer
    from mirage_mcp.server.notify import DesktopNotifier

    with tempfile.TemporaryDirectory(prefix="elytra-latency-") as folder:
        root = Path(folder)
        server = ControlPlaneServer(db_path=root / "runtime.db", port=0, token_file=root / "token", auth_token=OWNER)
        server.notifier = DesktopNotifier(enabled=False)
        base = server.start_background()
        try:
            owner = RuntimeClient(base, token=OWNER)
            owner.install_agent_actions()
            owner.apply_guardrails("balanced")
            credential = owner.create_host("Claude Code", "claude-code", 600)
            agents.save_credential("claude-code", credential, approval_window=600, fail_closed=False, gateway=base,
                                   wrapped_servers=[], home=root)
            env = {**os.environ, "HOME": str(root), "PYTHONPATH": os.pathsep.join([str(REPO / "src"), str(REPO)])}
            samples: dict[str, list[float]] = {}
            for label, tool, tool_input in (("read", "Read", {"file_path": "/tmp/p/src/app.py"}),
                                            ("edit", "Edit", {"file_path": "/tmp/p/src/app.py", "old_string": "a", "new_string": "b"})):
                timings = []
                for index in range(calls + 2):
                    payload = {"session_id": "latency", "cwd": "/tmp/p", "permission_mode": "default", "hook_event_name": "PreToolUse",
                               "tool_name": tool, "tool_input": tool_input, "tool_use_id": f"toolu_{label}_{index}"}
                    started = time.perf_counter()
                    subprocess.run([sys.executable, "-m", "mirage_mcp.hooks", "pre"], input=json.dumps(payload), capture_output=True,
                                   text=True, env=env, check=True)
                    if index >= 2:  # The first calls open the session and warm the file cache.
                        timings.append((time.perf_counter() - started) * 1000)
                samples[label] = timings
            started = time.perf_counter()
            subprocess.run([sys.executable, "-c", "pass"], env=env, check=True)
            interpreter = (time.perf_counter() - started) * 1000
        finally:
            server.stop()
    return {"calls": calls, "python_startup_ms": round(interpreter, 1),
            **{label: {"p50_ms": round(statistics.median(values), 1), "p95_ms": round(_percentile(values, 0.95), 1)} for label, values in samples.items()}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--calls", type=int, default=30)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = measure(args.calls)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Hook latency over {summary['calls']} calls (Python startup alone: {summary['python_startup_ms']} ms)")
        for label in ("read", "edit"):
            print(f"  {label:5} p50 {summary[label]['p50_ms']} ms   p95 {summary[label]['p95_ms']} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
