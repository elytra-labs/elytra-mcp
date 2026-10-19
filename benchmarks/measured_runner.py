"""Observed local effects of scripted tool calls through RuntimeService.

No LLM, provider, customer account, or real external mutation is involved. The
bypass arm is a scripted dispatch comparison, not an agent compromise baseline.
"""
from __future__ import annotations
from contextlib import ExitStack
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for entry in (REPO_ROOT, REPO_ROOT / "src"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))
from benchmarks.runner import percentile
from benchmarks.scenarios_50 import CLEAN_WORKFLOWS, EXPLOIT_SCENARIOS_50
from mirage_mcp.runtime.service import RuntimeService, RuntimeConflictError


class EffectEndpoint:
    def __init__(self, directory: Path, name: str, tool: str, payload: str, kind: str):
        self.database = directory / f"{name}.db"
        config = directory / f"{name}.json"
        config.write_text(json.dumps({"database": str(self.database), "tool_name": tool, "payload": payload, "kind": kind}))
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("effect_server.py")), str(config)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.counter = 0
        # Handshake makes process startup explicit and excludes it from call timing.
        self.call("tools/list", {})

    def call(self, method: str, params: dict) -> dict:
        self.counter += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], 10)[0]:
            raise TimeoutError("Fixture endpoint did not answer within 10 seconds")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("Fixture endpoint exited before returning a result")
        response = json.loads(line)
        if response.get("id") != self.counter or "error" in response:
            raise RuntimeError(f"Fixture endpoint returned an invalid result: {response!r}")
        return response["result"]

    def mutations(self) -> int:
        with sqlite3.connect(self.database) as connection:
            return connection.execute("SELECT COALESCE(SUM(mutation), 0) FROM receipts").fetchone()[0]

    def receipts(self) -> list[dict]:
        with sqlite3.connect(self.database) as connection:
            return [json.loads(row[0]) for row in connection.execute("SELECT arguments FROM receipts ORDER BY id")]

    def close(self):
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        for stream in (self.process.stdout, self.process.stderr):
            if stream:
                stream.close()


def _register(runtime, run, server, tool, category):
    # Registration represents a complete logical server inventory. Some fixture
    # pairs use two endpoint subprocesses for distinct tools on the same server;
    # retain those tools rather than falsely report removal on each discovery.
    inventory = {record["tool_name"]: record["tool_definition"]
                 for record in runtime.list_tools()
                 if record["server_id"] == server and record.get("present", True)}
    inventory[tool] = {"name": tool, "inputSchema": {"type": "object"}}
    runtime.register_tools(run["run_id"], run["run_token"], server,
                           list(inventory.values()), classifications={tool: category})


def _dispatch(runtime, run, endpoint, server, tool, arguments, call_id):
    decision = runtime.evaluate(run["run_id"], run["run_token"], server, tool, arguments, call_id)
    if decision["decision"] != "ALLOW":
        return decision, None
    claimed = runtime.claim_execution(run["run_id"], run["run_token"], call_id, decision["permit"], arguments)
    result = endpoint.call("tools/call", {"name": tool, "arguments": claimed["arguments"]})
    result = runtime.complete_execution(run["run_id"], run["run_token"], call_id, result)
    return decision, result


def run_pair(fixture: dict, *, protected: bool, grant_arguments: dict | None = None, classify_sink=True, approval: str | None = None, replay=False, tamper_after_approval=False) -> dict:
    """Execute identical source and attempted sink in fresh arm-specific state."""
    arguments = json.loads(fixture["hop2_args_json"])
    with tempfile.TemporaryDirectory(prefix="elytra-observed-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        source = EffectEndpoint(directory, "source", fixture["hop1_tool"], fixture["hop1_payload"], "source")
        stack.callback(source.close)
        sink = EffectEndpoint(directory, "sink", fixture["hop2_tool"], "", "sink")
        stack.callback(sink.close)
        runtime = None
        if protected:
            runtime = RuntimeService(directory / "runtime.db")
            stack.callback(runtime.close)
            grants = [] if grant_arguments is None else [{"server_id": fixture["hop2_server"], "tool_name": fixture["hop2_tool"], "arguments": grant_arguments}]
            run = runtime.create_run(fixture["user_prompt"], grants=grants)
            _register(runtime, run, fixture["hop1_server"], fixture["hop1_tool"], "SOURCE_UNTRUSTED")
            _register(runtime, run, fixture["hop2_server"], fixture["hop2_tool"], "SINK_PRIVILEGED_WRITE" if classify_sink else "UNKNOWN")
        before = sink.mutations()
        tampered_claim_rejected = None
        started = time.perf_counter()
        if protected:
            _dispatch(runtime, run, source, fixture["hop1_server"], fixture["hop1_tool"], {}, "source")
            decision, response = _dispatch(runtime, run, sink, fixture["hop2_server"], fixture["hop2_tool"], arguments, "sink")
            if approval is not None and decision.get("approval_id"):
                if approval == "CANCELLED":
                    runtime.cancel_call(run["run_id"], run["run_token"], "sink")
                else:
                    runtime.resolve_approval(decision["approval_id"], approval)
                if tamper_after_approval:
                    decision = runtime.evaluate(run["run_id"], run["run_token"], fixture["hop2_server"], fixture["hop2_tool"], arguments, "sink")
                    try:
                        runtime.claim_execution(run["run_id"], run["run_token"], "sink", decision["permit"], {**arguments, "extra": "not approved"})
                        tampered_claim_rejected = False
                    except RuntimeConflictError:
                        tampered_claim_rejected = True
                else:
                    decision, response = _dispatch(runtime, run, sink, fixture["hop2_server"], fixture["hop2_tool"], arguments, "sink")
        else:
            source.call("tools/call", {"name": fixture["hop1_tool"], "arguments": {}})
            response = sink.call("tools/call", {"name": fixture["hop2_tool"], "arguments": arguments})
            decision = {"decision": "BYPASS", "status": "DISPATCHED"}
        elapsed = (time.perf_counter() - started) * 1000
        replay_rejected = None
        if replay and protected and decision.get("permit"):
            try:
                runtime.claim_execution(run["run_id"], run["run_token"], "sink", decision["permit"], arguments)
                replay_rejected = False
            except RuntimeConflictError:
                replay_rejected = True
        after = sink.mutations()
        return {"fixture_id": fixture["id"], "arm": "protected" if protected else "bypass",
                "attempt": {"source_server": fixture["hop1_server"], "source_tool": fixture["hop1_tool"], "source_payload": fixture["hop1_payload"], "server_id": fixture["hop2_server"], "tool_name": fixture["hop2_tool"], "arguments": arguments},
                "permission": {"exact_grant_arguments": grant_arguments, "sink_classified": classify_sink, "operator_resolution": approval, "tamper_after_approval": tamper_after_approval},
                "decision": {key: value for key, value in decision.items() if key != "permit"}, "response": response,
                "mutation_before": before, "mutation_after": after, "mutation_delta": after - before,
                "destination_received_arguments": sink.receipts(), "replay_rejected": replay_rejected, "tampered_claim_rejected": tampered_claim_rejected,
                "elapsed_ms": round(elapsed, 4), "payload_bytes": len(fixture["hop1_payload"].encode()) + len(fixture["hop2_args_json"].encode())}


def run_isolation_check() -> dict:
    fixture = CLEAN_WORKFLOWS[-3]
    arguments = json.loads(fixture["hop2_args_json"])
    with tempfile.TemporaryDirectory(prefix="elytra-isolation-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        runtime = RuntimeService(directory / "runtime.db")
        stack.callback(runtime.close)
        grants = [{"server_id": fixture["hop2_server"], "tool_name": fixture["hop2_tool"], "arguments": arguments}]
        runs = [runtime.create_run("Isolation fixture", grants=grants) for _ in range(2)]
        source = EffectEndpoint(directory, "source", fixture["hop1_tool"], fixture["hop1_payload"], "source")
        sink = EffectEndpoint(directory, "sink", fixture["hop2_tool"], "", "sink")
        stack.callback(source.close)
        stack.callback(sink.close)
        for run in runs:
            _register(runtime, run, fixture["hop1_server"], fixture["hop1_tool"], "SOURCE_UNTRUSTED")
            _register(runtime, run, fixture["hop2_server"], fixture["hop2_tool"], "SINK_PRIVILEGED_WRITE")
        runtime.save_policy({"rule_id": "isolation", "sink_pattern": fixture["hop2_server"] + "." + fixture["hop2_tool"], "source_pattern": "*", "min_taint_level": "HIGH", "action": "BLOCK_SECOND_HOP"})
        _dispatch(runtime, runs[0], source, fixture["hop1_server"], fixture["hop1_tool"], {}, "read")
        dirty, _ = _dispatch(runtime, runs[0], sink, fixture["hop2_server"], fixture["hop2_tool"], arguments, "write")
        clean, _ = _dispatch(runtime, runs[1], sink, fixture["hop2_server"], fixture["hop2_tool"], arguments, "write")
        return {"name": "shared_service_run_isolation", "tainted_run_decision": dirty["decision"], "independent_run_decision": clean["decision"], "mutation_delta": sink.mutations(), "passed": dirty["decision"] == "BLOCK" and clean["decision"] == "ALLOW" and sink.mutations() == 1}


def run_measured_benchmark(write_artifacts=True, *, exploit_limit=None) -> dict[str, Any]:
    pairs = []
    for fixture in EXPLOIT_SCENARIOS_50[:exploit_limit]:
        baseline = run_pair(fixture, protected=False)
        protected = run_pair(fixture, protected=True)
        pairs.append({"kind": "scripted_adversarial_call", "bypass": baseline, "protected": protected,
                      "passed": baseline["mutation_delta"] == 1 and protected["mutation_delta"] == 0 and protected["decision"]["decision"] in {"STEP_UP", "BLOCK"}})
    checks = []
    for fixture in CLEAN_WORKFLOWS[-3:]:
        exact = json.loads(fixture["hop2_args_json"])
        baseline = run_pair(fixture, protected=False, grant_arguments=exact)
        protected = run_pair(fixture, protected=True, grant_arguments=exact)
        pairs.append({"kind": "legitimate_external_read_exact_grant", "bypass": baseline, "protected": protected, "passed": baseline["mutation_delta"] == 1 and protected["mutation_delta"] == 1 and baseline["destination_received_arguments"] == protected["destination_received_arguments"]})
        mutated = {**fixture, "id": fixture["id"] + "_MUTATED", "hop2_args_json": json.dumps({**exact, "unauthorized_extra": "attacker-changed-argument"})}
        result = run_pair(mutated, protected=True, grant_arguments=exact)
        checks.append({"name": mutated["id"], "result": result, "passed": result["mutation_delta"] == 0 and result["decision"]["decision"] == "STEP_UP"})
    fixture = CLEAN_WORKFLOWS[-3]
    for name, options, expected_mutations in [
        ("unknown_capability", {"classify_sink": False}, 0),
        ("denied_approval", {"approval": "DENIED"}, 0),
        ("cancelled_pending_call", {"approval": "CANCELLED"}, 0),
        ("approved_argument_substitution", {"approval": "APPROVED", "tamper_after_approval": True}, 0),
        ("approved_once_and_replay", {"approval": "APPROVED", "replay": True}, 1),
    ]:
        result = run_pair(fixture, protected=True, **options)
        passed = result["mutation_delta"] == expected_mutations and (name != "approved_once_and_replay" or result["replay_rejected"] is True) and (name != "approved_argument_substitution" or result["tampered_claim_rejected"] is True)
        checks.append({"name": name, "result": result, "passed": passed})
    checks.append(run_isolation_check())
    arm_latency = {}
    for arm in ("bypass", "protected"):
        values = [pair[arm]["elapsed_ms"] for pair in pairs]
        arm_latency[arm] = {"samples": len(values), "p50_ms": percentile(values, .5), "p95_ms": percentile(values, .95), "p99_ms": percentile(values, .99)}
    overhead = [pair["protected"]["elapsed_ms"] - pair["bypass"]["elapsed_ms"] for pair in pairs]
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "evaluation_kind": "scripted_runtime_with_subprocess_effects", "agent_calls": 0, "unprotected_agent_compromise_rate": None,
              "environment": {"python": platform.python_version(), "platform": platform.platform()}, "pairs": pairs, "checks": checks,
              "timing": {"arms": arm_latency, "paired_difference_ms": {"p50": percentile(overhead, .5), "p95": percentile(overhead, .95), "p99": percentile(overhead, .99)}, "startup_included": False, "warmup_calls": 0, "human_wait_included": False, "payload_bytes_min": min(pair["protected"]["payload_bytes"] for pair in pairs), "payload_bytes_max": max(pair["protected"]["payload_bytes"] for pair in pairs)},
              "passed": all(pair["passed"] for pair in pairs) and all(check["passed"] for check in checks),
              "limitations": ["Scripted calls, not agent-selected actions or real provider accounts.", "Direct RuntimeService dispatch with subprocess endpoints; HTTP/SDK transport is outside this harness.", "Temporary SQLite ledger effects only; no real shell, database, finance or external network operation.", "Bypass arm measures direct call effects, not agent compromise probability.", "Small sequential local sample; includes source + sink runtime/ledger/IPC cost but excludes process startup, setup, provider latency and human waiting."]}
    if write_artifacts:
        target = REPO_ROOT / "docs" / "evaluation"
        target.mkdir(parents=True, exist_ok=True)
        (target / "observed_effects.json").write_text(json.dumps(report, indent=2) + "\n")
        lines = ["# Scripted runtime observations", "", f"Generated: {report['timestamp']}", "", f"Fixture pair checks passed: {sum(p['passed'] for p in pairs)}/{len(pairs)}. Boundary checks passed: {sum(c['passed'] for c in checks)}/{len(checks)}.", "", "No language model or live external destination was used. No agent compromise rate is available.", "", "## Timing", "", "```json", json.dumps({"environment": report["environment"], **report["timing"]}, indent=2), "```", "", "## Limitations", ""]
        lines.extend("- " + item for item in report["limitations"])
        lines += ["", "Full recorded attempts, decisions and observed ledger effects: [observed_effects.json](observed_effects.json).", ""]
        (target / "OBSERVED_EFFECTS.md").write_text("\n".join(lines))
    return report


if __name__ == "__main__":
    report = run_measured_benchmark()
    print(json.dumps({"passed": report["passed"], "pairs": len(report["pairs"]), "checks": len(report["checks"]), "timing": report["timing"]}, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
