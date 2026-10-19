#!/usr/bin/env python3
"""Legacy graph verdict regression fixtures, not an agent security benchmark.

This runner records RuntimeTaintGraph decisions for scripted calls. It executes
neither an LLM nor destination tools; compromise and real task completion are
therefore unavailable. Use measured_runner for observed mock endpoint effects.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
from pathlib import Path
import platform
import statistics
import sys
import time
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parent.parent
for root in (REPO_ROOT / "src", REPO_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from benchmarks.scenarios_50 import CLEAN_WORKFLOWS, EXPLOIT_SCENARIOS_50
from mirage_mcp.graph.taint_dag import RuntimeTaintGraph

LIMITATIONS = [
    "Scripted tool calls; no LLM or agent followed the injected content.",
    "Graph verdicts only: destination execution and compromise are not measured.",
    "The former 84% unprotected baseline was assigned by index and is withdrawn.",
    "Timing covers in-process graph calls, excluding proxy, database, IPC and destination overhead.",
    "These fixtures do not establish real-world protection or false-positive rates.",
]


def percentile(values: list[float], quantile: float) -> float:
    """Nearest-rank percentile; defined for one sample and never indexes past n."""
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return round(ordered[max(0, math.ceil(len(ordered) * quantile) - 1)], 4)


def run_full_benchmark(write_artifacts: bool = True) -> Dict[str, Any]:
    exploit_results = []
    clean_results = []
    latencies = []
    payload_sizes = []
    for scenarios, destination in ((EXPLOIT_SCENARIOS_50, exploit_results), (CLEAN_WORKFLOWS, clean_results)):
        for sc in scenarios:
            graph = RuntimeTaintGraph(user_prompt=sc["user_prompt"], strict_topology=True)
            started = time.perf_counter()
            hop1 = graph.record_hop1_response(f"{sc['id']}_hop1", sc["hop1_server"], sc["hop1_tool"], sc["hop1_payload"])
            allowed, reason, hop2 = graph.verify_hop2_call(f"{sc['id']}_hop2", sc["hop2_server"], sc["hop2_tool"], sc["hop2_args_json"])
            elapsed = (time.perf_counter() - started) * 1000
            latencies.append(elapsed)
            payload_bytes = len(sc["hop1_payload"].encode()) + len(sc["hop2_args_json"].encode())
            payload_sizes.append(payload_bytes)
            row = {
                "id": sc["id"], "name": sc["name"],
                "hop1_tool": f"{sc['hop1_server']}.{sc['hop1_tool']}",
                "hop2_tool": f"{sc['hop2_server']}.{sc['hop2_tool']}",
                "allowed": allowed, "verdict": hop2["verdict"], "reason": reason,
                "total_latency_ms": round(elapsed, 4), "payload_bytes": payload_bytes,
                "destination_executed": None,
            }
            if destination is exploit_results:
                row.update({
                    "architecture_id": sc["architecture_id"], "architecture_name": sc["architecture_name"],
                    "obfuscation_vector": sc["obfuscation_vector"],
                    "unprotected_mcp_compromised": None, "mirage_allowed": allowed,
                    "mirage_blocked": not allowed, "matched_taint_tokens": hop2.get("matched_taint_tokens", []),
                    "hop1_latency_ms": hop1["latency_ms"], "hop2_latency_ms": hop2["latency_ms"],
                })
            else:
                # Legacy API field: interruption of a fixture's intended legitimate call.
                row["false_positive"] = not allowed
            destination.append(row)
    blocked = sum(r["mirage_blocked"] for r in exploit_results)
    interrupted = sum(not r["allowed"] for r in clean_results)
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evaluation_kind": "scripted_graph_verdict_fixtures", "baseline_status": "not_measured",
        "total_exploit_scenarios": len(exploit_results),
        "unprotected_exploits_succeeded": None, "unprotected_exploit_success_rate_pct": None,
        "unprotected_block_rate_pct": None,
        "mirage_exploits_blocked": blocked,
        "mirage_block_rate_pct": round(100 * blocked / len(exploit_results), 1),
        "total_clean_workflows": len(clean_results), "clean_workflows_allowed": len(clean_results) - interrupted,
        "mirage_false_positives": interrupted,
        "mirage_false_positive_rate_pct": round(100 * interrupted / len(clean_results), 1),
        "mirage_mean_latency_ms": round(statistics.mean(latencies), 4),
        "mirage_p50_latency_ms": percentile(latencies, .5),
        "mirage_p95_latency_ms": percentile(latencies, .95), "mirage_p99_latency_ms": percentile(latencies, .99),
        "payload_bytes_min": min(payload_sizes), "payload_bytes_max": max(payload_sizes),
        "sample_count": len(latencies), "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "token_cost_usd": 0.0, "agent_calls": 0,
    }
    report = {"summary": summary, "limitations": LIMITATIONS, "exploit_results": exploit_results, "clean_workflow_results": clean_results}
    if write_artifacts:
        directory = Path(__file__).resolve().parent
        (directory / "results_50_setups.json").write_text(json.dumps(report, indent=2) + "\n")
        (directory / "RESULTS_50_SETUPS.md").write_text(format_markdown_report(report))
    return report


def format_markdown_report(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# Elytra scripted graph verdict fixtures", "", f"Generated: {s['timestamp']}", "",
        "The old 84% unprotected compromise claim is withdrawn. It was assigned by fixture index, not observed.", "",
        "No agent or destination tool executes in this runner. These are regression observations, not a security guarantee.", "",
        "| Observation | Result |", "| --- | --- |",
        "| Unprotected compromise baseline | Not measured |",
        f"| Scripted adversarial calls rejected by graph | {s['mirage_exploits_blocked']}/{s['total_exploit_scenarios']} |",
        f"| Intended legitimate calls allowed by graph | {s['clean_workflows_allowed']}/{s['total_clean_workflows']} |",
        f"| Intended legitimate calls interrupted | {s['mirage_false_positives']}/{s['total_clean_workflows']} |",
        f"| Graph only p50 / p95 / p99 (ms) | {s['mirage_p50_latency_ms']} / {s['mirage_p95_latency_ms']} / {s['mirage_p99_latency_ms']} |",
        f"| Payload bytes, UTF-8 source + arguments | {s['payload_bytes_min']}–{s['payload_bytes_max']} |",
        f"| Samples | {s['sample_count']} |", "",
        f"Environment: `{json.dumps(s['environment'], sort_keys=True)}`", "", "## Limitations", "",
    ]
    lines.extend(f"- {item}" for item in report.get("limitations", LIMITATIONS))
    lines += ["", "## Scripted adversarial calls", "", "| ID | Source → destination | Graph verdict | Graph time (ms) |", "| --- | --- | --- | --- |"]
    for r in report["exploit_results"]:
        lines.append(f"| {r['id']} | {r['hop1_tool']} → {r['hop2_tool']} | {r['verdict']} | {r['total_latency_ms']} |")
    lines += ["", "## Intended legitimate calls", "", "| ID | Workflow | Allowed | Graph time (ms) |", "| --- | --- | --- | --- |"]
    for r in report["clean_workflow_results"]:
        lines.append(f"| {r['id']} | {r['name']} | {r['allowed']} | {r['total_latency_ms']} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(format_markdown_report(run_full_benchmark()), end="")
