#!/usr/bin/env python3
"""Local implementation checks; passing is not a security certification.

Measures the integrated runtime against scripted subprocess effects, verifies
honest evidence metadata, parses Python sources, and checks a built web artifact.
Latency is reported with its measurement boundary; no universal <2ms threshold
or cosmetic UI rule substitutes for execution integrity.
"""
from __future__ import annotations
import ast
import json
import math
from pathlib import Path
import subprocess
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for entry in (REPO_ROOT, REPO_ROOT / "src"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))


def gate_1_evidence_integrity() -> dict[str, Any]:
    from benchmarks.runner import run_full_benchmark
    report = run_full_benchmark(write_artifacts=False)
    summary = report["summary"]
    unavailable = all(summary[key] is None for key in ("unprotected_exploits_succeeded", "unprotected_exploit_success_rate_pct", "unprotected_block_rate_pct"))
    unavailable = unavailable and all(row["unprotected_mcp_compromised"] is None for row in report["exploit_results"])
    timings = [summary[f"mirage_p{percentile}_latency_ms"] for percentile in (50, 95, 99)]
    passed = unavailable and summary["agent_calls"] == 0 and summary["evaluation_kind"] == "scripted_graph_verdict_fixtures" and bool(report["limitations"]) and all(math.isfinite(value) and value >= 0 for value in timings)
    return {"gate": "Evidence integrity and graph observations", "passed": passed,
            "baseline": summary["baseline_status"], "adversarial_fixture_rejections": f"{summary['mirage_exploits_blocked']}/{summary['total_exploit_scenarios']}",
            "legitimate_fixture_interruptions": f"{summary['mirage_false_positives']}/{summary['total_clean_workflows']}",
            "graph_only_p50_p95_p99_ms": timings, "interpretation": "Fixture verdicts only; interruption observations do not fail this metadata check."}


def gate_2_runtime_effects() -> dict[str, Any]:
    from benchmarks.measured_runner import run_measured_benchmark
    report = run_measured_benchmark(write_artifacts=False)
    return {"gate": "Runtime authorization and observed subprocess effects", "passed": report["passed"],
            "scripted_pairs": len(report["pairs"]), "boundary_checks": len(report["checks"]),
            "failed_pairs": [pair["protected"]["fixture_id"] for pair in report["pairs"] if not pair["passed"]],
            "failed_checks": [check["name"] for check in report["checks"] if not check["passed"]],
            "timing": report["timing"], "boundary": "Direct RuntimeService + mock subprocess endpoints; no LLM/provider/HTTP transport."}


def gate_3_python_and_cli() -> dict[str, Any]:
    errors = []
    files = list((REPO_ROOT / "src").rglob("*.py")) + list((REPO_ROOT / "benchmarks").rglob("*.py"))
    for path in files:
        try:
            ast.parse(path.read_text(), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as error:
            errors.append(f"{path.relative_to(REPO_ROOT)}: {error}")
    process = subprocess.run([sys.executable, "-m", "mirage_mcp.cli.main", "--help"], cwd=REPO_ROOT, capture_output=True, text=True, timeout=10)
    return {"gate": "Python source syntax and CLI entrypoint", "passed": not errors and process.returncode == 0 and bool(process.stdout.strip()), "parsed_modules": len(files), "errors": errors, "cli_exit_code": process.returncode}


def gate_4_built_console() -> dict[str, Any]:
    candidates = [REPO_ROOT / "ui" / "dist", REPO_ROOT / "src" / "mirage_mcp" / "web"]
    builds = []
    for directory in candidates:
        if (directory / "index.html").is_file():
            assets = list(directory.rglob("*.js"))
            builds.append({"directory": str(directory.relative_to(REPO_ROOT)), "javascript_files": len(assets), "javascript_bytes": sum(path.stat().st_size for path in assets)})
    return {"gate": "Built console artifact presence", "passed": any(build["javascript_bytes"] > 0 for build in builds), "artifacts": builds, "boundary": "Presence only; browser and clean-wheel install checks remain separate."}


def main() -> int:
    gates = []
    for check in (gate_1_evidence_integrity, gate_2_runtime_effects, gate_3_python_and_cli, gate_4_built_console):
        try:
            gates.append(check())
        except Exception as error:
            gates.append({"gate": check.__name__, "passed": False, "error": f"{type(error).__name__}: {error}"})
    print(json.dumps({"checks": gates, "passed": all(gate["passed"] for gate in gates), "scope": "Local implementation observations, not production or universal security validation."}, indent=2))
    return 0 if all(gate["passed"] for gate in gates) else 1


if __name__ == "__main__":
    raise SystemExit(main())
