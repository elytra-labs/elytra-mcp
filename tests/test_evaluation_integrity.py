"""Protect evidence semantics and observe actual mock destination effects."""
from __future__ import annotations
import json
from benchmarks.runner import format_markdown_report, percentile, run_full_benchmark
from benchmarks.scenarios_50 import CLEAN_WORKFLOWS, EXPLOIT_SCENARIOS_50
from benchmarks.measured_runner import run_isolation_check, run_measured_benchmark, run_pair


def test_missing_baseline_stays_unavailable_and_report_does_not_invent_compromise():
    report = run_full_benchmark(write_artifacts=False)
    assert all(sc["unprotected_mcp_compromised"] is None for sc in EXPLOIT_SCENARIOS_50)
    assert report["summary"]["unprotected_exploits_succeeded"] is None
    assert report["summary"]["unprotected_exploit_success_rate_pct"] is None
    assert report["summary"]["agent_calls"] == 0
    markdown = format_markdown_report(report)
    assert "Not measured" in markdown
    assert "0/50 (0.0%)" not in markdown
    # Changing observations must change the generated outcome, not leave a hardcoded success.
    report["summary"]["mirage_exploits_blocked"] = 7
    assert "7/50" in format_markdown_report(report)


def test_percentile_handles_small_sets():
    assert percentile([], .99) == 0
    assert percentile([3], .99) == 3
    assert percentile([1, 2, 3, 4], .5) == 2


def test_subprocess_effects_match_exact_authority_and_argument_changes():
    fixture = CLEAN_WORKFLOWS[-3]
    arguments = json.loads(fixture["hop2_args_json"])
    bypass = run_pair(fixture, protected=False, grant_arguments=arguments)
    allowed = run_pair(fixture, protected=True, grant_arguments=arguments)
    assert bypass["mutation_delta"] == allowed["mutation_delta"] == 1
    assert bypass["destination_received_arguments"] == allowed["destination_received_arguments"] == [arguments]
    altered = {**fixture, "hop2_args_json": json.dumps({**arguments, "extra": "not granted"})}
    held = run_pair(altered, protected=True, grant_arguments=arguments)
    assert held["decision"]["decision"] == "STEP_UP"
    assert held["mutation_delta"] == 0
    assert held["destination_received_arguments"] == []


def test_observed_unknown_denial_approval_replay_and_shared_run_isolation():
    fixture = CLEAN_WORKFLOWS[-3]
    unknown = run_pair(fixture, protected=True, classify_sink=False)
    denied = run_pair(fixture, protected=True, approval="DENIED")
    approved = run_pair(fixture, protected=True, approval="APPROVED", replay=True)
    tampered = run_pair(fixture, protected=True, approval="APPROVED", tamper_after_approval=True)
    cancelled = run_pair(fixture, protected=True, approval="CANCELLED")
    assert unknown["decision"]["decision"] == "BLOCK" and unknown["mutation_delta"] == 0
    assert denied["decision"]["decision"] == "BLOCK" and denied["mutation_delta"] == 0
    assert approved["mutation_delta"] == 1 and approved["replay_rejected"] is True
    assert tampered["mutation_delta"] == 0 and tampered["tampered_claim_rejected"] is True
    assert cancelled["mutation_delta"] == 0 and cancelled["decision"]["status"] == "CANCELLED"
    assert run_isolation_check()["passed"] is True


def test_compact_harness_preserves_recorded_attempts_and_measurement_scope():
    report = run_measured_benchmark(write_artifacts=False, exploit_limit=1)
    assert report["passed"] is True
    assert report["agent_calls"] == 0 and report["unprotected_agent_compromise_rate"] is None
    assert report["timing"]["arms"]["protected"]["samples"] == 4
    attack = report["pairs"][0]
    assert attack["bypass"]["attempt"] == attack["protected"]["attempt"]
    assert attack["bypass"]["permission"] == attack["protected"]["permission"]
    assert attack["bypass"]["mutation_delta"] == 1
    assert attack["protected"]["mutation_delta"] == 0
