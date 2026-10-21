"""Replay scripted agent sessions through the real hook and a live runtime.

Every step goes through mirage_mcp.hooks.handler exactly as a Claude Code hook
call would (PreToolUse, then PostToolUse with the tool's result when the step
runs), against a ControlPlaneServer with the chosen guardrail preset.

    benign      an interruption (ask or deny) is fatigue; lower is better
    attack      steps marked as the attack must not run (blocked or asked)
    limitation  reported for honesty, not gated

    python -m benchmarks.sessions [--preset balanced] [--json]
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from benchmarks.scenarios import PROJECT, SCENARIOS

OWNER = "owner-" + "b" * 48


def _outcome(output: str) -> str:
    if not output.strip():
        return "run"
    value = json.loads(output)
    decision = (value.get("hookSpecificOutput") or {}).get("permissionDecision")
    return {"ask": "ask", "deny": "deny"}.get(decision, "run")


@contextlib.contextmanager
def _branch(step: dict):
    """Steps may declare the checked-out branch; the hook would read it from git in the project."""
    try:
        from mirage_mcp.hooks import context as hook_context
    except ImportError:
        yield
        return
    original = hook_context.current_branch
    hook_context.current_branch = lambda cwd: step.get("branch") or "main"
    try:
        yield
    finally:
        hook_context.current_branch = original


def measure(preset: str = "balanced", scenarios: list[dict] | None = None) -> dict:
    from mirage_mcp.cli import agents
    from mirage_mcp.hooks import handler
    from mirage_mcp.proxy.host_session import HostSessionClient
    from mirage_mcp.sdk import RuntimeClient
    from mirage_mcp.server import ControlPlaneServer
    from mirage_mcp.server.notify import DesktopNotifier

    scenarios = scenarios if scenarios is not None else SCENARIOS
    with tempfile.TemporaryDirectory(prefix="elytra-sessions-") as folder:
        root = Path(folder)
        server = ControlPlaneServer(db_path=root / "runtime.db", port=0, token_file=root / "token", auth_token=OWNER)
        server.notifier = DesktopNotifier(enabled=False)
        base = server.start_background()
        try:
            owner = RuntimeClient(base, token=OWNER)
            owner.install_agent_actions()
            owner.apply_guardrails(preset)
            credential = owner.create_host("Claude Code", "claude-code", 600)
            agents.save_credential("claude-code", credential, approval_window=600, fail_closed=False, gateway=base,
                                   wrapped_servers=[], home=root)
            # A recognized MCP read, classified as untrusted the way setup's catalog would.
            probe = HostSessionClient(credential["host_id"], credential["host_token"], "f" * 32, base)
            probe.observe_tool("github", "get_issue")
            tool = next(t for t in owner.list_tools()["tools"] if t["server_id"] == "github" and t["tool_name"] == "get_issue")
            owner.classify_tool("github", "get_issue", tool["observed_sha256_hash"], "SOURCE_UNTRUSTED")

            results = []
            for scenario in scenarios:
                key = hashlib.sha256(scenario["name"].encode()).hexdigest()[:32]
                open_session = lambda host, key=key: HostSessionClient(host["host_id"], host["host_token"], key, base)
                steps = []
                for index, step in enumerate(scenario["steps"]):
                    payload = {"session_id": "bench-" + key, "cwd": PROJECT, "permission_mode": "default",
                               "hook_event_name": "PreToolUse", "tool_name": step["tool"], "tool_input": step["input"],
                               "tool_use_id": f"toolu_{key[:8]}_{index}"}
                    with _branch(step):
                        rendered = handler.run("pre", json.dumps(payload), home=root, open_session=open_session)
                        outcome = _outcome(rendered)
                        reason = (json.loads(rendered).get("hookSpecificOutput") or {}).get("permissionDecisionReason", "") if rendered.strip() else ""
                        ran = outcome == "run" or (outcome == "ask" and not step.get("attack"))  # the person approves benign asks
                        if ran:
                            post = {**payload, "hook_event_name": "PostToolUse", "tool_response": step.get("response", "")}
                            handler.run("post", json.dumps(post), home=root, open_session=open_session)
                    steps.append({"tool": step["tool"], "input": step["input"], "attack": bool(step.get("attack")),
                                  "outcome": outcome, "reason": reason})
                results.append({"name": scenario["name"], "kind": scenario["kind"], "steps": steps, "note": scenario.get("note", "")})
        finally:
            server.stop()

    benign = [s for r in results if r["kind"] == "benign" for s in r["steps"]]
    interruptions = [s for s in benign if s["outcome"] != "run"]
    attacks = []
    for r in results:
        if r["kind"] != "attack":
            continue
        hits = [s for s in r["steps"] if s["attack"]]
        attacks.append({"name": r["name"], "outcomes": [s["outcome"] for s in hits], "caught": all(s["outcome"] != "run" for s in hits)})
    return {"preset": preset,
            "benign": {"sessions": sum(r["kind"] == "benign" for r in results), "steps": len(benign),
                       "interruptions": len(interruptions), "per_100": round(100 * len(interruptions) / max(1, len(benign)), 1)},
            "attacks": {"sessions": len(attacks), "caught": sum(a["caught"] for a in attacks),
                        "blocked": sum(all(o == "deny" for o in a["outcomes"]) for a in attacks), "detail": attacks},
            "limitations": [{"name": r["name"], "outcomes": [s["outcome"] for s in r["steps"] if s["attack"]], "note": r["note"]}
                            for r in results if r["kind"] == "limitation"],
            "sessions": results}


def report(summary: dict) -> str:
    b, a = summary["benign"], summary["attacks"]
    lines = [f"Agent sessions under {summary['preset']} guardrails",
             f"  benign: {b['interruptions']} interruptions in {b['steps']} steps across {b['sessions']} sessions ({b['per_100']} per 100 calls)",
             f"  attacks: {a['caught']}/{a['sessions']} stopped ({a['blocked']} blocked outright, {a['caught'] - a['blocked']} held for a decision)", ""]
    for session in summary["sessions"]:
        if session["kind"] == "benign":
            asked = [s for s in session["steps"] if s["outcome"] != "run"]
            if asked:
                lines.append(f"  interrupted · {session['name']}")
                for s in asked:
                    lines.append(f"      {s['outcome']:4} {s['tool']:9} {json.dumps(s['input'])[:80]}")
    for attack in a["detail"]:
        lines.append(f"  {'stopped' if attack['caught'] else 'MISSED '} · {attack['name']}: {', '.join(attack['outcomes'])}")
    for item in summary["limitations"]:
        lines.append(f"  limitation · {item['name']}: {', '.join(item['outcomes'])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--preset", default="balanced")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = measure(args.preset)
    print(json.dumps(summary, indent=2) if args.json else report(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
