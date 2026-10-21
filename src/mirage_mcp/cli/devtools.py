"""Developer commands: explain a decision, check that protection is live, and manage what counts as trusted."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from mirage_mcp.cli.setup import _client, _say, healthy

OUTCOME = {"ALLOW": "runs", "STEP_UP": "asks you", "BLOCK": "blocked"}
STATES = (("clean", "In a clean session"), ("inspected", "After untrusted content Elytra inspected"),
          ("uninspected", "After untrusted content Elytra could not inspect"), ("injection", "After suspected prompt injection"),
          ("secrets", "After reading secrets"))
SIMULATED_SOURCE = "example.com/issue/1"  # The read each simulated session makes; reasons show it as "an untrusted page".


def _gateway_preset_and_rules(gateway: str) -> tuple[str, list[dict]]:
    """The running runtime's preset and the person's own rules, so `explain` matches what will really happen."""
    try:
        client = _client(gateway)
        preset = client.guardrails().get("preset") or "balanced"
        rules = [p for p in client._request("GET", "/api/v1/policies")["policies"] if not p["rule_id"].startswith("guardrail.")]
        return preset, rules
    except (ValueError, RuntimeError, OSError, KeyError):
        return "balanced", []


def _simulate(tool: str, tool_input: dict, cwd: str, preset: str, rules: list[dict]) -> tuple[object, dict]:
    from mirage_mcp.hooks.classify import ACTIONS, classify
    from mirage_mcp.runtime import RuntimeService
    action = classify(tool, tool_input, {"cwd": cwd})
    if action.kind != "builtin":
        return action, {}
    with tempfile.TemporaryDirectory(prefix="elytra-explain-") as folder:
        service = RuntimeService(Path(folder) / "explain.db")
        try:
            service.install_builtin_actions()
            service.apply_guardrail_preset(preset)
            for rule in rules:
                service.save_policy({k: v for k, v in rule.items() if k not in {"hit_count", "created_at", "updated_at"}})
            host = service.create_host_credential("Explain", "explain")
            results = {}
            for index, (state, _) in enumerate(STATES):
                run = service.open_host_session(host["host_id"], host["host_token"], f"{index:x}" * 32)
                auth = (run["run_id"], run["run_token"])
                if state in {"inspected", "uninspected", "injection"}:
                    source = service.evaluate(*auth, "agent", "web_read", {"target": "https://" + SIMULATED_SOURCE}, "src", notify=False, claim=True)
                    if state == "inspected":
                        service.report_source_scan(*auth, "src", [])
                    elif state == "injection":
                        service.report_source_scan(*auth, "src", [{"signal": "explain", "evidence": "example"}])
                if state == "secrets":
                    service.evaluate(*auth, "agent", "read_secrets", {"path": ".env"}, "secret", notify=False, claim=True)
                decision = service.evaluate(*auth, "agent", action.tool, action.arguments, "call_" + uuid.uuid4().hex, notify=False)
                results[state] = decision
            return action, results
        finally:
            service.close()


def cmd_explain(args: argparse.Namespace) -> int:
    from mirage_mcp.hooks.classify import ACTIONS
    if args.path:
        tool, tool_input = ("Read" if args.read else "Edit"), {"file_path": args.path, "old_string": "", "new_string": ""}
        label = ("read " if args.read else "edit ") + args.path
    elif args.url:
        tool, tool_input, label = "WebFetch", {"url": args.url, "prompt": ""}, "fetch " + args.url
    else:
        command = " ".join(args.command) if len(args.command) > 1 else (args.command[0] if args.command else "")
        if not command:
            _say("Give a command, for example: elytra explain \"git push origin main\"")
            return 2
        tool, tool_input, label = "Bash", {"command": command}, command
    preset, rules = _gateway_preset_and_rules(args.gateway) if not args.preset else (args.preset, [])
    action, results = _simulate(tool, tool_input, os.path.abspath(args.cwd), preset, rules)
    _say(f"`{label}`")
    if action.kind == "protected":
        _say(f"  Always blocked: {action.reason}.")
        return 0
    if action.kind == "ignore":
        _say("  Not checked: this tool does not act on anything.")
        return 0
    if action.kind == "mcp":
        _say(f"  MCP tool {action.server}.{action.tool}: decided by its classification in the console (Tool integrity).")
        return 0
    description = ACTIONS[action.tool][1]
    _say(f"  Elytra sees: {action.tool.replace('_', ' ')} ({description[0].lower() + description[1:]})")
    _say(f"  Guardrails: {preset.title()}{f' plus {len(rules)} rule(s) of yours' if rules else ''}")
    width = max(len(text) for _, text in STATES)
    for state, text in STATES:
        decision = results[state]
        reason = decision.get("reason", "").replace(SIMULATED_SOURCE, "an untrusted page")
        detail = "" if decision["decision"] == "ALLOW" else f"  {reason.rstrip('.')}."
        _say(f"  {text:<{width}}  {OUTCOME.get(decision['decision'], decision['decision']):9}{detail}")
    return 0


# Doctor -------------------------------------------------------------------------------

def _hook_roundtrip(home: Path) -> float | None:
    """Time one real hook call the way an agent makes it."""
    payload = {"session_id": "elytra-doctor-" + uuid.uuid4().hex[:8], "cwd": str(Path.cwd()), "hook_event_name": "PreToolUse",
               "tool_name": "Read", "tool_input": {"file_path": str(Path.cwd() / "README.md")}, "tool_use_id": "toolu_doctor"}
    started = time.perf_counter()
    try:
        result = subprocess.run([sys.executable, "-m", "mirage_mcp.hooks", "pre"], input=json.dumps(payload), capture_output=True,
                                text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return (time.perf_counter() - started) * 1000 if result.returncode == 0 and "error" not in result.stderr.lower() else None


def cmd_doctor(args: argparse.Namespace) -> int:
    from mirage_mcp import __version__
    from mirage_mcp.cli import agents as agent_hooks
    from mirage_mcp.cli import hosts as host_configs
    from mirage_mcp.cli.service import Service
    from mirage_mcp.cloud.client import DEFAULT_LINK_FILE
    problems = 0

    def ok(text):
        _say(f"  ✓ {text}")

    def fix(text, how):
        nonlocal problems
        problems += 1
        _say(f"  ! {text}\n      → {how}")

    _say(f"Elytra {__version__}")
    service = Service()
    running = healthy(args.gateway)
    if running:
        ok("Runtime is running" + (" as a background service" if service.installed() else ""))
    else:
        fix("Runtime is not running, so agents' actions are not being checked", "elytra service start" if service.installed() else "elytra setup")
    hosts: dict[str, dict] = {}
    if running:
        try:
            client = _client(args.gateway)
            config = client._request("GET", "/api/v1/config")
            if config.get("version") and config["version"] != __version__:
                fix(f"The running runtime is version {config['version']}, but {__version__} is installed", "elytra service restart")
            for host in client.hosts()["hosts"]:
                if not host.get("revoked_at"):
                    hosts[host.get("kind", "")] = host
            preset = client.guardrails().get("preset")
            ok(f"Guardrails: {preset.title()}") if preset else fix("No guardrails preset is set", "elytra setup")
        except (ValueError, RuntimeError, OSError) as exc:
            fix(f"Could not read the runtime's state ({exc})", "elytra connect --open, or elytra service restart")
    installer = agent_hooks.HookInstaller()
    advice = {"claude-code": "Restart Claude Code, then run any command in it",
              "codex": "Open Codex and approve Elytra's hooks when it asks you to trust them",
              "grok": "Restart Grok, then run /hooks to confirm Elytra's hooks loaded",
              "antigravity": "Restart Antigravity"}
    for agent in agent_hooks.installed_agents():
        if not installer.installed(agent.kind):
            _say(f"  · {agent.label}: not protected (elytra setup --hosts {agent.kind} to add it)")
            continue
        seen = hosts.get(agent.kind, {}).get("last_seen_at")
        if seen:
            ok(f"{agent.label}: hooks installed and active (last check {seen.replace('T', ' ')[:16]} UTC)")
        elif running:
            fix(f"{agent.label}: hooks are installed, but no checks have reached Elytra yet", advice.get(agent.kind, f"Restart {agent.label}"))
        else:
            ok(f"{agent.label}: hooks installed")
    for config in host_configs.discover():
        pending = [s.name for s in config.servers if s.stdio and not s.wrapped]
        if pending:
            fix(f"{config.spec.label}: {len(pending)} MCP server(s) are not protected ({', '.join(pending[:3])})", "elytra setup")
        elif config.servers:
            ok(f"{config.spec.label}: all {sum(1 for s in config.servers if s.stdio)} local MCP server(s) protected")
    if running:
        latency = _hook_roundtrip(Path.home())
        if latency is None:
            fix("A test hook call did not get an answer", "Run elytra setup again, then elytra doctor")
        else:
            ok(f"A hook call answers in {latency:.0f} ms")
    _say(f"  {'✓' if DEFAULT_LINK_FILE.exists() else '·'} Account link: {'on' if DEFAULT_LINK_FILE.exists() else 'off (elytra link to approve from your phone)'}")
    _say("\nEverything checks out." if not problems else f"\n{problems} thing(s) to fix.")
    return 0 if not problems else 1


# Trust --------------------------------------------------------------------------------

def cmd_trust_domain(args: argparse.Namespace) -> int:
    from mirage_mcp.security.trusted_sources import DEFAULT_TRUSTED, USER_FILE, _normalize, user_entries
    entries = user_entries()
    if args.list or not args.domain:
        _say("Built in (official documentation and registries):")
        _say("  " + ", ".join(DEFAULT_TRUSTED[:12]) + f", and {len(DEFAULT_TRUSTED) - 12} more")
        _say("Yours:" if entries else "Yours: none yet. Add one with elytra trust-domain docs.example.com")
        for entry in entries:
            _say(f"  {entry}")
        return 0
    domain = _normalize(args.domain)
    if not domain or " " in domain or "." not in domain.split("/")[0]:
        _say("Give a domain such as docs.example.com, or a domain and path such as example.com/docs/")
        return 2
    if args.remove:
        entries = [e for e in entries if e != domain]
    elif domain not in entries:
        entries.append(domain)
    USER_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = USER_FILE.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump({"trusted": entries}, stream, indent=2)
    os.replace(temp, USER_FILE)
    _say(f"{'Removed' if args.remove else 'Trusted'} {domain}." + ("" if args.remove else " Reads from it no longer mark a session as untrusted, unless Elytra finds instructions aimed at AI agents in what it returns."))
    return 0


def cmd_trust_session(args: argparse.Namespace) -> int:
    client = _client(args.gateway)
    runs = [r for r in client.list_runs()["runs"] if r.get("coverage") == "HOST_SESSION" and r.get("status") == "ACTIVE"]
    marked = [r for r in runs if r.get("source_levels")]
    if not args.session:
        if not marked:
            _say("No agent session has read untrusted content or secrets right now.")
            return 0
        for run in sorted(marked, key=lambda r: r.get("created_at", ""), reverse=True):
            levels = run["source_levels"]
            names = ", ".join(f"{n} ({levels[n].lower()})" for n in sorted(levels, key=lambda n: n)[:4])
            _say(f"  {run['run_id']}  {run.get('host_label', 'Agent')}: {names}")
        _say("\nTrust one again after reviewing what it read: elytra trust-session <session id>")
        return 0
    result = client.trust_session(args.session)
    _say(f"Session trusted again; {len(result.get('cleared', []))} source(s) cleared. Its next changes are decided as in a clean session.")
    return 0


def register(sub) -> None:
    p = sub.add_parser("explain", help="Show what Elytra would decide for a command, a file or a URL, and why")
    p.add_argument("command", nargs="*", help='A shell command, quoted, for example "git push origin main"')
    p.add_argument("--path", help="Explain editing (or with --read, reading) this file instead")
    p.add_argument("--read", action="store_true")
    p.add_argument("--url", help="Explain fetching this URL instead")
    p.add_argument("--cwd", default=".", help="The agent's working directory (default: here)")
    p.add_argument("--preset", choices=["balanced", "cautious", "autonomous"], help="Explain under this preset instead of yours")
    p.add_argument("--gateway", default="http://127.0.0.1:8765")
    p.set_defaults(func=cmd_explain)
    p = sub.add_parser("doctor", help="Check that every agent is protected and Elytra is answering")
    p.add_argument("--gateway", default="http://127.0.0.1:8765")
    p.set_defaults(func=cmd_doctor)
    p = sub.add_parser("trust-domain", help="Treat a documentation site as trusted (or --remove it, or --list)")
    p.add_argument("domain", nargs="?")
    p.add_argument("--remove", action="store_true")
    p.add_argument("--list", action="store_true")
    p.set_defaults(func=cmd_trust_domain)
    p = sub.add_parser("trust-session", help="List agent sessions that read untrusted content, or trust one again")
    p.add_argument("session", nargs="?")
    p.add_argument("--gateway", default="http://127.0.0.1:8765")
    p.set_defaults(func=cmd_trust_session)
