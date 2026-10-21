"""`elytra setup`, `elytra uninstall`, `elytra status`, `elytra service`, `elytra open`."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

from mirage_mcp.catalog import load_catalog, match_server
from mirage_mcp.cli import agents as agent_hooks
from mirage_mcp.cli import hosts as host_configs
from mirage_mcp.cli.service import Service, healthy, wait_healthy
from mirage_mcp.runtime.guardrails import DEFAULT_PRESET, PRESETS

GATEWAY = "http://127.0.0.1:8765"
RUNNING_PROCESS = {"claude-code": "claude", "cursor": "Cursor", "claude-desktop": "Claude", "windsurf": "Windsurf", "vscode": "Code", "antigravity": "agy"}


def _say(text: str = "") -> None:
    print(text, flush=True)


def _ask(question: str, default: bool, assume_yes: bool) -> bool:
    if assume_yes:
        return default
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{question} {suffix} ").strip().lower()
    return default if not answer else answer in {"y", "yes"}


def _choose_preset(assume_yes: bool, preset: str | None) -> str:
    if preset:
        if preset not in PRESETS:
            raise ValueError("Preset must be balanced, cautious or autonomous")
        return preset
    if assume_yes:
        return DEFAULT_PRESET
    _say("\nHow much should agents do without asking you?")
    order = ["balanced", "cautious", "autonomous"]
    for index, key in enumerate(order, 1):
        _say(f"  {index}. {PRESETS[key]['label']}{' (recommended)' if key == DEFAULT_PRESET else ''}: {PRESETS[key]['summary']}")
    answer = input("Choose 1-3 [1]: ").strip() or "1"
    if answer not in {"1", "2", "3"}:
        raise ValueError("Choose 1, 2 or 3")
    return order[int(answer) - 1]


def _running(kind: str) -> bool:
    name = RUNNING_PROCESS.get(kind)
    if not name or not shutil.which("pgrep"):
        return False
    return subprocess.run(["pgrep", "-x", name], capture_output=True).returncode == 0


def _client(gateway: str):
    from mirage_mcp.sdk import RuntimeClient
    return RuntimeClient(base_url=gateway)


def _ensure_runtime(args, service: Service) -> None:
    if healthy(args.gateway):
        _say("✓ Elytra runtime is running")
        return
    if args.no_service:
        raise RuntimeError("The runtime is not running. Start it with `elytra up` in another terminal, then rerun setup.")
    if not service.supported:
        raise RuntimeError("Start the runtime with `elytra up`, then rerun setup (background service needs macOS or Linux).")
    _say("Starting the Elytra runtime as a background service…")
    path = service.install()
    if not wait_healthy(args.gateway):
        raise RuntimeError(f"The service did not become healthy. Check {service.log}")
    _say(f"✓ Runtime running in the background ({path})")


def cmd_setup(args: argparse.Namespace) -> int:
    if not args.yes and not sys.stdin.isatty():
        raise RuntimeError("Run setup in a terminal, or pass --yes for defaults")
    _say("Elytra setup: route your agent's tools through local guardrails.\n")
    _ensure_runtime(args, Service())
    client = _client(args.gateway)

    found = host_configs.discover()
    agents = agent_hooks.installed_agents()
    if args.hosts:
        wanted = {h.strip() for h in args.hosts.split(",") if h.strip()}
        found = [config for config in found if config.spec.kind in wanted]
        agents = [agent for agent in agents if agent.kind in wanted]
    if not found and not agents:
        _say("\nNo supported agents were found (Claude Code, Codex, Grok, Antigravity, Cursor, Claude Desktop, Windsurf, VS Code).")
        return 1

    # Reuse each agent's existing credential so new servers and hooks join the same sessions.
    credentials: dict[str, dict] = {}
    for agent in agent_hooks.AGENTS:
        saved = agent_hooks.load_credential(agent.kind)
        if saved:
            credentials[agent.kind] = saved
    for config in found:
        for server in config.servers:
            host_id = server.entry.get(host_configs.HOST_MARK)
            token = (server.entry.get("env") or {}).get("ELYTRA_HOST_TOKEN") or agent_hooks.load_token(host_id or "")
            if server.wrapped and host_id and token and config.spec.kind not in credentials:
                credentials[config.spec.kind] = {"host_id": host_id, "host_token": token}
            if server.wrapped and host_id and token and "ELYTRA_HOST_TOKEN" in (server.entry.get("env") or {}):
                # Earlier versions kept the credential in agent config, where the agent can read it. Move it.
                agent_hooks.save_token({"host_id": host_id, "host_token": token})
                del server.entry["env"]["ELYTRA_HOST_TOKEN"]
                if not server.entry["env"]:
                    del server.entry["env"]
                host_configs.write(config.path, config.data)
    # A credential revoked in the console cannot open sessions: rewrap those servers with a new one.
    active = {h["host_id"] for h in client.hosts()["hosts"] if not h.get("revoked_at")}
    for kind, credential in list(credentials.items()):
        if credential["host_id"] not in active:
            del credentials[kind]
            for config in found:
                for server in config.servers:
                    if server.entry.get(host_configs.HOST_MARK) == credential["host_id"]:
                        host_configs.unwrap_entry(server.entry)
    labels = {**{spec.kind: spec.label for spec in host_configs.HOSTS}, **{a.kind: a.label for a in agent_hooks.AGENTS}}

    def credential_for(kind: str) -> dict:
        if kind not in credentials:
            credentials[kind] = client.create_host(labels.get(kind, kind), kind, args.approval_window)
        agent_hooks.save_token(credentials[kind])
        return credentials[kind]

    recognized: dict[str, str] = {}
    wrapped_names: dict[str, set[str]] = {}
    changed_hosts: list[str] = []
    for config in found:
        stdio = [s for s in config.servers if s.stdio]
        remote = [s for s in config.servers if not s.stdio]
        pending = [s for s in stdio if not s.wrapped]
        wrapped_names.setdefault(config.spec.kind, set()).update(s.name for s in stdio if s.wrapped)
        _say(f"\n{config.spec.label}  ({config.path})")
        for server in config.servers:
            state = "protected" if server.wrapped else "remote, checked by hooks where supported" if not server.stdio else "will be protected"
            catalog_id = match_server(*server.launch) if server.stdio else None
            known = f" · recognized as {load_catalog()[catalog_id]['label']}" if catalog_id else ""
            _say(f"  - {server.name}: {state}{known}")
        if not pending:
            continue
        if _running(config.spec.kind):
            _say(f"  ! {config.spec.label} is running. Quit it before continuing so it does not overwrite these changes.")
        if not _ask(f"  Protect {len(pending)} MCP server(s) for {config.spec.label}?", True, args.yes):
            continue
        credential = credential_for(config.spec.kind)
        host_configs.backup(config.path)
        for server in pending:
            if host_configs.wrap_entry(server, credential["host_id"], credential["host_token"], args.gateway):
                wrapped_names[config.spec.kind].add(server.name)
                catalog_id = match_server(*server.launch)
                if catalog_id:
                    recognized[server.name] = catalog_id
        host_configs.write(config.path, config.data)
        changed_hosts.append(config.spec.label)
        _say(f"  ✓ Protected. Backup: {config.path.name}.elytra.bak")

    # Codex and Grok keep MCP servers in TOML; change them only through their own CLIs.
    for agent in agents:
        if agent.kind not in {"codex", "grok"}:
            continue
        servers = agent_hooks.cli_servers(agent.kind)
        pending = [s for s in servers if "mirage_mcp.cli.main" not in " ".join(map(str, s.get("args", [])))]
        wrapped_names.setdefault(agent.kind, set()).update(s["name"] for s in servers if s not in pending)
        if not pending or not _ask(f"\nProtect {len(pending)} {agent.label} MCP server(s)?", True, args.yes):
            continue
        credential = credential_for(agent.kind)
        for server in pending:
            agent_hooks.save_originals(agent.kind, [server])
            skipped = agent_hooks.wrap_cli_server(agent.kind, server, credential["host_id"], credential["host_token"], args.gateway)
            if skipped:
                if "refused" in skipped:
                    agent_hooks.restore_cli_server(agent.kind, server)
                _say(f"  - {server['name']}: not rewrapped ({skipped})")
                continue
            wrapped_names[agent.kind].add(server["name"])
            catalog_id = match_server(server["command"], list(server.get("args", [])))
            if catalog_id:
                recognized[server["name"]] = catalog_id
            _say(f"  ✓ {server['name']} protected")
            changed_hosts.append(agent.label)

    if recognized:
        names = ", ".join(f"{name} ({load_catalog()[cid]['label']})" for name, cid in sorted(recognized.items()))
        _say(f"\nKnown servers: {names}.")
        _say("Elytra can classify their listed tools (reads vs writes vs sends). Unlisted or changed tools still wait for your review.")
        if _ask("Accept the suggested classifications?", True, args.yes):
            for name, catalog_id in recognized.items():
                client.accept_catalog(name, catalog_id)
            _say("✓ Classifications accepted")

    # Built-in actions: shell commands, file edits and web access through each agent's hooks.
    if agents and not args.no_hooks:
        _say("\nAgents act mostly through built-in tools (shell, file edits, web), not MCP.")
        installer = agent_hooks.HookInstaller()
        installed_any = False
        for agent in agents:
            if not _ask(f"  Check {agent.label}'s own actions against your guardrails?", True, args.yes):
                continue
            credential = credential_for(agent.kind)
            agent_hooks.save_credential(agent.kind, credential, approval_window=args.approval_window, fail_closed=args.fail_closed,
                                        gateway=args.gateway, wrapped_servers=sorted(wrapped_names.get(agent.kind, set())))
            try:
                note = installer.install(agent.kind, args.approval_window)
            except (RuntimeError, ValueError, OSError) as exc:
                _say(f"  ! {agent.label}: {exc}")
                continue
            installed_any = True
            _say(f"  ✓ {agent.label}: hooks installed. {note}")
        if installed_any:
            client.install_agent_actions()

    preset = _choose_preset(args.yes, args.preset)
    client.apply_guardrails(preset)
    _say(f"✓ Guardrails: {PRESETS[preset]['label']}")

    _say("\nDone.")
    restart = list(dict.fromkeys(changed_hosts + [a.label for a in agents if agent_hooks.HookInstaller().installed(a.kind)]))
    if restart:
        _say(f"Restart {', '.join(restart)} to finish. Your agents work as before; Elytra asks you when an action needs a decision.")
    _say("Open the console any time with `elytra open`. Undo everything with `elytra uninstall`.")
    from mirage_mcp.cloud.client import DEFAULT_LINK_FILE
    if not DEFAULT_LINK_FILE.exists():
        _say("Away from your desk? `elytra link` lets you approve held actions from your phone with a free account. Optional.")
    if not args.yes and not args.no_open:
        _open_console(args.gateway)
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    restored, host_ids = 0, set()
    for config in host_configs.discover():
        touched = False
        for server in config.servers:
            if server.wrapped:
                host_id = host_configs.unwrap_entry(server.entry)
                if host_id:
                    host_ids.add(host_id)
                restored += 1
                touched = True
        if touched:
            host_configs.write(config.path, config.data)
            _say(f"✓ Restored {config.spec.label} ({config.path})")
    for kind in ("codex", "grok"):
        for original in agent_hooks.load_originals(kind):
            if agent_hooks.restore_cli_server(kind, original):
                restored += 1
                _say(f"✓ Restored {kind} MCP server {original['name']}")
    installer = agent_hooks.HookInstaller()
    for agent in agent_hooks.AGENTS:
        if installer.uninstall(agent.kind):
            _say(f"✓ Removed {agent.label} hooks")
    host_ids.update(agent_hooks.forget_credentials())
    if host_ids and healthy(args.gateway):
        client = _client(args.gateway)
        for host_id in sorted(host_ids):
            try:
                client.revoke_host(host_id)
            except Exception as exc:  # The configs are already restored; report and continue.
                _say(f"  ! Could not revoke {host_id}: {exc}")
    if not args.keep_service and Service().uninstall():
        _say("✓ Background service removed")
    _say(f"Restored {restored} server entr{'y' if restored == 1 else 'ies'}. Local records stay in ~/.elytra until you delete them.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    service = Service()
    running = healthy(args.gateway)
    _say(f"Runtime: {'running' if running else 'not running'}{' (background service)' if service.installed() else ''}")
    for config in host_configs.discover():
        protected = sum(1 for s in config.servers if s.wrapped)
        _say(f"{config.spec.label}: {protected}/{len(config.servers)} MCP servers protected ({config.path})")
    installer = agent_hooks.HookInstaller()
    for agent in agent_hooks.installed_agents():
        _say(f"{agent.label}: action hooks {'on' if installer.installed(agent.kind) else 'off'}")
    if running:
        client = _client(args.gateway)
        guardrails = client.guardrails()
        label = PRESETS.get(guardrails.get("preset") or "", {}).get("label", "not set")
        _say(f"Guardrails: {label}" + (f" + {guardrails['custom_rules']} custom rule(s)" if guardrails.get("custom_rules") else ""))
        for host in client.hosts()["hosts"]:
            if not host.get("revoked_at"):
                _say(f"Host {host['label']}: {host['active_sessions']} active session(s)")
    from mirage_mcp.cloud.client import DEFAULT_LINK_FILE
    _say("Account link: on (approve from your phone)" if DEFAULT_LINK_FILE.exists() else "Account link: off (`elytra link` to approve from your phone)")
    return 0


def cmd_service(args: argparse.Namespace) -> int:
    service = Service()
    if args.action == "install":
        _say(f"Installed {service.install()}")
        _say("Runtime healthy" if wait_healthy(args.gateway) else f"Runtime not healthy yet; check {service.log}")
    elif args.action == "uninstall":
        _say("Removed background service" if service.uninstall() else "No background service installed")
    elif args.action == "start":
        service.start()
    elif args.action == "stop":
        service.stop()
    elif args.action == "restart":
        service.stop()
        service.start()
        _say("Runtime healthy" if wait_healthy(args.gateway) else f"Runtime not healthy yet; check {service.log}")
    else:
        _say(f"Service: {'installed' if service.installed() else 'not installed'}; runtime {'running' if healthy(args.gateway) else 'not running'}")
    return 0


def _open_console(gateway: str) -> None:
    client = _client(gateway)
    url = client._request("POST", "/api/v1/pair", {})["pairing_url"]
    webbrowser.open(url)
    _say("Opened the Elytra console in your browser.")


def cmd_open(args: argparse.Namespace) -> int:
    if not healthy(args.gateway):
        raise RuntimeError("The runtime is not running. Run `elytra setup` or `elytra up`.")
    _open_console(args.gateway)
    return 0


def register(sub) -> None:
    p = sub.add_parser("setup", help="Start here: protect your coding agents (guided, asks before each change)")
    p.add_argument("--yes", action="store_true", help="Accept defaults without prompting")
    p.add_argument("--preset", choices=sorted(PRESETS), help="Guardrail preset (default: balanced)")
    p.add_argument("--hosts", help="Comma-separated agents to configure: claude-code,codex,grok,antigravity,cursor,claude-desktop,windsurf,vscode")
    p.add_argument("--approval-window", type=int, default=600, help="Seconds an agent waits for your decision (30-1800)")
    p.add_argument("--no-service", action="store_true", help="Do not install a background service; use a running `elytra up`")
    p.add_argument("--no-open", action="store_true", help="Do not open the console when finished")
    p.add_argument("--no-hooks", action="store_true", help="Only protect MCP servers; do not install action hooks")
    p.add_argument("--fail-closed", action="store_true", help="Block agent actions while the runtime is not running")
    p.add_argument("--gateway", default=GATEWAY)
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("uninstall", help="Undo setup: restore every agent configuration and remove the service")
    p.add_argument("--keep-service", action="store_true")
    p.add_argument("--gateway", default=GATEWAY)
    p.set_defaults(func=cmd_uninstall)

    p = sub.add_parser("status", help="Show what is protected, the guardrails, and the account link")
    p.add_argument("--gateway", default=GATEWAY)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("service", help="Manage the background runtime service")
    p.add_argument("action", choices=["install", "uninstall", "start", "stop", "restart", "status"])
    p.add_argument("--gateway", default=GATEWAY)
    p.set_defaults(func=cmd_service)

    p = sub.add_parser("open", help="Open the local console")
    p.add_argument("--gateway", default=GATEWAY)
    p.set_defaults(func=cmd_open)
