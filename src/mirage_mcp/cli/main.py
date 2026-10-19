"""
MIRAGE-MCP CLI (`mirage` / `mirage-mcp`).

Commands:
  - `mirage up [--host 127.0.0.1] [--port 8765] [--db .mirage/mirage.db] [--open]`
  - `mirage scan [--config <path>] [--json-output <path>]`
  - `mirage wrap [--config <path>] [--mode strict|step-up|audit]`
  - `mirage unwrap [--config <path>]`
  - `mirage proxy --server-name <name> [--mode strict|step-up|audit] -- <cmd> [args...]`
  - `mirage bench [--suite top50|flagship] [--format table|json|markdown]`
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional
import webbrowser

from mirage_mcp.graph.classifier import load_policy_overrides
from mirage_mcp.graph.taint_dag import StaticBlastRadiusAnalyzer
from mirage_mcp.proxy.stdio_proxy import MirageStdioProxy
from mirage_mcp.visualizer import write_blast_radius_snapshot

DEFAULT_DEMO_CONFIG: Dict[str, Any] = {
    "mcpServers": {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
        },
        "postgres": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres"],
        },
        "stripe": {
            "command": "npx",
            "args": ["-y", "@stripe/mcp"],
        },
        "gmail": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-gmail"],
        },
        "slack": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-slack"],
        },
        "terminal": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-bash"],
        },
    }
}


def discover_mcp_config(explicit_path: Optional[str]) -> Optional[Path]:
    if explicit_path:
        p = Path(explicit_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"MCP configuration file not found: {explicit_path}")

    candidates = [
        Path.cwd() / ".cursor" / "mcp.json",
        Path.cwd() / "claude_desktop_config.json",
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
        Path.home() / ".codeium/windsurf/mcp_config.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def cmd_scan(args: argparse.Namespace) -> int:
    overrides = load_policy_overrides(args.policy)
    analyzer = StaticBlastRadiusAnalyzer(policy_overrides=overrides)
    cfg_path = discover_mcp_config(args.config)

    if cfg_path is not None:
        graph_data = analyzer.analyze_config_file(str(cfg_path))
        source_label = str(cfg_path)
    elif args.demo:
        graph_data = analyzer.analyze_config_dict(DEFAULT_DEMO_CONFIG, workspace_name="explicit-demo")
        source_label = "explicit demo manifest"
    else:
        print("No host configuration found. Specify --config or explicitly select --demo.", file=sys.stderr)
        return 2
    graph_data["coverage"] = "inferred_from_config_only"
    graph_data["capabilities_verified"] = False

    json_out = write_blast_radius_snapshot(graph_data, args.json_output)
    if getattr(args, "output", None):
        write_blast_radius_snapshot(graph_data, args.output)

    print("=" * 74)
    print("MIRAGE-MCP // STATIC BLAST-RADIUS & LETHAL TRIFECTA SCANNER")
    print("=" * 74)
    print(f"  Target Config        : {source_label}")
    print(f"  Workspace            : {graph_data['workspace_name']}")
    print(f"  Scan ID              : {graph_data['scan_id']}")
    print(f"  Nodes Analyzed       : {len(graph_data['nodes'])}")
    print(f"  Edges Mapped         : {len(graph_data['edges'])}")
    print(f"  Lethal Trifectas     : {graph_data['lethal_trifecta_count']}")
    print("  Coverage             : Inferred inventory only; tool capabilities are not verified")
    print(f"  JSON Graph Artifact  : {json_out}")
    print("  Elytra Control UI  : Run `mirage up` -> http://127.0.0.1:8765")
    print("=" * 74)

    return 0


def cmd_up(args: argparse.Namespace) -> int:
    from mirage_mcp.server.control_plane import ControlPlaneServer
    from mirage_mcp.cloud.client import load_credentials
    credentials = load_credentials(args.cloud_credential_file)
    link = None
    if not credentials:
        try:
            link = load_credentials(args.link_credential_file)
        except Exception as exc:
            print(f"Account link not started: {exc}", file=sys.stderr)
    server = ControlPlaneServer(host=args.host, port=args.port, db_path=args.db,
                                token_file=args.token_file, development_origin=args.dev_origin,
                                cloud_credentials=credentials, link_credentials=link,
                                link_credential_file=args.link_credential_file)
    server.start_background()
    print(f"Elytra website: {server.base_url}")
    print(f"Local console: {server.base_url}/app/ (pair with elytra connect --open)")
    print("Coverage: explicitly identified runs through the Python integration or scoped tools-only stdio bridge.")
    if server.link_connector:
        print(f"Linked: held actions also appear at {server.link_connector.origin}/app/ for you to approve.")
    if args.open:
        webbrowser.open(server.pairing_url())
    try:
        server.wait_forever()
    except KeyboardInterrupt:
        print("Shutting down the local runtime...")
    finally:
        server.stop()
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    from mirage_mcp.sdk import RuntimeClient
    client = RuntimeClient(base_url=args.gateway, token_file=args.token_file)
    response = client._request("POST", "/api/v1/pair", {})
    url = response["pairing_url"]
    if args.code:
        print(url.split("#pair/", 1)[1])
    else:
        webbrowser.open(url)
        print("Opened a one-time pairing link in your browser. It expires in five minutes.")
    return 0


def _write_config(path: Path, payload: dict) -> None:
    import os
    import tempfile
    fd, name = tempfile.mkstemp(prefix=".elytra-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


def cmd_wrap(args: argparse.Namespace) -> int:
    import os
    from mirage_mcp.sdk import RuntimeClient
    if not args.run_id or not os.environ.get("ELYTRA_RUN_TOKEN"):
        print("An explicit --run-id and ELYTRA_RUN_TOKEN are required. Create a run first; unrelated desktop conversations must not share it.", file=sys.stderr)
        return 2
    if args.mode == "audit":
        print("Audit mode is not an execution bypass. Configure explicit policies in the local console.", file=sys.stderr)
        return 2
    token = os.environ["ELYTRA_RUN_TOKEN"]
    scoped = RuntimeClient(base_url=args.gateway, token=token).for_run(args.run_id, token)
    # Validate the run without mutating it before editing a host file.
    scoped._request("POST", "/api/v1/runtime/validate", {"run_id": args.run_id})
    cfg_path = discover_mcp_config(args.config)
    if cfg_path is None:
        print("Specify a real host configuration with --config.", file=sys.stderr)
        return 2
    if cfg_path.is_symlink():
        raise ValueError("Refusing to replace a symlinked host configuration")
    data = json.loads(cfg_path.read_text())
    servers = data.get("mcpServers", data.get("servers"))
    if not isinstance(servers, dict): raise ValueError("Host configuration must contain a server map")
    backup = cfg_path.with_suffix(cfg_path.suffix + ".elytra.bak")
    if backup.exists():
        raise ValueError(f"Backup already exists at {backup}; inspect it before another wrap")
    count = 0
    for name, entry in servers.items():
        if not isinstance(entry, dict) or not entry.get("command"): continue
        if "_elytra_original" in entry: continue
        command, launch_args = entry["command"], entry.get("args", [])
        if not isinstance(command, str) or not isinstance(launch_args, list): raise ValueError("Invalid stdio launch configuration")
        original = {key: entry[key] for key in ("command", "args", "env") if key in entry}
        entry["_elytra_original"] = original
        entry["command"] = "elytra"
        entry["args"] = ["proxy", "--server-name", name, "--run-id", args.run_id,
                         "--gateway", args.gateway, "--", command, *launch_args]
        entry["env"] = {**entry.get("env", {}), "ELYTRA_RUN_TOKEN": token}
        count += 1
    if not count:
        print("No unwrapped stdio entries found; no files changed.")
        return 0
    with backup.open("x") as stream:
        os.chmod(backup, 0o600)
        stream.write(cfg_path.read_text())
    _write_config(cfg_path, data)
    print(f"Wrapped {count} stdio entries for one explicit run. Backup: {backup}")
    print("Restart the host. Run expiry stops execution; create a new run for each task.")
    return 0


def cmd_unwrap(args: argparse.Namespace) -> int:
    cfg_path = discover_mcp_config(args.config)
    if cfg_path is None: raise ValueError("Specify --config")
    if cfg_path.is_symlink(): raise ValueError("Refusing to replace a symlinked configuration")
    data = json.loads(cfg_path.read_text())
    servers = data.get("mcpServers", data.get("servers", {}))
    count = 0
    for entry in servers.values():
        if not isinstance(entry, dict): continue
        original = entry.pop("_elytra_original", None) or entry.pop("_mirage_original", None)
        if original:
            for key in ("command", "args", "env"):
                if key in original: entry[key] = original[key]
                else: entry.pop(key, None)
            count += 1
    if count: _write_config(cfg_path, data)
    print(f"Restored {count} original launch entries; other settings preserved.")
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    import os
    from mirage_mcp.sdk import RuntimeClient
    from mirage_mcp.proxy.runtime_stdio import run_runtime_proxy
    command = list(args.target)
    if command and command[0] == "--": command.pop(0)
    host_id, host_token = args.host_id or os.environ.get("ELYTRA_HOST_ID"), os.environ.get("ELYTRA_HOST_TOKEN")
    if host_id or host_token:
        # Host mode: an agent host (for example Claude Code) launched this server.
        from mirage_mcp.proxy.host_session import HostSessionClient, host_session_key
        if not command or not host_id or not host_token:
            print("Host mode requires --host-id, ELYTRA_HOST_TOKEN, and an MCP command after --. Run elytra setup.", file=sys.stderr)
            return 2
        client = HostSessionClient(host_id, host_token, host_session_key(), args.gateway)
        window = float(client.session.get("approval_window", 120))
        return asyncio.run(run_runtime_proxy(client, args.server_name, command, approval_timeout=window + 5))
    token = os.environ.get("ELYTRA_RUN_TOKEN")
    if not command or not args.run_id or not token:
        print("Protected proxy requires --run-id, ELYTRA_RUN_TOKEN, and an MCP command after --.", file=sys.stderr)
        return 2
    if args.mode == "audit":
        print("Use explicit runtime policies; proxy audit bypass is unsupported.", file=sys.stderr)
        return 2
    scoped = RuntimeClient(base_url=args.gateway, token=token).for_run(args.run_id, token)
    return asyncio.run(run_runtime_proxy(scoped, args.server_name, command))


def cmd_bench(args: argparse.Namespace) -> int:
    if args.suite == "observed":
        try:
            from mirage_mcp.evaluation.measured_runner import run_measured_benchmark
        except ImportError:
            from benchmarks.measured_runner import run_measured_benchmark
        report = run_measured_benchmark(write_artifacts=False)
    else:
        try:
            from mirage_mcp.evaluation.runner import run_full_benchmark
        except ImportError:
            from benchmarks.runner import run_full_benchmark
        report = run_full_benchmark(write_artifacts=False)
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    if args.format == "markdown" and args.suite != "observed":
        try:
            from mirage_mcp.evaluation.runner import format_markdown_report
        except ImportError:
            from benchmarks.runner import format_markdown_report
        print(format_markdown_report(report))
    else:
        print(json.dumps(report if args.format == "json" else report.get("summary", report), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="elytra",
        description="Elytra: local, explicit-run MCP execution controls",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_up = sub.add_parser("up", help="Start Control Plane API + React console server")
    p_up.add_argument("--host", default="127.0.0.1", help="Bind host address")
    p_up.add_argument("--port", type=int, default=8765, help="Bind port")
    p_up.add_argument("--db", default=None, help="Path to SQLite WAL database")
    p_up.add_argument("--open", action="store_true", help="Open Control Plane UI in browser")
    p_up.add_argument("--token-file", default=str(Path.home() / ".elytra/control-plane.token"))
    p_up.add_argument("--dev-origin", default=None, help="Explicit local frontend development origin")
    p_up.add_argument('--cloud-credential-file', default=str(Path.home() / '.elytra/cloud-device.json'))
    p_up.add_argument('--link-credential-file', default=str(Path.home() / '.elytra/cloud-link.json'))
    p_up.set_defaults(func=cmd_up)
    p_connect = sub.add_parser("connect", help="Pair a local browser with a one-time link")
    p_connect.add_argument("--gateway", default="http://127.0.0.1:8765")
    p_connect.add_argument("--token-file", default=None)
    p_connect.add_argument("--open", action="store_true", help="Open the paired console (default)")
    p_connect.add_argument("--code", action="store_true", help="Print a one-time code for manual entry")
    p_connect.set_defaults(func=cmd_connect)

    p_scan = sub.add_parser("scan", help="Scan MCP config and generate blast_radius_graph.json")
    p_scan.add_argument("--config", help="Path to claude_desktop_config.json or .cursor/mcp.json")
    p_scan.add_argument("--policy", help="Optional path to mirage.policy.yaml")
    p_scan.add_argument("--output", default=None, help="Optional secondary JSON snapshot path")
    p_scan.add_argument(
        "--json-output", default="blast_radius_graph.json", help="Output JSON graph file path"
    )
    p_scan.add_argument("--open", action="store_true", help="Open Control Plane in browser")
    p_scan.add_argument("--demo", action="store_true", help="Explicitly use an illustrative manifest")
    p_scan.set_defaults(func=cmd_scan)

    p_wrap = sub.add_parser("wrap", help="Wrap MCP server commands with Mirage runtime proxy")
    p_wrap.add_argument("--config", help="Path to MCP client configuration JSON")
    p_wrap.add_argument(
        "--mode",
        choices=["strict", "step-up", "audit"],
        default="strict",
        help="Runtime enforcement mode",
    )
    p_wrap.add_argument("--run-id", default=None, help="One explicit run shared by these tools")
    p_wrap.add_argument("--gateway", default="http://127.0.0.1:8765")
    p_wrap.set_defaults(func=cmd_wrap)

    p_unwrap = sub.add_parser("unwrap", help="Restore original unwrapped MCP client configuration")
    p_unwrap.add_argument("--config", help="Path to MCP client configuration JSON")
    p_unwrap.set_defaults(func=cmd_unwrap)

    p_proxy = sub.add_parser("proxy", help="Run stdio JSON-RPC 2.0 taint interceptor proxy")
    p_proxy.add_argument("--server-name", default="mcp", help="Logical MCP server identifier")
    p_proxy.add_argument(
        "--mode", choices=["strict", "step-up", "audit"], default="strict", help="Enforcement mode"
    )
    p_proxy.add_argument("--user-prompt", default="", help="Optional initial user intent anchor")
    p_proxy.add_argument("--telemetry-log", help="Optional path to JSONL telemetry output")
    p_proxy.add_argument("target", nargs=argparse.REMAINDER, help="Target command after `--`")
    p_proxy.add_argument("--run-id", default=None)
    p_proxy.add_argument("--host-id", default=None, help="Host-session mode: the agent host credential id (token in ELYTRA_HOST_TOKEN)")
    p_proxy.add_argument("--gateway", default="http://127.0.0.1:8765")
    p_proxy.set_defaults(func=cmd_proxy)

    p_bench = sub.add_parser("bench", help="Run second-hop exploit red-team benchmark suite")
    p_bench.add_argument("--suite", choices=["observed", "top50", "flagship"], default="observed")
    p_bench.add_argument("--format", choices=["table", "json", "markdown"], default="table")
    p_bench.add_argument("--output", help="Optional report JSON output path")
    p_bench.set_defaults(func=cmd_bench)

    from mirage_mcp.cloud import cli as cloud_cli
    from mirage_mcp.cloud.client import DEFAULT_CREDENTIAL_FILE
    p_login = sub.add_parser('login', help='Enroll this runtime in a hosted workspace')
    p_login.add_argument('--cloud-url', required=True, help='Your Elytra HTTPS deployment origin')
    p_login.add_argument('--device-name')
    p_login.add_argument('--code', action='store_true', help='Print a one-time code for manual enrollment instead of opening a browser')
    p_login.add_argument('--credential-file', default=str(DEFAULT_CREDENTIAL_FILE))
    p_login.set_defaults(func=cloud_cli.login)
    from mirage_mcp.cloud.client import DEFAULT_CLOUD_URL, DEFAULT_LINK_FILE
    p_link = sub.add_parser('link', help='Approve held actions from your phone: link this machine to a free account')
    p_link.add_argument('--cloud-url', default=DEFAULT_CLOUD_URL, help='Elytra HTTPS origin (default: %(default)s)')
    p_link.add_argument('--device-name')
    p_link.add_argument('--code', action='store_true', help='Print a one-time code instead of opening a browser')
    p_link.add_argument('--credential-file', default=str(DEFAULT_LINK_FILE))
    p_link.add_argument('--managed-credential-file', default=str(DEFAULT_CREDENTIAL_FILE))
    p_link.add_argument('--gateway', default='http://127.0.0.1:8765')
    p_link.add_argument('--token-file', default=str(Path.home()/'.elytra/control-plane.token'))
    p_link.set_defaults(func=cloud_cli.link)
    p_unlink = sub.add_parser('unlink', help='Stop approving held actions from your account')
    p_unlink.add_argument('--credential-file', default=str(DEFAULT_LINK_FILE))
    p_unlink.add_argument('--gateway', default='http://127.0.0.1:8765')
    p_unlink.add_argument('--token-file', default=str(Path.home()/'.elytra/control-plane.token'))
    p_unlink.set_defaults(func=cloud_cli.unlink)
    p_logout = sub.add_parser('logout', help='Remove this machine cloud enrollment')
    p_logout.add_argument('--credential-file', default=str(DEFAULT_CREDENTIAL_FILE))
    p_logout.add_argument('--gateway', default='http://127.0.0.1:8765')
    p_logout.add_argument('--token-file', default=str(Path.home()/'.elytra/control-plane.token'))
    p_logout.set_defaults(func=cloud_cli.logout)
    p_cloud = sub.add_parser('cloud', help='Inspect hosted enrollment')
    cloud_sub = p_cloud.add_subparsers(dest='cloud_command', required=True)
    p_status = cloud_sub.add_parser('status')
    p_status.add_argument('--credential-file', default=str(DEFAULT_CREDENTIAL_FILE))
    p_status.set_defaults(func=cloud_cli.status)
    from mirage_mcp.cli import setup as setup_cli
    setup_cli.register(sub)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Elytra: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
