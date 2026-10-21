"""Authenticated loopback API, execution coordinator, and local product serving."""
from __future__ import annotations

from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import queue
import shlex
import socket
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from mirage_mcp import __version__
from mirage_mcp.server.access import DEFAULT_HOME, DEFAULT_TOKEN_FILE, LocalAccess
from mirage_mcp.visualizer import get_ui_dist_path

MAX_BODY = 1024 * 1024
VERSION = __version__


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class _SSEBroker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[queue.Queue] = set()

    def subscribe(self) -> queue.Queue:
        stream: queue.Queue = queue.Queue(maxsize=128)
        with self._lock:
            if len(self._subscribers) >= 32:
                raise ValueError("Too many active event streams")
            self._subscribers.add(stream)
        return stream

    def unsubscribe(self, stream: queue.Queue) -> None:
        with self._lock:
            self._subscribers.discard(stream)

    def publish(self, event_type: str, data: dict[str, Any]) -> None:
        with self._lock:
            for stream in list(self._subscribers):
                try:
                    stream.put_nowait({"type": event_type, "timestamp": _utc_now_iso(), "data": data})
                except queue.Full:
                    self._subscribers.discard(stream)


class ControlPlaneServer:
    """Local trusted-operator service. Remote hosting is intentionally unsupported."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765,
                 db_path: str | Path | None = None, ui_dist_dir: str | Path | None = None,
                 token_file: str | Path = DEFAULT_TOKEN_FILE, auth_token: str | None = None,
                 development_origin: str | None = None, cloud_credentials: dict | None = None,
                 link_credentials: dict | None = None, link_credential_file: str | Path | None = None) -> None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("The local gateway must bind to loopback; remote hosting is unsupported")
        from mirage_mcp.runtime import RuntimeService
        self.host, self.port = host, port
        self.access = LocalAccess(token_file=token_file, owner_token=auth_token)
        path = Path(db_path) if db_path is not None else DEFAULT_HOME / (f"managed-{cloud_credentials['device_id']}.db" if cloud_credentials else 'live.db')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.broker = _SSEBroker()
        self.cloud_connector = None
        self.link_connector = None
        self.link_credential_file = link_credential_file
        from mirage_mcp.server.notify import DesktopNotifier
        self.notifier = DesktopNotifier()
        if cloud_credentials:
            from mirage_mcp.cloud.runtime import ManagedRuntimeService
            from mirage_mcp.cloud.connector import CloudConnector
            self.runtime = ManagedRuntimeService(path, cloud_credentials, event_callback=self._runtime_event)
            try:
                self.cloud_connector = CloudConnector(self.runtime, cloud_credentials)
                self.runtime.cloud_notify = self.cloud_connector.notify
            except Exception:
                self.runtime.close()
                raise
        else:
            self.runtime = RuntimeService(path, event_callback=self._runtime_event)
            if link_credentials:
                from mirage_mcp.cloud.linked import LinkedConnector
                try:
                    self.link_connector = LinkedConnector(self.runtime, link_credentials)
                except Exception as exc:
                    # An account link is optional; local protection starts without it.
                    print(f"Account link not started: {exc}", file=sys.stderr)
        self.store = self.runtime
        self.ui_dist_dir = Path(ui_dist_dir) if ui_dist_dir else get_ui_dist_path()
        if development_origin:
            parsed_dev = urlparse(development_origin)
            if parsed_dev.scheme != "http" or parsed_dev.hostname not in {"127.0.0.1", "localhost"} or parsed_dev.path not in {"", "/"}:
                self.runtime.close()
                raise ValueError("Development origins must be local HTTP origins")
        self.development_origin = development_origin
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._closed = False
        self._benchmark: dict[str, Any] | None = None

    @property
    def base_url(self) -> str:
        host = "127.0.0.1" if self.host == "localhost" else self.host
        return f"http://{'[::1]' if host == '::1' else host}:{self.port}"

    def _runtime_event(self, event: dict[str, Any]) -> None:
        self.broker.publish("interception_event", {"event": event})
        if self.cloud_connector: self.cloud_connector.notify(event)
        if self.link_connector and event.get('decision') == 'STEP_UP_REQUIRED': self.link_connector.notify(event)
        self.notifier.notify_event(event)

    def reload_link(self) -> dict:
        """Start (or restart) the account link from its saved credential, without restarting the runtime."""
        if self.cloud_connector:
            return {'linked': False, 'error': 'Managed mode does not use a personal link'}
        from mirage_mcp.cloud.client import DEFAULT_LINK_FILE, load_credentials
        from mirage_mcp.cloud.linked import LinkedConnector
        credentials = load_credentials(self.link_credential_file or DEFAULT_LINK_FILE)
        if self.link_connector:
            self.link_connector.stop()
            self.link_connector = None
        if not credentials:
            return {'linked': False}
        self.link_connector = LinkedConnector(self.runtime, credentials)
        self.link_connector.start()
        return self.link_connector.status()

    def pairing_url(self) -> str:
        return f"{self.base_url}/app/#pair/{self.access.create_pairing()}"

    def _origins(self) -> set[str]:
        origins = {f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}", f"http://[::1]:{self.port}"}
        if self.development_origin:
            origins.add(self.development_origin)
        return origins

    def build_redteam_report(self, force_rerun: bool = False) -> dict[str, Any]:
        if self._benchmark is not None and not force_rerun:
            return self._benchmark
        try:
            from mirage_mcp.evaluation.runner import run_full_benchmark
            from mirage_mcp.evaluation.scenarios_50 import EXPLOIT_SCENARIOS_50
        except ImportError:
            from benchmarks.runner import run_full_benchmark
            from benchmarks.scenarios_50 import EXPLOIT_SCENARIOS_50
        raw = run_full_benchmark(write_artifacts=False)
        summary = raw["summary"]
        sources = {entry["id"]: entry for entry in EXPLOIT_SCENARIOS_50}
        scenarios = []
        for row in raw["exploit_results"]:
            source = sources[row["id"]]
            scenarios.append({
                "setup_id": row["id"], "name": row["name"], "category": row["obfuscation_vector"],
                "source_server": source["hop1_server"], "source_tool": source["hop1_tool"],
                "sink_server": source["hop2_server"], "sink_tool": source["hop2_tool"],
                "expected_rule": "Legacy graph fixture", "blocked": row["mirage_blocked"],
                "actual_rule": row["verdict"], "eval_latency_ms": row["total_latency_ms"],
                "attack_narrative": f"Scripted {row['hop1_tool']} followed by {row['hop2_tool']}. No model or external service was invoked.",
                "poison_snippet": source["hop1_payload"][:220],
            })
        self._benchmark = {
            "run_at": summary["timestamp"], "evaluation_kind": "deterministic_legacy_graph_fixtures",
            "baseline_status": "not_measured", "total_attack_setups": summary["total_exploit_scenarios"],
            "blocked_attacks": summary["mirage_exploits_blocked"], "block_rate_pct": summary["mirage_block_rate_pct"],
            "total_clean_workflows": summary["total_clean_workflows"], "false_positives": summary["mirage_false_positives"],
            "false_positive_rate_pct": summary["mirage_false_positive_rate_pct"],
            "mean_latency_ms": summary["mirage_mean_latency_ms"], "p95_latency_ms": summary["mirage_p95_latency_ms"],
            "p99_latency_ms": summary["mirage_p99_latency_ms"], "scenarios": scenarios,
            "limitations": ["Scripted fixtures; no live agent compromise rate is measured.",
                            "Legacy graph restrictions can interrupt legitimate tasks; see the clean workflow results."],
        }
        return self._benchmark

    def run_redteam_scenario(self, setup_id: str | None = None) -> dict[str, Any]:
        report = self.build_redteam_report(force_rerun=True)
        if setup_id and setup_id not in {s["setup_id"] for s in report["scenarios"]}:
            raise ValueError("Unknown fixture ID")
        return {**report, "active_setup_id": setup_id, "topology": self.runtime.topology(),
                "events_recorded": [], "isolated": True}

    def discover_mcp_servers(self) -> list[dict[str, Any]]:
        home = Path.home()
        paths = [("Claude Desktop", home / "Library/Application Support/Claude/claude_desktop_config.json"),
                 ("Cursor IDE", home / ".cursor/mcp.json"),
                 ("Windsurf IDE", home / ".codeium/windsurf/mcp_config.json"),
                 ("VS Code Copilot", home / ".vscode/mcp.json")]
        found = []
        for app, path in paths:
            if not path.is_file() or path.stat().st_size > MAX_BODY:
                continue
            try:
                data = json.loads(path.read_text())
                entries = data.get("mcpServers", data.get("servers", {}))
                for name, entry in entries.items():
                    if not isinstance(entry, dict):
                        continue
                    # Environment values and connection strings are never returned to the UI.
                    command = str(entry.get("command", ""))
                    raw_args = entry.get("args", [])
                    args = [str(value) for value in raw_args] if isinstance(raw_args, list) else []
                    from mirage_mcp.security.secret_guard import SecretRedactor
                    redactor = SecretRedactor()
                    args = redactor.redact(args).redacted_payload
                    safe_args, hide_next = [], False
                    for argument in args:
                        sensitive = any(part in argument.lower().split('=', 1)[0] for part in ("password", "secret", "token", "api-key", "api_key", "credential", "authorization"))
                        if hide_next:
                            safe_args.append("[CREDENTIAL_HIDDEN]")
                            hide_next = False
                        elif sensitive and argument.startswith('-'):
                            if '=' in argument: safe_args.append(argument.split('=', 1)[0] + '=[CREDENTIAL_HIDDEN]')
                            else: safe_args.append(argument); hide_next = True
                        else:
                            safe_args.append("[CONNECTION_STRING_HIDDEN]" if "://" in argument else argument)
                    args = safe_args
                    wrapped = Path(command).name in ("elytra", "mirage", "mirage-mcp")
                    found.append({"origin": "discovered", "host_app": app, "config_path": str(path),
                                  "server_name": str(name), "command": command, "args": args,
                                  "wrapped": wrapped, "transport": "stdio" if command else "http",
                                  "estimated_tools": 0, "risk_profile": "UNKNOWN", "coverage": "configuration_only"})
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        return found

    def wrap_server_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        # Generic desktop interception is only available with an explicit run scope.
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("An explicit run_id is required. Create a run in Setup; conversation identity cannot be inferred from desktop MCP traffic.")
        if not any(run["run_id"] == run_id and run.get("status") == "ACTIVE" for run in self.runtime.list_runs()):
            raise ValueError("Select an active run")
        name = str(payload.get("server_name", "mcp-server"))
        command, args = payload.get("command"), payload.get("args", [])
        if not isinstance(command, str) or not command or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError("A command and string arguments are required")
        if any("HIDDEN]" in arg or "REDACTED" in arg for arg in args):
            raise ValueError("This inventory hides credentials. Use the local CLI with the original host file to preserve them.")
        launch = ["proxy", "--server-name", name, "--run-id", run_id, "--gateway", self.base_url, "--", command, *args]
        return {"server_name": name, "wrapped_config": {"mcpServers": {name: {"command": "elytra", "args": launch,
                  "env": {"ELYTRA_RUN_TOKEN": "<run-scoped token; never use the owner credential>"}}}},
                "cli_snippet": shlex.join(["elytra", *launch]), "requires_run_token": True,
                "coverage": "explicit_run_only", "applied": False}

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "Elytra"
            protocol_version = "HTTP/1.0"

            def log_message(self, *_: Any) -> None:
                pass

            def _owner(self) -> bool:
                return service.access.is_owner(self.headers.get("Authorization", ""), self.headers.get("Cookie", ""))

            def _json(self, data: Any, status: int = 200, headers: dict[str, str] | None = None) -> None:
                encoded = json.dumps(data, allow_nan=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(encoded)

            def _guard(self, write: bool = False) -> bool:
                host = self.headers.get("Host", "")
                if host not in {f"127.0.0.1:{service.port}", f"localhost:{service.port}", f"[::1]:{service.port}", "127.0.0.1", "localhost"}:
                    self._json({"error": "Invalid local Host header"}, 403)
                    return False
                origin = self.headers.get("Origin")
                if origin and origin not in service._origins():
                    self._json({"error": "Cross-origin access is forbidden"}, 403)
                    return False
                if write and not self.headers.get("Authorization", "").startswith("Bearer "):
                    if not origin or self.headers.get("X-Elytra-Request") != "1":
                        self._json({"error": "Browser writes require same-origin request protection"}, 403)
                        return False
                return True

            def _body(self) -> dict[str, Any]:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("Chunked request bodies are unsupported")
                count = int(self.headers.get("Content-Length", "0"))
                if count < 0 or count > MAX_BODY:
                    raise ValueError("Request exceeds the 1 MiB limit")
                if self.headers.get_content_type() != "application/json":
                    raise ValueError("Content-Type must be application/json")
                data = json.loads(self.rfile.read(count) or b"{}")
                if not isinstance(data, dict):
                    raise ValueError("JSON object required")
                return data

            def _run_args(self, payload: dict[str, Any]) -> tuple[str, str]:
                run_id = payload.get("run_id")
                authorization = self.headers.get("Authorization", "")
                token = payload.get("run_token") if self._owner() else authorization.removeprefix("Bearer ")
                if not authorization.startswith("Bearer ") and not self._owner():
                    raise PermissionError("A run-scoped bearer credential is required")
                if not isinstance(run_id, str) or not isinstance(token, str) or not token:
                    raise ValueError("run_id and run credential are required")
                return run_id, token

            def _error(self, exc: Exception) -> None:
                from mirage_mcp.runtime import RuntimeAuthorizationError, RuntimeConflictError, RuntimeValidationError
                if isinstance(exc, (PermissionError, RuntimeAuthorizationError)):
                    code = 403
                elif isinstance(exc, (RuntimeConflictError,)):
                    code = 409
                elif isinstance(exc, (ValueError, KeyError, TypeError, RuntimeValidationError)):
                    code = 400
                else:
                    code = 500
                self._json({"error": str(exc) if code != 500 else "Internal gateway error"}, code)

            def do_OPTIONS(self) -> None:
                self._json({"error": "Cross-origin API access is disabled"}, 403)

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                path, query = parsed.path, parse_qs(parsed.query)
                if not path.startswith("/api/"):
                    self._static(path)
                    return
                if not self._guard():
                    return
                if path == "/api/v1/health":
                    self._json({"status": "ok", "service": "elytra-local-runtime", "version": VERSION})
                    return
                if path == "/api/v1/config":
                    self._json({"demo_mode": False, "authenticated": self._owner(), "version": VERSION, "local": True})
                    return
                try:
                    if path.startswith("/api/v1/runtime/calls/"):
                        run_id, token = self._run_args({"run_id": query.get("run_id", [None])[0],
                                                        "run_token": query.get("run_token", [None])[0]})
                        self._json(service.runtime.get_call(run_id, token, unquote(path.rsplit("/", 1)[-1])))
                        return
                    if not self._owner():
                        self._json({"error": "Pair this browser using elytra connect --open"}, 401)
                        return
                    runtime = service.runtime
                    if path == "/api/v1/overview": self._json(runtime.overview())
                    elif path == "/api/v1/topology": self._json(runtime.topology())
                    elif path == "/api/v1/events":
                        limit = max(1, min(1000, int(query.get("limit", [200])[0])))
                        self._json({"events": runtime.list_events(limit=limit)})
                    elif path == "/api/v1/approvals": self._json({"approvals": runtime.list_approvals(query.get("status", [None])[0])})
                    elif path == "/api/v1/policies": self._json({"policies": runtime.get_policies()})
                    elif path == "/api/v1/schema-pins": self._json({"pins": runtime.list_pins()})
                    elif path == "/api/v1/discovery": self._json({"servers": service.discover_mcp_servers()})
                    elif path in ("/api/v1/runs", "/api/v1/runtime/runs"): self._json({"runs": runtime.list_runs()})
                    elif path in ("/api/v1/tools", "/api/v1/runtime/tools"): self._json({"tools": runtime.list_tools()})
                    elif path == "/api/v1/runtime/coverage": self._json({**runtime.health_summary(), **(runtime.cloud_status() if hasattr(runtime, 'cloud_status') else {'managed': False})})
                    elif path == "/api/v1/redteam/scenarios": self._json(service.build_redteam_report())
                    elif path == "/api/v1/hosts": self._json({"hosts": runtime.list_hosts()})
                    elif path == "/api/v1/guardrails": self._json(runtime.guardrails())
                    elif path == "/api/v1/cloud/link": self._json(service.link_connector.status() if service.link_connector else {'linked': False})
                    elif path == "/api/v1/catalog": self._json(runtime.catalog_servers())
                    elif path == "/api/v1/stream": self._stream(query)
                    else: self._json({"error": "Unknown endpoint"}, 404)
                except (BrokenPipeError, ConnectionResetError):
                    return
                except Exception as exc:
                    self._error(exc)

            def do_POST(self) -> None:
                path = urlparse(self.path).path
                if not path.startswith("/api/"):
                    self._json({"error": "Unknown endpoint"}, 404)
                    return
                if not self._guard(write=True):
                    return
                try:
                    body = self._body()
                    if path == "/api/v1/session":
                        code = body.get("pairing_code", "")
                        if not isinstance(code, str) or len(code) > 256:
                            raise ValueError("Invalid pairing code")
                        cookie = service.access.redeem(code)
                        self._json({"authenticated": True}, headers={"Set-Cookie": f"elytra_session={cookie}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=28800"})
                        return
                    if path == "/api/v1/runtime/host-session":
                        authorization = self.headers.get("Authorization", "")
                        if not authorization.startswith("Bearer "):
                            raise PermissionError("A host credential is required")
                        self._json(service.runtime.open_host_session(body.get("host_id"), authorization[7:], body.get("session_key"), body.get("parent_key")))
                        return
                    scoped = {"/api/v1/runtime/tools/register", "/api/v1/runtime/tools", "/api/v1/runtime/tools/observe", "/api/v1/runtime/evaluate", "/api/v1/runtime/claim",
                              "/api/v1/runtime/complete", "/api/v1/runtime/cancel", "/api/v1/runtime/finish", "/api/v1/runtime/uncertain", "/api/v1/runtime/validate",
                              "/api/v1/runtime/sources/scan"}
                    if path in scoped:
                        self._scoped(path, body)
                        return
                    if not self._owner():
                        self._json({"error": "Operator authentication required"}, 401)
                        return
                    runtime = service.runtime
                    if path == "/api/v1/session/logout":
                        service.access.logout(self.headers.get("Cookie", ""))
                        self._json({"authenticated": False}, headers={"Set-Cookie": "elytra_session=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0"})
                    elif path == '/api/v1/cloud/disconnect':
                        if service.cloud_connector:
                            result = runtime.disconnect_cloud()
                            service.cloud_connector.stop()
                            self._json(result)
                        else: self._json({'managed': False, 'connected': False})
                    elif path == '/api/v1/cloud/link/reload':
                        self._json(service.reload_link())
                    elif path == '/api/v1/cloud/link/disconnect':
                        if service.link_connector:
                            service.link_connector.stop()
                            service.link_connector = None
                        self._json({'linked': False})
                    elif path == "/api/v1/pair": self._json({"pairing_url": service.pairing_url()})
                    elif path.startswith("/api/v1/sessions/") and path.endswith("/trust"):
                        self._json(runtime.reset_session_trust(unquote(path.split("/")[-2])))
                    elif path in ("/api/v1/runs", "/api/v1/runtime/runs"):
                        self._json(runtime.create_run(intent=body.get("intent", ""), grants=body.get("grants", []), ttl_seconds=body.get("ttl_seconds", 3600)), 201)
                    elif path == "/api/v1/schema-pins/acknowledge":
                        self._json(runtime.acknowledge_schema(body["server_id"], body["tool_name"], body["sha256_hash"], body["category"]))
                        service.broker.publish("policy_updated", {})
                    elif path == "/api/v1/policies":
                        self._json(runtime.save_policy(body))
                        service.broker.publish("policy_updated", {})
                    elif path == "/api/v1/approvals/resolve" or (path.startswith("/api/v1/approvals/") and path.endswith("/resolve")):
                        approval_id = body.get("approval_id") if path == "/api/v1/approvals/resolve" else unquote(path.split("/")[-2])
                        result = runtime.resolve_approval(approval_id, body.get("status", "DENIED"), actor="local-operator")
                        # Permits are returned only to the originating scoped run, never to the browser.
                        result = {k: v for k, v in result.items() if k not in ("permit", "run_token")}
                        self._json(result)
                        service.broker.publish("approval_resolved", {})
                    elif path == "/api/v1/discovery/wrap": self._json(service.wrap_server_config(body))
                    elif path == "/api/v1/hosts":
                        self._json(runtime.create_host_credential(body.get("label", ""), body.get("kind", ""), body.get("approval_window", 600)), 201)
                    elif path.startswith("/api/v1/hosts/") and path.endswith("/revoke"):
                        self._json(runtime.revoke_host(unquote(path.split("/")[-2])))
                        service.broker.publish("policy_updated", {})
                    elif path == "/api/v1/guardrails":
                        self._json(runtime.apply_guardrail_preset(body.get("preset", "")))
                        service.broker.publish("policy_updated", {})
                    elif path.startswith("/api/v1/policies/") and path.endswith("/delete"):
                        self._json(runtime.delete_policy(unquote(path.split("/")[-2])))
                        service.broker.publish("policy_updated", {})
                    elif path == "/api/v1/agent-actions/install":
                        self._json({"actions": [t["tool_name"] for t in runtime.install_builtin_actions()]})
                    elif path == "/api/v1/catalog/accept":
                        self._json(runtime.accept_catalog_server(body.get("server_id"), body.get("catalog_id")))
                        service.broker.publish("policy_updated", {})
                    elif path == "/api/v1/redteam/run": self._json(service.run_redteam_scenario(body.get("setup_id")))
                    else: self._json({"error": "Unknown endpoint"}, 404)
                except (BrokenPipeError, ConnectionResetError):
                    return
                except Exception as exc:
                    self._error(exc)

            def _scoped(self, path: str, body: dict[str, Any]) -> None:
                run_id, token = self._run_args(body)
                runtime = service.runtime
                if path.endswith("/tools/register") or path.endswith("/runtime/tools"):
                    if body.get("classifications") and not self._owner():
                        raise PermissionError("Only the local operator may classify tools")
                    result = runtime.register_tools(run_id, token, body["server_id"], body["tools"], classifications=body.get("classifications") if self._owner() else None)
                elif path.endswith("/tools/observe"):
                    result = runtime.observe_tool(run_id, token, body["server_id"], body["tool_name"])
                elif path.endswith("/validate"):
                    result = runtime.validate_run(run_id, token)
                elif path.endswith("/evaluate"):
                    result = runtime.evaluate(run_id, token, body["server_id"], body["tool_name"], body.get("arguments", {}), body["call_id"], notify=body.get("notify", True) is not False, claim=body.get("claim") is True)
                elif path.endswith("/claim"):
                    result = runtime.claim_execution(run_id, token, body["call_id"], body["permit"], body.get("arguments", {}))
                elif path.endswith("/complete"):
                    result = runtime.complete_execution(run_id, token, body["call_id"], body.get("result"), bool(body.get("is_error", False)))
                elif path.endswith("/uncertain"):
                    result = runtime.mark_uncertain(run_id, token, body["call_id"], body.get("reason", "Transport ended after dispatch"))
                elif path.endswith("/cancel"):
                    result = runtime.cancel_call(run_id, token, body["call_id"])
                elif path.endswith("/finish"):
                    result = runtime.finish_run(run_id, token, body.get("status", "COMPLETED"))
                elif path.endswith("/sources/scan"):
                    result = runtime.report_source_scan(run_id, token, body["call_id"], body.get("findings", []))
                else:
                    raise ValueError("Unknown run operation")
                self._json(result)

            def _stream(self, query: dict[str, list[str]]) -> None:
                stream = service.broker.subscribe()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                try:
                    initial = {"overview": service.runtime.overview(), "topology": service.runtime.topology()}
                    self.wfile.write(f"event: snapshot\ndata: {json.dumps(initial)}\n\n".encode())
                    self.wfile.flush()
                    if query.get("once", ["0"])[0] == "1":
                        return
                    while self._owner() and not service._closed:
                        try:
                            event = stream.get(timeout=10)
                            data = f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
                        except queue.Empty:
                            data = b": keepalive\n\n"
                        self.wfile.write(data)
                        self.wfile.flush()
                finally:
                    service.broker.unsubscribe(stream)

            def _static(self, request_path: str) -> None:
                root = service.ui_dist_dir.resolve()
                clean = unquote(request_path).lstrip("/")
                if any(part.startswith(".") for part in Path(clean).parts):
                    self._json({"error": "Not found"}, 404)
                    return
                candidate = (root / (clean or "index.html")).resolve()
                if not candidate.is_relative_to(root):
                    self._json({"error": "Not found"}, 404)
                    return
                if not candidate.is_file():
                    if clean.startswith("assets/") or Path(clean).suffix:
                        self._json({"error": "Static asset not found"}, 404)
                        return
                    candidate = root / "index.html"
                if not candidate.is_file():
                    self._json({"error": "Console assets are missing. Install a complete release or build ui/ before packaging."}, 503)
                    return
                content = candidate.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mimetypes.guess_type(str(candidate))[0] or "application/octet-stream")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
                self.send_header("Cache-Control", "no-cache" if candidate.suffix == ".html" else "public, max-age=3600")
                self.end_headers()
                self.wfile.write(content)

        return Handler

    def dispatch_raw_http(self, method: str, path: str, body: dict[str, Any] | bytes | None = None,
                          headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        """Request the real handler over a socketpair; default credential is the test owner."""
        payload = json.dumps(body).encode() if isinstance(body, dict) else (body or b"")
        hdrs = {"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json",
                "Content-Length": str(len(payload)), "Authorization": f"Bearer {self.access.owner_token}"}
        if headers is not None:
            hdrs.update(headers)
        request = (f"{method.upper()} {path} HTTP/1.0\r\n" + "".join(f"{key}: {value}\r\n" for key, value in hdrs.items()) + "\r\n").encode() + payload
        client, server = socket.socketpair()
        client.settimeout(10)
        handler = self._make_handler()
        def handle() -> None:
            try:
                handler(server, ("127.0.0.1", 0), self)
            finally:
                server.close()
        thread = threading.Thread(target=handle, daemon=True)
        thread.start()
        try:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = client.recv(65536)
                if not chunk: break
                chunks.append(chunk)
        finally:
            client.close()
        thread.join(timeout=10)
        header, _, response = b"".join(chunks).partition(b"\r\n\r\n")
        lines = header.decode().split("\r\n")
        status = int(lines[0].split()[1])
        return status, dict(line.split(": ", 1) for line in lines[1:] if ": " in line), response

    def start_background(self) -> str:
        if self._httpd is not None: return self.base_url
        server_type = type("IPv6Server", (ThreadingHTTPServer,), {"address_family": socket.AF_INET6}) if self.host == "::1" else ThreadingHTTPServer
        try:
            self._httpd = server_type((self.host, self.port), self._make_handler())
        except OSError:
            self.runtime.close()
            self._closed = True
            raise
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="elytra-runtime")
        self._thread.start()
        if self.cloud_connector: self.cloud_connector.start()
        if self.link_connector: self.link_connector.start()
        return self.base_url

    def wait_forever(self) -> None:
        if self._thread is None: raise RuntimeError("Start the service first")
        while self._thread.is_alive(): self._thread.join(timeout=1)

    def serve_forever(self) -> None:
        self.start_background()
        self.wait_forever()

    def shutdown(self) -> None:
        if self._closed: return
        self._closed = True
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None: self._thread.join(timeout=2)
        if self.cloud_connector: self.cloud_connector.stop()
        if self.link_connector: self.link_connector.stop()
        self.runtime.close()

    stop = shutdown


def main() -> None:
    server = ControlPlaneServer(port=int(os.environ.get("MIRAGE_PORT", "8765")), db_path=os.environ.get("MIRAGE_DB_PATH"))
    print(f"Elytra local product: {server.base_url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__": main()
