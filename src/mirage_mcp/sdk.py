"""Small stdlib HTTP client for the supported explicit-run integration.

Owner credentials stay in the orchestrator. Pass only ``client.for_run(...)``
to MCP proxy processes. A token authenticates requests; it never substitutes
for a tool classification, policy, exact grant or approval.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
import uuid


class RuntimeAPIError(RuntimeError):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RuntimeClient:
    def __init__(self, base_url="http://127.0.0.1:8765", token=None, token_file=None):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("A plain HTTP(S) control-plane URL is required")
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("This release supports only a loopback control plane")
        if parsed.query or parsed.fragment:
            raise ValueError("Control-plane URL cannot contain a query or fragment")
        self.base_url = base_url.rstrip("/")
        self.run_id = None
        self.run_token = None
        self.token = token
        if self.token is None:
            path = Path(token_file or Path.home() / ".elytra" / "control-plane.token")
            if path.is_file():
                self.token = path.read_text().strip()
        if not self.token:
            raise ValueError("Owner token required; start `elytra up` or supply token/token_file")
        # Never forward bearer credentials through ambient HTTP proxies or
        # redirects. Hosted support can add an explicitly configured transport.
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _request(self, method: str, route: str, payload=None):
        data = json.dumps(payload, allow_nan=False).encode() if payload is not None else None
        request = Request(self.base_url + route, data=data, method=method,
                          headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=20) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise RuntimeAPIError(response.status, "Control-plane response exceeds 8 MiB")
                return json.loads(raw)
        except HTTPError as exc:
            try:
                detail = json.loads(exc.read(4096)).get("error", "Control-plane request failed")
            except (ValueError, AttributeError):
                detail = "Control-plane request failed"
            raise RuntimeAPIError(exc.code, str(detail)) from None
        except URLError as exc:
            raise RuntimeAPIError(0, "Cannot connect to the local Elytra control plane") from exc

    def _scoped(self) -> dict:
        if not self.run_id:
            raise ValueError("Use client.for_run(run_id,run_token) for run operations")
        return {"run_id": self.run_id}

    def _owner(self):
        if self.run_id:
            raise ValueError("Run-scoped clients cannot perform owner operations")

    def create_run(self, intent: str, grants=None, ttl_seconds=3600):
        self._owner()
        return self._request("POST", "/api/v1/runtime/runs", {"intent": intent, "grants": grants or [], "ttl_seconds": ttl_seconds})

    # Owner operations for host integrations and guardrails.
    def create_host(self, label: str, kind: str, approval_window: int = 600):
        self._owner()
        return self._request("POST", "/api/v1/hosts", {"label": label, "kind": kind, "approval_window": approval_window})

    def hosts(self):
        self._owner()
        return self._request("GET", "/api/v1/hosts")

    def revoke_host(self, host_id: str):
        self._owner()
        return self._request("POST", "/api/v1/hosts/" + quote(host_id, safe="") + "/revoke", {})

    def guardrails(self):
        self._owner()
        return self._request("GET", "/api/v1/guardrails")

    def apply_guardrails(self, preset: str):
        self._owner()
        return self._request("POST", "/api/v1/guardrails", {"preset": preset})

    def install_agent_actions(self):
        self._owner()
        return self._request("POST", "/api/v1/agent-actions/install", {})

    def accept_catalog(self, server_id: str, catalog_id: str):
        self._owner()
        return self._request("POST", "/api/v1/catalog/accept", {"server_id": server_id, "catalog_id": catalog_id})

    @classmethod
    def host_session(cls, host_id: str, host_token: str, session_key: str, base_url="http://127.0.0.1:8765"):
        """Open or resume the host-session run for one agent host process. Uses only the host credential."""
        host = cls(base_url=base_url, token=host_token)
        opened = host._request("POST", "/api/v1/runtime/host-session", {"host_id": host_id, "session_key": session_key})
        scoped = host.for_run(opened["run_id"], opened["run_token"])
        scoped.session = opened
        return scoped

    def for_run(self, run_id: str, run_token: str):
        scoped = object.__new__(RuntimeClient)
        scoped.base_url, scoped.run_id, scoped.run_token = self.base_url, run_id, run_token
        scoped.token = run_token
        scoped._opener = self._opener
        return scoped

    def run(self, intent: str, grants=None, ttl_seconds=3600):
        created = self.create_run(intent, grants, ttl_seconds)
        return self.for_run(created["run_id"], created["run_token"])

    def register_tools(self, server_id: str, tools: list):
        return self._request("POST", "/api/v1/runtime/tools/register", {**self._scoped(), "server_id": server_id, "tools": tools})

    def validate_run(self):
        return self._request("POST", "/api/v1/runtime/validate", self._scoped())

    def list_tools(self):
        self._owner()
        return self._request("GET", "/api/v1/tools")

    def list_runs(self):
        self._owner()
        return self._request("GET", "/api/v1/runtime/runs")

    def classify_tool(self, server_id: str, tool_name: str, sha256_hash: str, category: str):
        self._owner()
        return self._request("POST", "/api/v1/schema-pins/acknowledge", {"server_id": server_id, "tool_name": tool_name, "sha256_hash": sha256_hash, "category": category})

    acknowledge_schema = classify_tool

    def evaluate(self, server_id: str, tool_name: str, arguments: dict, call_id=None, notify: bool = True):
        return self._request("POST", "/api/v1/runtime/evaluate", {**self._scoped(), "server_id": server_id, "tool_name": tool_name, "arguments": arguments,
                                                                 "call_id": call_id or "call_" + uuid.uuid4().hex, "notify": bool(notify)})

    def observe_tool(self, server_id: str, tool_name: str):
        return self._request("POST", "/api/v1/runtime/tools/observe", {**self._scoped(), "server_id": server_id, "tool_name": tool_name})

    def claim(self, call_id: str, permit: str, arguments: dict):
        return self._request("POST", "/api/v1/runtime/claim", {**self._scoped(), "call_id": call_id, "permit": permit, "arguments": arguments})

    claim_execution = claim

    def complete(self, call_id: str, result: Any, is_error=False):
        return self._request("POST", "/api/v1/runtime/complete", {**self._scoped(), "call_id": call_id, "result": result, "is_error": bool(is_error)})

    complete_execution = complete

    def call_status(self, call_id: str):
        self._scoped()
        return self._request("GET", "/api/v1/runtime/calls/" + quote(call_id, safe="") + "?" + urlencode({"run_id": self.run_id}))

    def cancel(self, call_id: str):
        return self._request("POST", "/api/v1/runtime/cancel", {**self._scoped(), "call_id": call_id})

    cancel_call = cancel

    def mark_uncertain(self, call_id, reason="Transport ended after dispatch"):
        return self._request("POST", "/api/v1/runtime/uncertain", {**self._scoped(), "call_id": call_id, "reason": reason})

    def approvals(self, status=None):
        self._owner()
        route = "/api/v1/approvals" + ("?" + urlencode({"status": status}) if status else "")
        return self._request("GET", route)

    def resolve_approval(self, approval_id, status, actor="local-user"):
        self._owner()
        return self._request("POST", "/api/v1/approvals/" + quote(approval_id, safe="") + "/resolve", {"status": status, "actor": actor})

    def finish(self, status="COMPLETED"):
        return self._request("POST", "/api/v1/runtime/finish", {**self._scoped(), "status": status})

    finish_run = finish

    def proxy(self, server_id: str, command: list[str]):
        self._scoped()
        from mirage_mcp.proxy.protected_client import ProtectedMCPClient
        return ProtectedMCPClient(self, server_id, command)

    def __enter__(self):
        self._scoped()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finish("FAILED" if exc_type else "COMPLETED")
