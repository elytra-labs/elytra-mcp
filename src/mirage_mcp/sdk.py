"""Small stdlib HTTP client for the supported explicit-run integration.

Owner credentials stay in the orchestrator. Pass only ``client.for_run(...)``
to MCP proxy processes. A token authenticates requests; it never substitutes
for a tool classification, policy, exact grant or approval.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit
import uuid

MAX_RESPONSE = 8 * 1024 * 1024


class RuntimeAPIError(RuntimeError):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


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
        self._parsed = parsed

    def _request(self, method: str, route: str, payload=None):
        """One request to the loopback control plane. Bearer credentials never pass through proxies or redirects."""
        data = json.dumps(payload, allow_nan=False).encode() if payload is not None else b""
        parsed = self._parsed
        if parsed.scheme != "http":
            return self._request_tls(method, route, data if payload is not None else None)
        host = parsed.hostname
        head = (f"{method} {route} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n"
                f"Authorization: Bearer {self.token}\r\nContent-Type: application/json\r\nAccept: application/json\r\n"
                f"Content-Length: {len(data)}\r\n\r\n").encode()
        try:
            with socket.create_connection((host.strip("[]"), parsed.port or 80), timeout=20) as connection:
                connection.sendall(head + data)
                chunks, size = [], 0
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_RESPONSE + 65536:
                        raise RuntimeAPIError(0, "Control-plane response exceeds 8 MiB")
        except OSError as exc:
            raise RuntimeAPIError(0, "Cannot connect to the local Elytra control plane") from exc
        raw = b"".join(chunks)
        header, _, body = raw.partition(b"\r\n\r\n")
        try:
            status = int(header.split(b" ", 2)[1])
        except (IndexError, ValueError):
            raise RuntimeAPIError(0, "Invalid control-plane response") from None
        if b"transfer-encoding: chunked" in header.lower():
            body = self._dechunk(body)
        if 300 <= status < 400:
            raise RuntimeAPIError(status, "Control-plane redirects are not followed")
        if status >= 400:
            try:
                detail = json.loads(body[:4096]).get("error", "Control-plane request failed")
            except (ValueError, AttributeError):
                detail = "Control-plane request failed"
            raise RuntimeAPIError(status, str(detail))
        if len(body) > MAX_RESPONSE:
            raise RuntimeAPIError(status, "Control-plane response exceeds 8 MiB")
        try:
            return json.loads(body)
        except ValueError:
            raise RuntimeAPIError(status, "Invalid control-plane response") from None

    @staticmethod
    def _dechunk(body: bytes) -> bytes:
        out, rest = [], body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out.append(rest[:size])
            rest = rest[size + 2:]
        return b"".join(out)

    def _request_tls(self, method: str, route: str, data):
        from urllib.error import HTTPError, URLError
        from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        request = Request(self.base_url + route, data=data, method=method,
                          headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=20) as response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
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
    def host_session(cls, host_id: str, host_token: str, session_key: str, base_url="http://127.0.0.1:8765", parent_key: str | None = None):
        """Open or resume a host session for one agent host process, or for one conversation in it (`parent_key`).
        Uses only the host credential."""
        host = cls(base_url=base_url, token=host_token)
        body = {"host_id": host_id, "session_key": session_key, **({"parent_key": parent_key} if parent_key else {})}
        opened = host._request("POST", "/api/v1/runtime/host-session", body)
        scoped = host.for_run(opened["run_id"], opened["run_token"])
        scoped.session = opened
        return scoped

    def for_run(self, run_id: str, run_token: str):
        scoped = object.__new__(RuntimeClient)
        scoped.base_url, scoped.run_id, scoped.run_token = self.base_url, run_id, run_token
        scoped.token = run_token
        scoped._parsed = self._parsed
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

    def evaluate(self, server_id: str, tool_name: str, arguments: dict, call_id=None, notify: bool = True, claim: bool = False):
        """Decide a call. `claim=True` also claims an allowed call at once (no permit is returned then)."""
        return self._request("POST", "/api/v1/runtime/evaluate", {**self._scoped(), "server_id": server_id, "tool_name": tool_name, "arguments": arguments,
                                                                 "call_id": call_id or "call_" + uuid.uuid4().hex, "notify": bool(notify),
                                                                 **({"claim": True} if claim else {})})

    def observe_tool(self, server_id: str, tool_name: str):
        return self._request("POST", "/api/v1/runtime/tools/observe", {**self._scoped(), "server_id": server_id, "tool_name": tool_name})

    def claim(self, call_id: str, permit: str, arguments: dict):
        return self._request("POST", "/api/v1/runtime/claim", {**self._scoped(), "call_id": call_id, "permit": permit, "arguments": arguments})

    claim_execution = claim

    def complete(self, call_id: str, result: Any, is_error=False):
        return self._request("POST", "/api/v1/runtime/complete", {**self._scoped(), "call_id": call_id, "result": result, "is_error": bool(is_error)})

    complete_execution = complete

    def report_scan(self, call_id: str, findings: list):
        """Report what content inspection found in a read this run dispatched. Findings only ever raise taint."""
        return self._request("POST", "/api/v1/runtime/sources/scan", {**self._scoped(), "call_id": call_id, "findings": findings})

    def trust_session(self, run_id: str):
        self._owner()
        return self._request("POST", "/api/v1/sessions/" + quote(run_id, safe="") + "/trust", {})

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
