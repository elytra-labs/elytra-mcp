"""Legacy seeded-store fixtures and the empty authenticated live HTTP service."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest

from mirage_mcp.server import ControlPlaneServer
from mirage_mcp.store import MirageSQLiteStore

_DIRECT_OPENER = build_opener(ProxyHandler({}))


def _http(
    url: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Use the actual ephemeral listener; never fall back to a user's server."""
    payload = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=payload, method=method,
                      headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with _DIRECT_OPENER.open(request, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except HTTPError as response:
        return response.code, dict(response.headers), response.read()


def _http_json(url: str, method: str = "GET", body=None, headers=None) -> dict[str, Any]:
    status, _, payload = _http(url, method, body, headers)
    assert 200 <= status < 300, f"Unexpected HTTP status {status}: {payload!r}"
    return json.loads(payload)


def test_sqlite_store_seed_and_crud(tmp_path: Path) -> None:
    """Legacy demonstration fixtures only; these are not live product metrics."""
    db_file = tmp_path / "test_mirage.db"
    store = MirageSQLiteStore(db_path=db_file)

    overview = store.get_overview()
    assert overview["total_events"] >= 18
    assert overview["blocked_second_hops"] >= 5
    assert overview["pending_approvals"] == 2
    assert overview["schema_pins_verified"] == 6
    assert overview["attack_block_rate_pct"] == 100.0
    assert overview["false_positive_rate_pct"] == 0.0

    topo = store.get_topology()
    assert len(topo["nodes"]) == 13
    assert len(topo["edges"]) == 16

    policies = store.list_policies()
    assert len(policies) == 6
    toggled = store.toggle_policy("MIRAGE-TAINT-001", False)
    assert toggled is not None
    assert toggled["enabled"] is False

    pins = store.list_schema_pins()
    assert len(pins) == 8
    statuses = {p["tool_name"]: p["status"] for p in pins}
    assert statuses["slack_post_webhook"] == "DRIFT_DETECTED"
    assert statuses["untrusted_markdown_fetcher"] == "POISON_SUSPECTED"

    pending = store.list_approvals(status="PENDING")
    assert len(pending) == 2
    resolved = store.resolve_approval(pending[0]["approval_id"], "DENIED")
    assert resolved is not None
    assert resolved["status"] == "DENIED"
    assert len(store.list_approvals(status="PENDING")) == 1


def test_control_plane_http_endpoints(tmp_path: Path) -> None:
    server = ControlPlaneServer(host="127.0.0.1", port=0, db_path=tmp_path / "live.db",
                                auth_token="test-owner-" + "x" * 48,
                                token_file=tmp_path / "unused-owner-token")
    base_url = server.start_background()
    owner = {"Authorization": "Bearer test-owner-" + "x" * 48}
    try:
        assert server.port != 0
        health = _http_json(f"{base_url}/api/v1/health")
        assert health["status"] == "ok"
        assert health["service"] == "elytra-local-runtime"
        assert _http(f"{base_url}/api/v1/overview")[0] == 401
        assert _http(f"{base_url}/api/v1/overview", headers={"Authorization": "Bearer invalid"})[0] == 401

        overview = _http_json(f"{base_url}/api/v1/overview", headers=owner)
        assert overview["mode"] == "live"
        assert overview["coverage"] == "EXPLICIT_RUN"
        assert overview["total_events"] == overview["pending_approvals"] == overview["active_sessions"] == 0
        assert overview["attack_block_rate_pct"] is None
        assert overview["false_positive_rate_pct"] is None
        topology = _http_json(f"{base_url}/api/v1/topology", headers=owner)
        assert topology["nodes"] == topology["edges"] == []
        for route, key in (("events", "events"), ("approvals", "approvals"), ("policies", "policies"),
                           ("schema-pins", "pins"), ("runtime/runs", "runs"), ("tools", "tools")):
            assert _http_json(f"{base_url}/api/v1/{route}", headers=owner)[key] == []

        # Evaluation runs are isolated observations; they cannot seed live
        # topology, tool registry, approvals, policies, run history or telemetry.
        evaluation = _http_json(f"{base_url}/api/v1/redteam/run", "POST", {"setup_id": "EXP_01"}, owner)
        assert evaluation["isolated"] is True
        assert evaluation["baseline_status"] == "not_measured"
        assert evaluation["evaluation_kind"] == "deterministic_legacy_graph_fixtures"
        assert evaluation["active_setup_id"] == "EXP_01"
        assert evaluation["events_recorded"] == []
        assert evaluation["topology"]["nodes"] == evaluation["topology"]["edges"] == []
        for route, key in (("events", "events"), ("approvals", "approvals"), ("policies", "policies"),
                           ("schema-pins", "pins"), ("runtime/runs", "runs"), ("tools", "tools")):
            assert _http_json(f"{base_url}/api/v1/{route}", headers=owner)[key] == []
        assert _http_json(f"{base_url}/api/v1/overview", headers=owner)["total_events"] == 0

        # A pairing code is one-use and grants an HttpOnly session, without
        # returning the administrative bearer credential to the browser.
        pairing = _http_json(f"{base_url}/api/v1/pair", "POST", {}, owner)
        code = pairing["pairing_url"].split("#pair/", 1)[1]
        assert _http(f"{base_url}/api/v1/session", "POST", {"pairing_code": code})[0] == 403
        browser_headers = {"Origin": base_url, "X-Elytra-Request": "1"}
        status, headers, payload = _http(f"{base_url}/api/v1/session", "POST", {"pairing_code": code}, browser_headers)
        assert status == 200 and json.loads(payload) == {"authenticated": True}
        assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert owner["Authorization"].split()[1] not in cookie
        browser_headers["Cookie"] = cookie
        assert _http(f"{base_url}/api/v1/session", "POST", {"pairing_code": code}, browser_headers)[0] == 400
        assert _http_json(f"{base_url}/api/v1/overview", headers={"Cookie": cookie})["total_events"] == 0

        policy = {"rule_id": "operator-test-policy", "source_pattern": "*", "sink_pattern": "records.*",
                  "min_taint_level": "HIGH", "action": "STEP_UP_APPROVAL"}
        assert _http(f"{base_url}/api/v1/policies", "POST", policy, {"Cookie": cookie, "Origin": base_url})[0] == 403
        assert _http(f"{base_url}/api/v1/policies", "POST", policy,
                     {**browser_headers, "Origin": "https://untrusted.example"})[0] == 403
        assert _http_json(f"{base_url}/api/v1/policies", headers=owner)["policies"] == []
        saved = _http_json(f"{base_url}/api/v1/policies", "POST", policy, browser_headers)
        assert saved["rule_id"] == policy["rule_id"]
        assert len(_http_json(f"{base_url}/api/v1/policies", headers=owner)["policies"]) == 1

        status, headers, stream = _http(f"{base_url}/api/v1/stream?once=1", headers={"Cookie": cookie})
        assert status == 200 and "text/event-stream" in headers["Content-Type"]
        assert "event: snapshot" in stream.decode()
        assert _http(f"{base_url}/api/v1/session/logout", "POST", {}, browser_headers)[0] == 200
        assert _http(f"{base_url}/api/v1/overview", headers={"Cookie": cookie})[0] == 401
    finally:
        server.shutdown()
