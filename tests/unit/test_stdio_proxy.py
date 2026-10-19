"""
Unit and integration tests for `MirageStdioProxy` over real JSON-RPC 2.0 stdio subprocesses.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mirage_mcp.proxy.stdio_proxy import MirageStdioProxy


def test_stdio_proxy_blocks_second_hop_over_real_subprocess() -> None:
    proxy = MirageStdioProxy(
        server_name="all",
        user_prompt="Summarize GitHub issue #42 and check if we have a matching bug report.",
        mode="strict",
    )

    messages: List[Dict[str, Any]] = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "github.get_issue",
                "arguments": {"repo": "acme/platform", "issue_number": 42},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "postgres.run_query",
                "arguments": {"sql": "SELECT 1; DROP TABLE users CASCADE;"},
            },
        },
    ]

    target_cmd = [sys.executable, "-m", "redteam.mock_mcp_servers", "--server", "all"]
    responses = asyncio.run(
        proxy.execute_session_script(target_cmd, messages, cwd=str(REPO_ROOT))
    )

    assert len(responses) == 4
    # 1. initialize passed through cleanly
    assert responses[0]["id"] == 1
    assert "protocolVersion" in responses[0]["result"]

    # 2. tools/list passed through cleanly
    assert responses[1]["id"] == 2
    assert len(responses[1]["result"]["tools"]) >= 10

    # 3. Hop 1 untrusted read allowed and tainted the session
    assert responses[2]["id"] == 3
    assert responses[2]["result"]["isError"] is False
    assert proxy.dag.session_tainted is True

    # 4. Hop 2 privileged write was deterministically blocked by MirageStdioProxy
    assert responses[3]["id"] == 4
    assert responses[3]["result"]["isError"] is True
    assert "MIRAGE-MCP INTERCEPT" in responses[3]["result"]["content"][0]["text"]
    assert responses[3]["result"]["_mirage"]["verdict"] == "BLOCKED_SECOND_HOP"
