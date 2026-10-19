"""Exercise the CLI tools-only bridge over real pipes and loopback HTTP."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sqlite3
import sys

from mirage_mcp.sdk import RuntimeClient
from mirage_mcp.server import ControlPlaneServer


ENDPOINT = r'''
import json, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("CREATE TABLE calls(method TEXT, arguments TEXT)")
connection.commit()
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    connection.execute("INSERT INTO calls VALUES(?, ?)", (method, json.dumps(message.get("params", {}))))
    connection.commit()
    if "id" not in message:
        continue
    response = {"jsonrpc": "2.0", "id": message["id"]}
    if method == "initialize":
        response["result"] = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "stdio-test-fixture", "version": "1"}}
    elif method == "tools/list":
        response["result"] = {"tools": [{"name": "read", "description": "Read fixture issue details", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        response["result"] = {"content": [{"type": "text", "text": "Fixture issue details"}], "isError": False, "arguments": message["params"]["arguments"]}
    else:
        # These methods are deliberately implemented here so the test detects
        # accidental forwarding through the tools-only protection boundary.
        response["result"] = {"unexpected_forwarding": True}
    print(json.dumps(response), flush=True)
connection.close()
'''


def test_cli_bridge_enforces_tools_only_and_survives_malformed_cancellation(tmp_path: Path):
    server = ControlPlaneServer(db_path=tmp_path / "runtime.db", port=0,
                               token_file=tmp_path / "unused-token", auth_token="owner-" + "x" * 48)
    base_url = server.start_background()
    owner = RuntimeClient(base_url, token="owner-" + "x" * 48)
    run = owner.run("Read the harmless fixture issue")
    endpoint = tmp_path / "endpoint.py"
    endpoint.write_text(ENDPOINT)
    ledger = tmp_path / "endpoint.db"
    environment = dict(os.environ)
    environment["ELYTRA_RUN_TOKEN"] = run.run_token
    repository = Path(__file__).resolve().parent.parent
    environment["PYTHONPATH"] = os.pathsep.join([str(repository / "src"), str(repository)])

    async def scenario():
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "mirage_mcp.cli.main", "proxy", "--server-name", "fixture",
            "--run-id", run.run_id, "--gateway", base_url, "--", sys.executable, str(endpoint), str(ledger),
            cwd=repository, env=environment, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        responses = []

        async def send(message):
            process.stdin.write((json.dumps(message) + "\n").encode())
            await process.stdin.drain()

        async def receive():
            line = await asyncio.wait_for(process.stdout.readline(), timeout=5)
            assert line, "CLI bridge exited without a JSON-RPC response"
            response = json.loads(line)
            assert response["jsonrpc"] == "2.0"
            responses.append(response)
            return response

        async def request(identifier, method, params=None):
            await send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}})
            response = await receive()
            assert response["id"] == identifier
            return response

        try:
            initialized = await request(1, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "integration-test", "version": "1"}})
            assert initialized["result"]["protocolVersion"] == "2025-03-26"
            assert set(initialized["result"]["capabilities"]) == {"tools"}
            await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            withheld = await request(2, "tools/list")
            assert withheld["result"] == {"tools": [], "review_required": 1}
            unknown_call = await request(3, "tools/call", {"name": "read", "arguments": {}})
            assert unknown_call["result"]["isError"] is True
            with sqlite3.connect(ledger) as connection:
                assert connection.execute("SELECT COUNT(*) FROM calls WHERE method='tools/call'").fetchone()[0] == 0

            records = await asyncio.to_thread(owner.list_tools)
            record = records["tools"][0]
            assert record["category"] == "UNKNOWN"
            await asyncio.to_thread(owner.classify_tool, "fixture", "read", record["observed_sha256_hash"], "SOURCE_UNTRUSTED")
            approved = await request(4, "tools/list")
            assert [tool["name"] for tool in approved["result"]["tools"]] == ["read"]
            result = await request(5, "tools/call", {"name": "read", "arguments": {"issue": 42}})
            assert result["result"]["arguments"] == {"issue": 42}
            assert result["result"]["isError"] is False
            with sqlite3.connect(ledger) as connection:
                arguments = [json.loads(row[0]) for row in connection.execute("SELECT arguments FROM calls WHERE method='tools/call'")]
            assert arguments == [{"name": "read", "arguments": {"issue": 42}}]

            for identifier, method in ((6, "resources/list"), (7, "prompts/list"), (8, "resources/read")):
                response = await request(identifier, method)
                assert response["error"]["code"] == -32601

            # Formerly these malformed notifications crashed the whole bridge.
            for params in (["invalid"], {"requestId": {}}, {"requestId": []}, {"requestId": True}):
                await send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": params})
                rejected = await receive()
                assert rejected["id"] is None and rejected["error"]["code"] == -32700
            assert (await request(9, "ping"))["result"] == {}

            # Concurrent requests share the same stdio stream; response IDs
            # remain correct even when task scheduling changes their order.
            await send({"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}})
            await send({"jsonrpc": "2.0", "id": "ping", "method": "ping", "params": {}})
            concurrent = [await receive(), await receive()]
            assert {response["id"] for response in concurrent} == {"list", "ping"}
            assert all("result" in response for response in concurrent)

            process.stdin.close()
            await process.stdin.wait_closed()
            assert await asyncio.wait_for(process.wait(), timeout=5) == 0
            trailing_output = await process.stdout.read()
            stderr = await process.stderr.read()
            assert trailing_output == b""
            leaked_credential = run.run_token.encode() in json.dumps(responses).encode() or run.run_token.encode() in stderr
            assert not leaked_credential, "The CLI unexpectedly emitted a scoped credential"
            assert b"Traceback" not in stderr
            with sqlite3.connect(ledger) as connection:
                forwarded = {row[0] for row in connection.execute("SELECT method FROM calls")}
            assert not ({"resources/list", "resources/read", "prompts/list"} & forwarded)
            events = await asyncio.to_thread(owner._request, "GET", "/api/v1/events")
            assert any(event["execution_status"] == "COMPLETED" for event in events["events"])
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
    try:
        asyncio.run(scenario())
    finally:
        server.shutdown()
