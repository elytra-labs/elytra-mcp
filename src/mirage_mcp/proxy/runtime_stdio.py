"""Tools-only MCP stdio bridge for an explicitly identified Elytra run.

The bridge advertises only capabilities it enforces. Prompts/resources/sampling
are not silently forwarded outside the policy boundary.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import sys

from mirage_mcp.proxy.protected_client import ProtectedMCPClient, ExecutionBlocked, ExecutionUncertain


async def run_runtime_proxy(client, server_id: str, command: list[str], approval_timeout: float = 120) -> int:
    tasks: dict[object, asyncio.Task] = {}
    output_lock = asyncio.Lock()

    async def send(message):
        async with output_lock:
            sys.stdout.write(json.dumps(message, allow_nan=False) + "\n")
            sys.stdout.flush()

    async with ProtectedMCPClient(client, server_id, command, approval_timeout=approval_timeout) as target:
        async def handle(message):
            request_id, method = message.get("id"), message.get("method")
            params = message.get("params") or {}
            if request_id is None:
                return
            try:
                if method == "initialize":
                    requested = params.get("protocolVersion", "2025-11-25")
                    version = requested if requested in {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"} else "2025-11-25"
                    result = {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "elytra-explicit-run-proxy", "version": "0.4.0a2"},
                        "instructions": "Only tools routed through this explicit run are covered. Unclassified tools require local operator review."}
                elif method == "ping": result = {}
                elif method == "tools/list": result = await target.list_tools()
                elif method == "tools/call":
                    if not isinstance(params.get("name"), str) or not isinstance(params.get("arguments", {}), dict):
                        raise ValueError("Invalid tool call")
                    result = await target.call_tool(params["name"], params.get("arguments", {}))
                else:
                    await send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601,
                        "message": "Only tool operations are supported by this protected integration"}})
                    return
                await send({"jsonrpc": "2.0", "id": request_id, "result": result})
            except ExecutionBlocked as exc:
                await send({"jsonrpc": "2.0", "id": request_id, "result": {"isError": True,
                    "content": [{"type": "text", "text": "Elytra did not dispatch this call: " + str(exc)}]}})
            except ExecutionUncertain:
                await send({"jsonrpc": "2.0", "id": request_id, "result": {"isError": True,
                    "content": [{"type": "text", "text": "Execution outcome is uncertain. Inspect the destination; do not automatically retry."}]}})
            except asyncio.CancelledError:
                await send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32800, "message": "Call cancelled"}})
            except Exception:
                await send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603,
                    "message": "Protected transport error; inspect the local runtime"}})
            finally:
                tasks.pop(request_id, None)

        reader = asyncio.StreamReader(limit=1024 * 1024 + 1)
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        try:
            while True:
                line = await reader.readline()
                if not line: break
                if len(line) > 1024 * 1024: raise ValueError("MCP message exceeds 1 MiB")
                try:
                    message = json.loads(line)
                    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0": raise ValueError("Invalid JSON-RPC message")
                    params = message.get("params", {})
                    if not isinstance(params, dict): raise ValueError("Message params must be an object")
                    cancel_id = params.get("requestId")
                    if message.get("method") == "notifications/cancelled" and (isinstance(cancel_id, bool) or not isinstance(cancel_id, (str, int))):
                        raise ValueError("Invalid cancellation request ID")
                    request_id = message.get("id")
                    if request_id is not None and (isinstance(request_id, bool) or not isinstance(request_id, (str, int))):
                        raise ValueError("Invalid request ID")
                except (ValueError, TypeError):
                    await send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON-RPC message"}})
                    continue
                if message.get("method") == "notifications/cancelled":
                    task = tasks.get((message.get("params") or {}).get("requestId"))
                    if task: task.cancel()
                elif request_id is not None:
                    if request_id in tasks:
                        await send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "Request ID already pending"}})
                    elif len(tasks) >= 64:
                        await send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "Too many concurrent requests"}})
                    else:
                        tasks[request_id] = asyncio.create_task(handle(message))
        finally:
            for task in list(tasks.values()): task.cancel()
            await asyncio.gather(*list(tasks.values()), return_exceptions=True)
    return 0
