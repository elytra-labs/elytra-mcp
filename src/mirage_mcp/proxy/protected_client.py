"""Supported Python MCP integration: every call is authorized before dispatch.

The trusted orchestrator starts an explicit run. This transport only receives
its scoped client; it cannot classify tools, create grants, or approve itself.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import time
import uuid
from typing import Any


class ExecutionBlocked(RuntimeError):
    def __init__(self, decision: dict):
        self.decision = decision
        super().__init__(decision.get("reason", "Execution was not authorized"))


class ExecutionUncertain(RuntimeError):
    """The request may have reached the server. It must never be auto-retried."""


class ProtectedMCPClient:
    def __init__(self, client, server_id: str, command: list[str], *, timeout: float = 30,
                 approval_timeout: float = 120) -> None:
        if not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("A nonempty MCP server command is required")
        self.client, self.server_id, self.command = client, server_id, command
        self.timeout, self.approval_timeout = timeout, approval_timeout
        self._process = None
        self._reader_task = None
        self._pending: dict[str, asyncio.Future] = {}
        self._send_lock = asyncio.Lock()
        self._tools: dict[str, dict] = {}
        self._available: set[str] = set()
        self._next_id = 0

    async def __aenter__(self):
        self._process = await asyncio.create_subprocess_exec(*self.command, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=1024 * 1024 + 1, start_new_session=True,
            env={key: value for key, value in os.environ.items() if key not in {"ELYTRA_RUN_TOKEN", "ELYTRA_OWNER_TOKEN"}})
        self._reader_task = asyncio.create_task(self._read())
        try:
            await self._rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "elytra-protected-python", "version": "0.4.0a2"}})
            await self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            await self.list_tools()
        except BaseException:
            await self.close()
            raise
        return self

    async def _send(self, message: dict) -> None:
        data = (json.dumps(message, allow_nan=False) + "\n").encode()
        if len(data) > 1024 * 1024:
            raise ValueError("MCP message exceeds the 1 MiB limit")
        async with self._send_lock:
            if self._process is None or self._process.stdin is None:
                raise RuntimeError("MCP transport is closed")
            self._process.stdin.write(data)
            await self._process.stdin.drain()

    async def _read(self) -> None:
        try:
            while True:
                line = await self._process.stdout.readline()
                if not line:
                    raise ConnectionError("MCP server disconnected")
                if len(line) > 1024 * 1024:
                    raise ValueError("MCP message exceeds the 1 MiB limit")
                response = json.loads(line)
                if not isinstance(response, dict):
                    raise ValueError("MCP responses must be JSON objects")
                if "method" in response:
                    # This integration does not advertise sampling or elicitation.
                    if "id" in response:
                        await self._send({"jsonrpc": "2.0", "id": response["id"],
                            "error": {"code": -32601, "message": "Client capability not supported"}})
                    continue
                future = self._pending.get(str(response.get("id")))
                if future is not None and not future.done():
                    future.set_result(response)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            for pending in list(self._pending.values()):
                if not pending.done():
                    pending.set_exception(exc)

    async def _rpc(self, method: str, params: dict | None = None) -> Any:
        self._next_id += 1
        request_id = str(self._next_id)
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
            response = await asyncio.wait_for(future, timeout=self.timeout)
            if "error" in response:
                raise RuntimeError("MCP server returned a protocol error")
            if "result" not in response:
                raise RuntimeError("MCP response did not include a result")
            return response["result"]
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                await self._send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": request_id}})
            raise
        finally:
            self._pending.pop(request_id, None)

    async def list_tools(self) -> dict:
        tools, cursor = [], None
        for _ in range(20):
            result = await self._rpc("tools/list", {"cursor": cursor} if cursor else {})
            batch = result.get("tools") if isinstance(result, dict) else None
            if not isinstance(batch, list):
                raise ValueError("Server supplied an invalid tools/list response")
            tools.extend(batch)
            if len(tools) > 1000:
                raise ValueError("At most 1000 tool definitions are supported")
            cursor = result.get("nextCursor")
            if not cursor: break
        else:
            raise ValueError("Too many tool discovery pages")
        records = await asyncio.to_thread(self.client.register_tools, self.server_id, tools)
        self._tools = {tool["name"]: tool for tool in tools}
        available = {record["tool_name"] for record in records if record.get("available")}
        self._available = available
        # Unknown and suspicious descriptions cannot be exposed to the agent.
        return {"tools": [record["tool_definition"] for record in records if record["tool_name"] in available],
                "review_required": len(tools) - len(available)}

    async def call_tool(self, tool_name: str, arguments: dict | None = None) -> Any:
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be an object")
        # Refresh declared schemas at the pre-execution boundary, not just at startup.
        await self.list_tools()
        if tool_name not in self._available:
            raise ExecutionBlocked({"decision": "BLOCK", "reason": "Tool is absent, unclassified, or its metadata requires operator review"})
        call_id = "call_" + uuid.uuid4().hex
        claimed = False
        try:
            decision = await asyncio.to_thread(self.client.evaluate, self.server_id, tool_name, arguments, call_id)
            deadline = time.monotonic() + self.approval_timeout
            while decision["decision"] == "STEP_UP":
                if time.monotonic() >= deadline:
                    await asyncio.to_thread(self.client.cancel, call_id)
                    raise ExecutionBlocked({**decision, "reason": "Approval timed out; no tool call was dispatched"})
                await asyncio.sleep(.25)
                decision = await asyncio.to_thread(self.client.call_status, call_id)
            if decision["decision"] != "ALLOW":
                raise ExecutionBlocked(decision)
            # An operator may have reviewed for minutes: re-observe the actual
            # destination metadata immediately before the durable dispatch claim.
            await self.list_tools()
            if tool_name not in self._available:
                await asyncio.to_thread(self.client.cancel, call_id)
                raise ExecutionBlocked({"decision": "BLOCK", "reason": "Tool inventory changed while approval was pending"})
            claim = await asyncio.to_thread(self.client.claim, call_id, decision["permit"], arguments)
            claimed = True
            result = await self._rpc("tools/call", {"name": tool_name, "arguments": claim["arguments"]})
            return await asyncio.to_thread(self.client.complete, call_id, result, bool(isinstance(result, dict) and result.get("isError")))
        except BaseException as exc:
            if claimed:
                # Failure after claim is not evidence that an external mutation did not occur.
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(self.client.mark_uncertain, call_id, "Transport ended after dispatch; inspect destination before retrying")
                if isinstance(exc, asyncio.CancelledError): raise
                raise ExecutionUncertain("Call outcome is uncertain. Automatic retry is forbidden; inspect the destination.") from exc
            if not isinstance(exc, ExecutionBlocked):
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(self.client.cancel, call_id)
            raise

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
        if self._process:
            if self._process.stdin:
                self._process.stdin.close()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=2)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self._process.pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(self._process.pid, signal.SIGKILL)
                    await self._process.wait()
            # The launcher may exit before its descendants. Reap its isolated
            # process group as well; no caller processes share that group.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self._process.pid, signal.SIGKILL)
            self._process = None

    async def __aexit__(self, *_):
        await self.close()
