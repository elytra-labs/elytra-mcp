"""
High-speed asyncio JSON-RPC 2.0 stdio wiretap & second-hop taint interceptor for MCP servers.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from mirage_mcp.graph.taint_dag import RuntimeTaintGraph


class MirageStdioProxy:
    """
    Intercepts JSON-RPC 2.0 MCP traffic over stdio between an AI Agent Client
    and an underlying MCP Server subprocess.

    - Transparently forwards `initialize`, `notifications/*`, `resources/*`, `prompts/*`, `ping`.
    - Inspects `tools/list` responses to register tool metadata with `RuntimeTaintGraph`.
    - Intercepts `tools/call`:
      * Pre-execution: runs `dag.verify_hop2_call(...)` in <1.5ms.
      * If blocked (and mode != "audit"), returns a valid JSON-RPC 2.0 response with
        `result.isError = True` and a deterministic explanation without invoking the sink.
      * Post-execution: runs `dag.record_hop1_response(...)` on the returned tool content
        to track untrusted Hop 1 taint.
    """

    def __init__(
        self,
        server_name: str = "mcp",
        user_prompt: str = "",
        mode: str = "strict",
        dag: Optional[RuntimeTaintGraph] = None,
        telemetry_log_path: Optional[str | Path] = None,
        on_telemetry_event: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.server_name = server_name
        self.mode = mode.lower()
        strict_topology = self.mode in ("strict", "step-up")
        self.dag = dag or RuntimeTaintGraph(
            user_prompt=user_prompt,
            strict_topology=strict_topology,
        )
        self.telemetry_log_path = Path(telemetry_log_path) if telemetry_log_path else None
        self.on_telemetry_event = on_telemetry_event
        # Maps JSON-RPC request ID -> (server_name, tool_name,Method)
        self._pending_calls: Dict[Any, Tuple[str, str, str]] = {}

    def _emit_telemetry(self, evt: Dict[str, Any]) -> None:
        if self.telemetry_log_path:
            try:
                with self.telemetry_log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(evt) + "\n")
            except Exception:
                pass
        if self.on_telemetry_event:
            try:
                self.on_telemetry_event(evt)
            except Exception:
                pass

    def _split_tool_name(self, raw_tool_name: str) -> Tuple[str, str]:
        if "." in raw_tool_name:
            srv, tl = raw_tool_name.split(".", 1)
            return srv, tl
        return self.server_name, raw_tool_name

    def handle_client_message(
        self, raw_msg: Dict[str, Any]
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Evaluate an outbound JSON-RPC 2.0 message from the AI Agent Client.
        Returns `(forward_to_server, immediate_client_response)`.
        """
        method = raw_msg.get("method", "")
        msg_id = raw_msg.get("id")

        if method == "tools/list" and msg_id is not None:
            self._pending_calls[msg_id] = (self.server_name, "", "tools/list")
            return True, None

        if method == "tools/call":
            params = raw_msg.get("params") or {}
            raw_tool_name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            srv, tool_name = self._split_tool_name(raw_tool_name)
            args_json = (
                json.dumps(arguments, sort_keys=True)
                if not isinstance(arguments, str)
                else arguments
            )
            call_id = f"call_{msg_id}" if msg_id is not None else "call_notify"

            allowed, reason, evt = self.dag.verify_hop2_call(
                call_id=call_id,
                server=srv,
                tool_name=tool_name,
                arguments_json=args_json,
            )
            self._emit_telemetry(evt)

            if not allowed and self.mode != "audit":
                blocked_response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "isError": True,
                        "content": [
                            {
                                "type": "text",
                                "text": f"[MIRAGE-MCP INTERCEPT] {reason}",
                            }
                        ],
                        "_mirage": evt,
                    },
                }
                return False, blocked_response

            if msg_id is not None:
                self._pending_calls[msg_id] = (srv, tool_name, "tools/call")
            return True, None

        # All other JSON-RPC messages (initialize, notifications/*, resources/*, prompts/*) pass through untouched
        return True, None

    def handle_server_message(self, raw_msg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspect an inbound JSON-RPC 2.0 response from the underlying MCP Server
        before forwarding it back to the AI Agent Client.
        """
        msg_id = raw_msg.get("id")
        if msg_id is None or msg_id not in self._pending_calls:
            return raw_msg

        srv, tool_name, method = self._pending_calls.pop(msg_id)
        result = raw_msg.get("result")
        if not isinstance(result, dict):
            return raw_msg

        if method == "tools/list":
            tools = result.get("tools", [])
            if isinstance(tools, list):
                for t in tools:
                    if isinstance(t, dict):
                        t_name = str(t.get("name", ""))
                        t_desc = str(t.get("description", ""))
                        s_name, clean_name = self._split_tool_name(t_name)
                        self.dag.register_tool_metadata(s_name, clean_name, t_desc)
            return raw_msg

        if method == "tools/call":
            content_items = result.get("content", [])
            extracted_texts: List[str] = []
            if isinstance(content_items, list):
                for item in content_items:
                    if isinstance(item, dict) and "text" in item:
                        extracted_texts.append(str(item["text"]))
                    elif isinstance(item, str):
                        extracted_texts.append(item)
            payload_text = "\n".join(extracted_texts) if extracted_texts else json.dumps(result)
            evt = self.dag.record_hop1_response(
                call_id=f"resp_{msg_id}",
                server=srv,
                tool_name=tool_name,
                response_payload=payload_text,
            )
            self._emit_telemetry(evt)

        return raw_msg

    async def execute_session_script(
        self,
        target_cmd: List[str],
        client_messages: List[Dict[str, Any]],
        cwd: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Spawn an underlying MCP stdio server subprocess, feed a sequence of JSON-RPC
        client messages through the Mirage wiretap, and return all JSON-RPC responses
        received by the client.
        """
        proc = await asyncio.create_subprocess_exec(
            *target_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        responses: List[Dict[str, Any]] = []
        try:
            for msg in client_messages:
                should_forward, immediate_resp = self.handle_client_message(msg)
                if not should_forward:
                    if immediate_resp is not None:
                        responses.append(immediate_resp)
                    continue

                line_out = (json.dumps(msg) + "\n").encode("utf-8")
                proc.stdin.write(line_out)
                await proc.stdin.drain()

                # Notifications (no id) do not produce a server response
                if msg.get("id") is None:
                    continue

                raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
                if not raw_line:
                    break
                server_msg = json.loads(raw_line.decode("utf-8"))
                processed_resp = self.handle_server_message(server_msg)
                responses.append(processed_resp)
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()

        return responses

    async def run_stdio_forever(self, target_cmd: List[str]) -> int:
        """
        Run the live stdio proxy loop between `sys.stdin`/`sys.stdout` and `target_cmd`.
        """
        proc = await asyncio.create_subprocess_exec(
            *target_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        async def client_to_server() -> None:
            while True:
                line = await reader.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    msg = json.loads(text)
                except json.JSONDecodeError:
                    proc.stdin.write(line)
                    await proc.stdin.drain()
                    continue

                should_forward, immediate_resp = self.handle_client_message(msg)
                if not should_forward:
                    if immediate_resp is not None:
                        sys.stdout.write(json.dumps(immediate_resp) + "\n")
                        sys.stdout.flush()
                    continue

                proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
                await proc.stdin.drain()

            try:
                proc.stdin.close()
            except Exception:
                pass

        async def server_to_client() -> None:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    msg = json.loads(text)
                    processed = self.handle_server_message(msg)
                    sys.stdout.write(json.dumps(processed) + "\n")
                    sys.stdout.flush()
                except json.JSONDecodeError:
                    sys.stdout.write(text + "\n")
                    sys.stdout.flush()

        await asyncio.gather(client_to_server(), server_to_client())
        return await proc.wait()
