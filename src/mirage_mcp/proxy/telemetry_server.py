"""
Lightweight local asyncio HTTP + Server-Sent Events (SSE) telemetry server
for streaming live `TelemetryEvent` packets to the `blast_radius.html` visualizer.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from mirage_mcp.visualizer import serialize_blast_radius_payload


class TelemetryServer:
    """
    Zero-dependency asyncio HTTP + SSE server bound to `127.0.0.1:8765`.
    Endpoints:
      - `GET /`            -> Current topology JSON snapshot
      - `GET /api/graph`   -> Current `blast_radius_graph.json` payload
      - `GET /api/events`  -> Real-time SSE stream of `TelemetryEvent` objects
    """

    def __init__(
        self,
        graph_data: Optional[Dict[str, Any]] = None,
        host: str = "127.0.0.1",
        port: int = 8765,
    ) -> None:
        self.graph_data: Dict[str, Any] = graph_data or {}
        self.host = host
        self.port = port
        self._subscribers: List[asyncio.Queue[Dict[str, Any]]] = []
        self._server: Optional[asyncio.AbstractServer] = None

    def broadcast_event(self, evt: Dict[str, Any]) -> None:
        """Broadcast a runtime telemetry event to all connected SSE clients."""
        live_events = self.graph_data.setdefault("live_events", [])
        if isinstance(live_events, list):
            live_events.append(evt)
        for q in list(self._subscribers):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                pass

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            if not request_line:
                writer.close()
                return
            parts = request_line.decode("utf-8", errors="ignore").strip().split(" ")
            path = parts[1] if len(parts) >= 2 else "/"

            # Consume HTTP headers
            while True:
                hdr = await reader.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break

            if path.startswith("/api/graph"):
                body = json.dumps(self.graph_data).encode("utf-8")
                headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json; charset=utf-8\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("utf-8")
                writer.write(headers + body)
                await writer.drain()
                writer.close()
                return

            if path.startswith("/api/events"):
                headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Connection: keep-alive\r\n\r\n"
                ).encode("utf-8")
                writer.write(headers)
                await writer.drain()

                queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=128)
                self._subscribers.append(queue)
                try:
                    while True:
                        evt = await queue.get()
                        sse_chunk = f"data: {json.dumps(evt)}\n\n".encode("utf-8")
                        writer.write(sse_chunk)
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    if queue in self._subscribers:
                        self._subscribers.remove(queue)
                    writer.close()
                return

            payload_bytes = serialize_blast_radius_payload(self.graph_data).encode("utf-8")
            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(payload_bytes)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(headers + payload_bytes)
            await writer.drain()
            writer.close()
        except Exception:
            try:
                writer.close()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
