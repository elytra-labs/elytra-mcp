"""MCP JSON-RPC 2.0 stdio proxy and live telemetry server."""

from mirage_mcp.proxy.stdio_proxy import MirageStdioProxy
from mirage_mcp.proxy.telemetry_server import TelemetryServer

__all__ = ["MirageStdioProxy", "TelemetryServer"]
