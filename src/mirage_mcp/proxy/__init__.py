"""MCP JSON-RPC 2.0 stdio proxy and live telemetry server."""

__all__ = ["MirageStdioProxy", "TelemetryServer"]


def __getattr__(name):
    # Imported on first use, so a hook that only needs host sessions starts fast.
    if name == "MirageStdioProxy":
        from mirage_mcp.proxy.stdio_proxy import MirageStdioProxy
        return MirageStdioProxy
    if name == "TelemetryServer":
        from mirage_mcp.proxy.telemetry_server import TelemetryServer
        return TelemetryServer
    raise AttributeError(name)
