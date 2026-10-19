"""Isolated JSON-RPC fixture endpoint. Only mutates its temporary SQLite ledger.

This is not a production MCP server and never accesses customer tools or networks.
"""
from __future__ import annotations
import json
from pathlib import Path
import sqlite3
import sys


def main() -> None:
    config = json.loads(Path(sys.argv[1]).read_text())
    db = sqlite3.connect(config["database"])
    db.execute("CREATE TABLE IF NOT EXISTS receipts (id INTEGER PRIMARY KEY, arguments TEXT, mutation INTEGER)")
    db.commit()
    for line in sys.stdin:
        request = json.loads(line)
        response = {"jsonrpc": "2.0", "id": request.get("id")}
        if request.get("method") == "tools/list":
            response["result"] = {"tools": [{"name": config["tool_name"], "inputSchema": {"type": "object"}}]}
        elif request.get("method") == "tools/call" and request.get("params", {}).get("name") == config["tool_name"]:
            args = request["params"].get("arguments", {})
            mutation = int(config["kind"] == "sink")
            db.execute("INSERT INTO receipts(arguments, mutation) VALUES (?, ?)", (json.dumps(args, sort_keys=True), mutation))
            db.commit()
            response["result"] = {"content": [{"type": "text", "text": config["payload"] if not mutation else "Fixture effect committed"}], "isError": False}
        else:
            response["error"] = {"code": -32601, "message": "Unknown fixture method/tool"}
        print(json.dumps(response), flush=True)
    db.close()


if __name__ == "__main__":
    main()
