"""A complete MCP server in one file, standard library only.

Speaks JSON-RPC 2.0 over stdio, newline-delimited, which is all the MCP stdio
transport requires. Exposes one tool, `lookup_hash`, backed by intel_db.json.

Everything it returns is FABRICATED for a teaching lab. It is not real threat
intelligence and must never be presented as such.

Run it by hand:
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python mock_intel_server/server.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SERVER_NAME = "mock-intel"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"
DB_PATH = Path(__file__).with_name("intel_db.json")

TOOLS = [
    {
        "name": "lookup_hash",
        "description": (
            "Look up a SHA256 file hash in the lab's mock threat-intel corpus. "
            "Returns a fabricated verdict, family, first-seen date and confidence. "
            "Teaching data only - never real intelligence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sha256": {
                    "type": "string",
                    "description": "Lowercase hex SHA256 of the file to look up.",
                }
            },
            "required": ["sha256"],
        },
    }
]


def load_db() -> dict:
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def lookup_hash(arguments: dict) -> str:
    digest = str(arguments.get("sha256", "")).strip().lower()
    if not digest:
        return "Error: sha256 argument is required."

    record = load_db().get(digest)
    if record is None:
        return (
            f"UNKNOWN - {digest[:16]}... is not in the mock corpus.\n"
            "No verdict available. Do not speculate about this sample."
        )

    return (
        f"verdict: {record['verdict']}\n"
        f"family: {record['family']}\n"
        f"first_seen: {record['first_seen']}\n"
        f"confidence: {record['confidence']}\n"
        f"context: {record['context']}\n"
        f"source: mock corpus (fabricated teaching data)"
    )


def handle(message: dict) -> dict | None:
    """Return a JSON-RPC response, or None for notifications."""
    method = message.get("method")
    msg_id = message.get("id")

    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }
    elif method in ("notifications/initialized", "initialized"):
        return None
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method in ("resources/list", "prompts/list"):
        result = {"resources": []} if method.startswith("resources") else {"prompts": []}
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        if name != "lookup_hash":
            return error(msg_id, -32602, f"Unknown tool: {name}")
        text = lookup_hash(params.get("arguments") or {})
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        if msg_id is None:
            return None
        return error(msg_id, -32601, f"Method not found: {method}")

    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
