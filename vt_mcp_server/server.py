"""A complete MCP server in one file, standard library only.

Speaks JSON-RPC 2.0 over stdio, newline-delimited, which is all the MCP stdio
transport requires. Exposes two tools backed by the real VirusTotal public API:

  lookup_hash(sha256)  - detections, threat label, first-seen, permalink
  vt_quota()           - how much of the free tier is left, without spending any

Only the hash is ever sent. Files never leave this machine. Responses are cached on
disk, and a client-side throttle keeps you inside the free tier's 4 lookups/minute.

Try it by hand:
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python vt_mcp_server/server.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from triagelab import intel  # noqa: E402

SERVER_NAME = "virustotal"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "lookup_hash",
        "description": (
            "Look up a SHA256 file hash on VirusTotal. Returns detection counts, the "
            "suggested threat label, file type, first-submission date and a permalink. "
            "Only the hash is sent - never the file. Free tier: 4 lookups/minute."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sha256": {"type": "string", "description": "Lowercase hex SHA256 of the file."},
                "refresh": {
                    "type": "boolean",
                    "description": "Bypass the local cache and spend a live lookup.",
                    "default": False,
                },
            },
            "required": ["sha256"],
        },
    },
    {
        "name": "vt_quota",
        "description": "Report remaining VirusTotal free-tier quota without making a lookup.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def tool_lookup_hash(arguments: dict) -> str:
    digest = str(arguments.get("sha256", "")).strip().lower()
    if not digest:
        return "Error: sha256 argument is required."

    result = intel.lookup(digest, use_cache=not arguments.get("refresh", False))

    if result.status == intel.STATUS_OK:
        lines = [
            f"detections: {result.detection_ratio}",
            f"threat_label: {result.threat_label or 'none'}",
            f"type: {result.type_description or 'unknown'}",
            f"first_seen: {result.first_submission or 'unknown'}",
            f"reputation: {result.reputation}",
            f"permalink: {result.permalink}",
            f"source: VirusTotal{' (cached)' if result.cached else ' (live)'}",
        ]
        if result.names:
            lines.insert(3, f"known_names: {', '.join(result.names)}")
        return "\n".join(lines)

    return f"{result.status}: {result.message}"


def tool_vt_quota(_: dict) -> str:
    quota = intel.quota_status()
    key_state = "configured" if intel.vt_api_key() else "MISSING - set VT_API_KEY in .env"
    return (
        f"api_key: {key_state}\n"
        f"this_minute: {quota['calls_last_minute']}/{quota['calls_per_minute']}\n"
        f"today: {quota['used_today']}/{quota['daily_quota']}\n"
        f"retry_after_s: {quota['retry_after']}"
    )


HANDLERS = {"lookup_hash": tool_lookup_hash, "vt_quota": tool_vt_quota}


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
        handler = HANDLERS.get(params.get("name"))
        if handler is None:
            return error(msg_id, -32602, f"Unknown tool: {params.get('name')}")
        text = handler(params.get("arguments") or {})
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
