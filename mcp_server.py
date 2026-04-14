#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal stdio MCP server for Mini-HIDS.
"""

import json
import sys
from typing import Any, Dict

from hids_cli import ban_ip, ensure_runtime, get_alerts, get_blacklist, get_status, unban_ip


SERVER_INFO = {"name": "mini-hids", "version": "1.2.0"}
PROTOCOL_VERSION = "2025-06-18"


TOOLS = [
    {
        "name": "mini_hids_status",
        "description": "Get daemon, load, firewall backend, and runtime file status.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "mini_hids_get_alerts",
        "description": "Read recent alert log lines from Mini-HIDS.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "minimum": 1, "maximum": 500, "default": 10}
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "mini_hids_get_blacklist",
        "description": "List currently active blacklist entries.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "mini_hids_ban_ip",
        "description": "Ban an IP address using the configured firewall backend.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["ip", "reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mini_hids_unban_ip",
        "description": "Unban an IP address using the configured firewall backend.",
        "inputSchema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
            "additionalProperties": False,
        },
    },
]


def _response(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_result(payload: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
        "structuredContent": payload,
        "isError": is_error,
    }


def _handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "mini_hids_status":
        return _tool_result(get_status())
    if name == "mini_hids_get_alerts":
        lines = arguments.get("lines", 10)
        return _tool_result(get_alerts(lines))
    if name == "mini_hids_get_blacklist":
        return _tool_result(get_blacklist())
    if name == "mini_hids_ban_ip":
        result = ban_ip(arguments["ip"], arguments["reason"])
        return _tool_result(result, is_error=not result.get("success", False))
    if name == "mini_hids_unban_ip":
        result = unban_ip(arguments["ip"])
        return _tool_result(result, is_error=not result.get("success", False))
    raise KeyError(name)


def _handle_request(message: Dict[str, Any]) -> Dict[str, Any]:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})

    if method == "initialize":
        return _response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "ping":
        return _response(request_id, {})

    if method == "tools/list":
        return _response(request_id, {"tools": TOOLS})

    if method == "tools/call":
        try:
            name = params["name"]
            arguments = params.get("arguments", {})
            return _response(request_id, _handle_tool_call(name, arguments))
        except KeyError as exc:
            return _error(request_id, -32602, "Unknown tool: {}".format(exc.args[0]))
        except Exception as exc:
            return _response(
                request_id,
                _tool_result({"success": False, "message": str(exc)}, is_error=True),
            )

    if request_id is None:
        return {}

    return _error(request_id, -32601, "Method not found: {}".format(method))


def main() -> None:
    ensure_runtime()

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        response = _handle_request(message)
        if response:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
