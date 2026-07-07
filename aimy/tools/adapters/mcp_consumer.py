"""MCP Consumer — connect to external MCP servers (Burp, Fiddler, Playwright).

Discovers tools from connected MCP servers and makes them available
to the ToolRunner alongside native tools.

Supported transports: SSE, stdio

Usage:
    consumer = MCPConsumer()
    consumer.connect("burp", "http://127.0.0.1:9876/", transport="sse")
    tools = consumer.list_tools("burp")
"""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any


class MCPConsumer:
    """Client for consuming external MCP tools."""

    def __init__(self):
        self._servers: dict[str, dict] = {}      # name -> config
        self._tools: dict[str, dict] = {}         # server_name -> {tool_name: schema}

    # ── Connection management ─────────────────────────────────────

    def connect_sse(self, name: str, url: str, headers: dict[str, str] | None = None) -> bool:
        """Connect to an MCP server via SSE transport."""
        self._servers[name] = {
            "type": "sse",
            "url": url,
            "headers": headers or {},
        }
        return True  # actual connection is lazy (on first tool call)

    def connect_stdio(self, name: str, command: str, args: list[str]) -> bool:
        """Connect to an MCP server via stdio transport."""
        self._servers[name] = {
            "type": "stdio",
            "command": command,
            "args": args,
        }
        return True

    def disconnect(self, name: str) -> None:
        self._servers.pop(name, None)
        self._tools.pop(name, None)

    @property
    def connected_servers(self) -> list[str]:
        return list(self._servers.keys())

    # ── Tool discovery ────────────────────────────────────────────

    def list_tools(self, server_name: str) -> list[dict]:
        """List all tools from a connected MCP server."""
        if server_name not in self._servers:
            return []

        # Return cached tools if already discovered
        if server_name in self._tools:
            return list(self._tools[server_name].values())

        # Try to discover via JSON-RPC initialize + tools/list
        cfg = self._servers[server_name]
        try:
            if cfg["type"] == "sse":
                tools = self._discover_sse(cfg)
            elif cfg["type"] == "stdio":
                tools = self._discover_stdio(cfg)
            else:
                tools = []
        except Exception:
            tools = []

        self._tools[server_name] = {t["name"]: t for t in tools}
        return tools

    def _discover_sse(self, cfg: dict) -> list[dict]:
        """Discover tools from SSE MCP server."""
        import urllib.request
        import re

        url = cfg["url"]
        headers = {"Accept": "text/event-stream", **cfg.get("headers", {})}

        # Step 1: GET SSE endpoint to get session ID
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception:
            # Try with a short timeout
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=2) as resp:
                body = resp.read(1024).decode("utf-8", errors="replace")

        # Extract session ID from "event: endpoint\ndata: ?sessionId=xxx"
        sid_match = re.search(r'sessionId=([a-f0-9-]+)', body)
        if not sid_match:
            return []
        session_id = sid_match.group(1)

        # Step 2: POST tools/list
        msg_url = f"{url}messages?sessionId={session_id}" if "/sse" in url else \
                  url.replace("/sse", f"/messages?sessionId={session_id}") if "/sse" in url else \
                  f"{url.rstrip('/')}/messages?sessionId={session_id}"

        # Reconstruct message URL from the endpoint
        endpoint_match = re.search(r'/messages\?sessionId=[a-f0-9-]+', body)
        if endpoint_match:
            msg_path = endpoint_match.group(0)
            base = url.rsplit("/", 1)[0] if "/" in url else url
            msg_url = f"http://127.0.0.1:{_get_port(url)}{msg_path}"

        body_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        req2 = urllib.request.Request(
            msg_url,
            data=json.dumps(body_data).encode("utf-8"),
            headers={"Content-Type": "application/json", **cfg.get("headers", {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req2, timeout=5) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            return result.get("result", {}).get("tools", [])
        except Exception:
            return []

    def _discover_stdio(self, cfg: dict) -> list[dict]:
        """Discover tools from stdio MCP server."""
        # For now, return empty — stdio discovery requires persistent process
        return []

    # ── Tool execution ────────────────────────────────────────────

    def call_tool(self, server_name: str, tool_name: str, arguments: dict) -> str | None:
        """Call a tool on a specific MCP server. Returns result text or None."""
        if server_name not in self._servers:
            return None

        cfg = self._servers[server_name]
        try:
            if cfg["type"] == "sse":
                return self._call_sse(cfg, tool_name, arguments)
            elif cfg["type"] == "stdio":
                return self._call_stdio(cfg, tool_name, arguments)
        except Exception as e:
            return f"[MCP ERROR] {server_name}/{tool_name}: {e}"
        return None

    def _call_sse(self, cfg: dict, tool_name: str, arguments: dict) -> str | None:
        """Call a tool via SSE MCP transport (simplified)."""
        # For a real implementation, this would maintain persistent SSE sessions
        # For now, return None to indicate "try other dispatch methods"
        return None

    def _call_stdio(self, cfg: dict, tool_name: str, arguments: dict) -> str | None:
        return None

    def call_tool_any(self, tool_name: str, arguments: dict) -> str | None:
        """Try calling a tool on any connected server. Returns first successful result."""
        for server_name in self._servers:
            result = self.call_tool(server_name, tool_name, arguments)
            if result:
                return result
        return None


def _get_port(url: str) -> int:
    """Extract port from URL."""
    import re
    m = re.search(r':(\d+)/', url)
    return int(m.group(1)) if m else 80
