"""ToolRegistry — unified index of all available tools.

Supports:
  - Built-in tools (terminal, read_file, write_file, web_search)
  - Security tools (recon, vuln_scan, secret_hunt, etc. — 17 tools)
  - WAF/Bypass tools (2 tools)
  - Asset expansion tools (4 tools)
  - Shell tools auto-discovered from tools/ directory
  - MCP tools auto-discovered from connected MCP servers (Burp/Fiddler/Playwright)
"""

from __future__ import annotations

import os
from typing import Any

from aimy.tools.tool_descriptions import TOOL_DESCRIPTIONS


class ToolEntry:
    """A single tool's metadata."""

    def __init__(
        self,
        name: str,
        description: str,
        schema: dict[str, Any],
        source: str = "builtin",      # "builtin" | "shell" | "python" | "mcp"
        category: str = "general",    # "general" | "recon" | "scan" | "exploit" | "report" | "asset"
        risk: str = "safe",           # "safe" | "caution" | "danger"
        phase: str = "any",           # "recon" | "map" | "find" | "prove" | "report" | "any"
        cost: str = "free",           # "free" | "cheap" | "paid"
    ):
        self.name = name
        self.description = description
        self.schema = schema
        self.source = source
        self.category = category
        self.risk = risk
        self.phase = phase
        self.cost = cost


class ToolRegistry:
    """Unified index of all tools available to the agent."""

    def __init__(self):
        self._tools: dict[str, ToolEntry] = {}
        self._by_category: dict[str, list[str]] = {}
        self._by_phase: dict[str, list[str]] = {}
        self._by_source: dict[str, list[str]] = {}

    # ── Registration ──────────────────────────────────────────────

    def register(self, entry: ToolEntry) -> None:
        """Add a tool to the registry."""
        self._tools[entry.name] = entry
        self._by_category.setdefault(entry.category, []).append(entry.name)
        self._by_phase.setdefault(entry.phase, []).append(entry.name)
        self._by_source.setdefault(entry.source, []).append(entry.name)

    def register_many(self, entries: list[ToolEntry]) -> None:
        for e in entries:
            self.register(e)

    def register_from_schema(self, schema: dict, source: str = "builtin",
                             category: str = "general", risk: str = "safe",
                             phase: str = "any") -> None:
        """Register from an OpenAI function-calling schema dict."""
        func = schema.get("function", {})
        entry = ToolEntry(
            name=func.get("name", ""),
            description=func.get("description", ""),
            schema=schema,
            source=source,
            category=category,
            risk=risk,
            phase=phase,
        )
        self.register(entry)

    # ── Discovery ─────────────────────────────────────────────────

    def discover_shell_tools(self, tools_dir: str) -> int:
        """Auto-discover shell scripts from a directory. Returns count added."""
        count = 0
        if not os.path.isdir(tools_dir):
            return 0
        for fn in sorted(os.listdir(tools_dir)):
            if not fn.endswith(".sh") and not fn.endswith(".py"):
                continue
            # Skip private/internal modules
            if fn.startswith("_") or fn.startswith("__"):
                continue
            fp = os.path.join(tools_dir, fn)
            if not os.path.isfile(fp):
                continue
            name = os.path.splitext(fn)[0]
            if name in self._tools:
                continue  # already registered
            source = "python" if fn.endswith(".py") else "shell"

            # Auto-categorize by filename
            category = self._guess_category(name)
            phase = self._guess_phase(name)

            # Look up human-readable description
            desc = TOOL_DESCRIPTIONS.get(name, "")
            if not desc:
                desc = TOOL_DESCRIPTIONS.get(name.replace("_", "-"), "")
            if not desc:
                desc = f"Security tool: {fn}"

            entry = ToolEntry(
                name=name,
                description=desc,
                schema={
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": f"Execute the {fn} {source} script.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "args": {"type": "string", "description": "Command-line arguments to pass to the script"},
                            },
                            "required": [],
                        },
                    },
                },
                source=source,
                category=category,
                risk="caution",
                phase=phase,
            )
            self.register(entry)
            count += 1
        return count

    def register_mcp_tool(self, server_name: str, tool: dict) -> bool:
        """Register a single MCP-discovered tool. Returns True if added."""
        name = tool.get("name", "")
        if not name or name in self._tools:
            return False
        entry = ToolEntry(
            name=name,
            description=tool.get("description", ""),
            schema={
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool.get("description", ""),
                    "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
                },
            },
            source="mcp",
            category=_guess_mcp_category(name),
            risk="caution",
            phase="any",
        )
        self.register(entry)
        return True

    def discover_mcp_tools(self, mcp_server_name: str, tools: list[dict]) -> int:
        """Register tools discovered from an MCP server. Returns count added."""
        count = 0
        for t in tools:
            name = t.get("name", "")
            if not name or name in self._tools:
                continue
            entry = ToolEntry(
                name=name,
                description=t.get("description", ""),
                schema={
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": t.get("description", ""),
                        "parameters": t.get("inputSchema", {"type": "object", "properties": {}}),
                    },
                },
                source="mcp",
                category=_guess_mcp_category(name),
                risk="caution",
                phase="any",
            )
            self.register(entry)
            count += 1
        return count

    # ── Query ─────────────────────────────────────────────────────

    def get(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def list_all(self) -> list[str]:
        return sorted(self._tools.keys())

    def list_by_category(self, category: str) -> list[str]:
        return self._by_category.get(category, [])

    def list_by_phase(self, phase: str) -> list[str]:
        return self._by_phase.get(phase, [])

    def list_by_source(self, source: str) -> list[str]:
        return self._by_source.get(source, [])

    def get_schemas(self, names: list[str] | None = None,
                    allowlist: list[str] | None = None) -> list[dict]:
        """Return tool schemas in OpenAI format, optionally filtered."""
        result = []
        for name, entry in self._tools.items():
            if allowlist and name not in allowlist:
                continue
            if names and name not in names:
                continue
            result.append(entry.schema)
        return result

    def get_schemas_for_phase(self, phase: str) -> list[dict]:
        """Return tools suitable for a hunt phase."""
        names = self.list_by_phase(phase) + self.list_by_phase("any")
        return self.get_schemas(allowlist=names)

    @property
    def tool_count(self) -> int:
        return len(self._tools)

    @property
    def categories(self) -> dict[str, int]:
        return {k: len(v) for k, v in self._by_category.items()}

    # ── Helpers ───────────────────────────────────────────────────

    def _guess_category(self, name: str) -> str:
        name_l = name.lower()
        if any(kw in name_l for kw in ("recon", "subdomain", "enum", "dns", "cdn", "csp", "asn")):
            return "recon"
        if any(kw in name_l for kw in ("scan", "vuln", "nuclei", "cve", "rce", "sqli", "xss", "ssrf")):
            return "scan"
        if any(kw in name_l for kw in ("fuzz", "bypass", "idor", "api", "inject")):
            return "exploit"
        if any(kw in name_l for kw in ("report", "validate", "triage")):
            return "report"
        if any(kw in name_l for kw in ("sourcemap", "favicon", "permut", "asset")):
            return "asset"
        if any(kw in name_l for kw in ("secret", "token", "cred", "leak")):
            return "secret"
        return "general"

    def _guess_phase(self, name: str) -> str:
        name_l = name.lower()
        if any(kw in name_l for kw in ("recon", "enum", "dns", "subdomain", "asn", "cdn", "csp", "favicon", "permut", "sourcemap")):
            return "recon"
        if any(kw in name_l for kw in ("scan", "vuln", "nuclei", "cve", "detect")):
            return "find"
        if any(kw in name_l for kw in ("fuzz", "bypass", "exploit", "sqli", "idor", "rce", "inject")):
            return "prove"
        if any(kw in name_l for kw in ("report", "validate", "triage")):
            return "report"
        return "any"


def _guess_mcp_category(name: str) -> str:
    """Guess category for MCP-discovered tools by name prefix."""
    n = name.lower()
    if any(kw in n for kw in ("proxy", "http", "request", "response", "repeater", "intruder", "scanner", "scan")):
        return "scan"
    if any(kw in n for kw in ("browser", "navigate", "click", "snapshot", "screenshot")):
        return "recon"
    if any(kw in n for kw in ("session", "fiddler", "list_session", "search_session")):
        return "recon"
    return "general"


def create_default_registry(tools_dir: str | None = None) -> ToolRegistry:
    """Create a ToolRegistry populated with all built-in and security tools."""
    from aimy.tools.schema import get_all_tools

    reg = ToolRegistry()

    # Register all schema-defined tools
    category_map = {
        "terminal": "general", "read_file": "general", "write_file": "general", "web_search": "general",
        "run_recon": "recon", "run_vuln_scan": "scan", "run_js_analysis": "recon",
        "run_secret_hunt": "secret", "run_param_discovery": "recon",
        "run_api_fuzz": "exploit", "run_cors_check": "scan", "run_cms_exploit": "exploit",
        "run_rce_scan": "scan", "run_sqlmap_targeted": "exploit", "run_sqlmap_on_file": "exploit",
        "run_jwt_audit": "exploit", "read_recon_summary": "recon", "read_findings_summary": "report",
        "update_working_memory": "general", "finish": "general",
        "run_bypass_403": "exploit", "run_waf_analysis": "exploit",
        "run_asn_discovery": "asset", "run_favicon_hunt": "asset", "run_js_sourcemap": "asset",
    }
    phase_map = {
        "run_recon": "recon", "run_asn_discovery": "recon", "run_favicon_hunt": "recon",
        "run_js_sourcemap": "recon", "run_param_discovery": "recon", "run_js_analysis": "recon",
        "run_vuln_scan": "find", "run_cors_check": "find", "run_rce_scan": "find",
        "run_secret_hunt": "find",
        "run_cms_exploit": "prove", "run_api_fuzz": "prove", "run_sqlmap_targeted": "prove",
        "run_sqlmap_on_file": "prove", "run_jwt_audit": "prove", "run_bypass_403": "prove",
        "run_waf_analysis": "prove",
        "read_findings_summary": "report", "finish": "report",
    }

    for schema in get_all_tools():
        name = schema["function"]["name"]
        reg.register(ToolEntry(
            name=name,
            description=schema["function"]["description"],
            schema=schema,
            source="builtin",
            category=category_map.get(name, "general"),
            risk="caution" if name.startswith("run_") and name not in ("read_recon_summary", "read_findings_summary", "update_working_memory") else "safe",
            phase=phase_map.get(name, "any"),
        ))

    # Auto-discover shell tools
    if tools_dir and os.path.isdir(tools_dir):
        reg.discover_shell_tools(tools_dir)

    return reg
