"""
burp_mcp_adapter.py — Burp MCP ↔ AIMY agent loop 全互通
Copy to: C:/Users/PC/Desktop/彦/aimy/tools/adapters/burp_mcp.py

用法: 在 aimy loop 启动前调用 register_burp_tools(runner)，所有 HTTP 请求走 Burp。
"""
from __future__ import annotations
from typing import Any, Callable, Optional

# ══════════════════════════════════════════════════════════════════
# 1. Burp MCP 工具 Schema（OpenAI function-calling 格式）
# ══════════════════════════════════════════════════════════════════

BURP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "burp_send_request",
            "description": "Send an HTTP request through Burp Suite proxy. Returns full response with headers, body, status, timing. REQUIRED for all web testing — never use raw curl.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL to request"},
                    "method": {"type": "string", "default": "GET", "description": "HTTP method"},
                    "headers": {"type": "string", "default": "{}", "description": "JSON object of extra headers"},
                    "body": {"type": "string", "description": "Request body for POST/PUT/PATCH"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_fuzz",
            "description": "Fuzz an HTTP request by injecting payloads at FUZZ keyword position. Returns all responses.",
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {"type": "string", "description": "Raw HTTP request with FUZZ marker"},
                    "host": {"type": "string", "description": "Target hostname"},
                    "port": {"type": "integer", "default": 443},
                    "use_tls": {"type": "boolean", "default": True},
                    "payloads": {"type": "string", "description": "Comma-separated payload strings"},
                },
                "required": ["request", "host"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_repeater",
            "description": "Send a request to Burp Repeater for manual review and resend.",
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {"type": "string", "description": "Raw HTTP request"},
                    "host": {"type": "string", "description": "Target hostname"},
                    "port": {"type": "integer", "default": 443},
                    "use_tls": {"type": "boolean", "default": True},
                    "tab_name": {"type": "string", "description": "Repeater tab label"},
                },
                "required": ["request", "host"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_oob_payload",
            "description": "Generate a Burp Collaborator OOB payload for blind SSRF/XSS detection. Returns a unique subdomain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "Collaborator client ID (create once, reuse)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_oob_poll",
            "description": "Poll for Collaborator interactions (DNS/HTTP/SMTP). Returns any triggered callbacks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "Collaborator client ID"},
                },
                "required": ["client_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_proxy_history",
            "description": "Search Burp proxy history for previously captured requests/responses. Useful for recon.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Filter by hostname"},
                    "path": {"type": "string", "description": "Filter by URL path"},
                    "limit": {"type": "integer", "default": 20},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_scan",
            "description": "Start an active audit (vulnerability scan) on a URL. Pro edition only.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to scan"},
                    "mode": {"type": "string", "default": "normal", "description": "light/normal/thorough"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_passive_intel",
            "description": "Scan proxy history for sensitive data: AWS keys, API tokens, JWTs, emails, internal IPs, 30+ patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_items": {"type": "integer", "default": 1000},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_analyze_request",
            "description": "Parse and analyze a raw HTTP request — extract method, URL, params, cookies, body, content-type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {"type": "string", "description": "Raw HTTP request string"},
                },
                "required": ["request"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_analyze_response",
            "description": "Parse and analyze a raw HTTP response — status, headers, cookies, body, MIME type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "response": {"type": "string", "description": "Raw HTTP response string"},
                },
                "required": ["response"],
            },
        },
    },
]


# ══════════════════════════════════════════════════════════════════
# 2. MCP 适配器 — 把 Claude Code 的 MCP 调用桥接到 tool_executor
# ══════════════════════════════════════════════════════════════════

class BurpMCPAdapter:
    """把 Burp MCP 工具适配为 aimy tool_executor 能用的格式。

    使用时传入一个 call_mcp 函数（主进程里调 Claude Code MCP 工具的那个函数）。

    用法:
        adapter = BurpMCPAdapter(call_mcp_func)
        runner.register(adapter.tool_schemas, adapter.dispatch)
    """

    # 工具名映射: burp_* → mcp__burp__*
    _TOOL_MAP: dict[str, str] = {}

    def __init__(self, call_mcp: Optional[Callable] = None):
        self._call_mcp = call_mcp
        self._collab_client_id: str = ""
        self._build_tool_map()

    def _build_tool_map(self):
        self._TOOL_MAP = {
            "burp_send_request":     "mcp__burp__http_send_request",
            "burp_fuzz":             "mcp__burp__http_fuzz",
            "burp_repeater":         "mcp__burp__repeater_send",
            "burp_oob_payload":      "mcp__burp__collaborator_generate_payload",
            "burp_oob_poll":         "mcp__burp__collaborator_poll",
            "burp_proxy_history":    "mcp__burp__proxy_history",
            "burp_scan":             "mcp__burp__scanner_start_audit",
            "burp_passive_intel":    "mcp__burp__passive_intel",
            "burp_analyze_request":  "mcp__burp__analyze_request",
            "burp_analyze_response": "mcp__burp__analyze_response",
        }

    def set_mcp_handler(self, call_mcp: Callable):
        """注入实际的 MCP 调用函数。"""
        self._call_mcp = call_mcp

    @property
    def tool_schemas(self) -> list[dict]:
        return BURP_TOOLS

    def dispatch(self, tool_name: str, args: dict[str, Any]) -> str:
        """aimy tool_executor 协议：根据 tool_name 调用对应的 Burp MCP。"""
        mcp_name = self._TOOL_MAP.get(tool_name)
        if not mcp_name:
            return f"[Burp] Unknown tool: {tool_name}"

        # ── 参数转换 ──────────────────────────────────────────────
        params = self._adapt_params(tool_name, dict(args))

        # ── 预处理：OOB Collaborator ─────────────────────────────
        if tool_name == "burp_oob_payload":
            if not self._collab_client_id:
                # 自动创建 collaborator client
                try:
                    result = self._call_mcp(
                        "mcp__burp__collaborator_create_client", {}
                    )
                    if isinstance(result, dict):
                        self._collab_client_id = result.get("clientId", "")
                except Exception:
                    pass
            params["client_id"] = self._collab_client_id

        if tool_name == "burp_oob_poll":
            params["client_id"] = self._collab_client_id

        # ── 调用 MCP ─────────────────────────────────────────────
        try:
            result = self._call_mcp(mcp_name, params) if self._call_mcp else None
        except Exception as e:
            return f"[Burp] MCP error: {e}"

        if result is None:
            return "[Burp] No MCP handler — running in preamble-only mode. Burp tools registered but not active."

        # ── 格式化输出 ───────────────────────────────────────────
        return self._format_result(tool_name, result)

    def _adapt_params(self, tool_name: str, args: dict) -> dict:
        """把 aimy agent 传的参数转换为 Burp MCP 期望的格式。"""
        out = {}

        if tool_name == "burp_send_request":
            out["url"] = args.get("url", "")
            out["method"] = args.get("method", "GET")
            headers = args.get("headers", "{}")
            if isinstance(headers, str):
                out["headers"] = headers
            else:
                import json as _json
                out["headers"] = _json.dumps(headers)
            if "body" in args:
                out["body"] = args["body"]
            # Set defaults
            out.setdefault("port", 443)
            out.setdefault("use_tls", True)

        elif tool_name == "burp_fuzz":
            out["request"] = args.get("request", "")
            out["host"] = args.get("host", "")
            out["port"] = int(args.get("port", 443))
            out["use_tls"] = bool(args.get("use_tls", True))
            payloads = args.get("payloads", "")
            if isinstance(payloads, str):
                out["payloads"] = [p.strip() for p in payloads.split(",")]
            else:
                out["payloads"] = list(payloads) if payloads else []

        elif tool_name == "burp_repeater":
            out["request"] = args.get("request", "")
            out["host"] = args.get("host", "")
            out["port"] = int(args.get("port", 443))
            out["use_tls"] = bool(args.get("use_tls", True))
            if "tab_name" in args:
                out["tab_name"] = args["tab_name"]

        elif tool_name in ("burp_oob_payload", "burp_oob_poll"):
            out = args  # pass through

        elif tool_name == "burp_proxy_history":
            out["limit"] = int(args.get("limit", 20))
            if "host" in args:
                out["host"] = args["host"]
            if "path" in args:
                out["path"] = args["path"]

        elif tool_name == "burp_scan":
            out["url"] = args.get("url", "")
            out["mode"] = args.get("mode", "normal")

        elif tool_name == "burp_passive_intel":
            out["max_items"] = int(args.get("max_items", 1000))

        elif tool_name == "burp_analyze_request":
            out["request"] = args.get("request", "")

        elif tool_name == "burp_analyze_response":
            out["response"] = args.get("response", "")

        else:
            out = args

        return out

    def _format_result(self, tool_name: str, result) -> str:
        """把 Burp MCP 返回格式化给 LLM 阅读。"""
        if not isinstance(result, dict) or "error" in result:
            return str(result)[:2000]

        if tool_name == "burp_send_request":
            return (
                f"Status: {result.get('status_code', '?')}\n"
                f"Headers: {str(result.get('response_headers', ''))[:500]}\n"
                f"Body (first 1500 chars):\n{str(result.get('response_body', ''))[:1500]}"
            )

        if tool_name == "burp_fuzz":
            responses = result if isinstance(result, list) else result.get("responses", [])
            lines = []
            for r in (responses or [])[:20]:
                if isinstance(r, dict):
                    lines.append(f"  [{r.get('status_code','?')}] len={r.get('response_length','?')}")
            return f"{len(lines)} responses:\n" + "\n".join(lines)

        if tool_name == "burp_oob_payload":
            return f"OOB payload: {result.get('payload', result)}"

        if tool_name == "burp_oob_poll":
            interactions = result.get("interactions", [])
            if not interactions:
                return "No OOB interactions yet."
            return f"{len(interactions)} interaction(s):\n" + str(interactions)[:1000]

        if tool_name == "burp_proxy_history":
            entries = result if isinstance(result, list) else result.get("entries", [])
            lines = []
            for e in (entries or [])[:30]:
                if isinstance(e, dict):
                    lines.append(f"  {e.get('method','?')} {e.get('url','?')} [{e.get('status_code','?')}]")
            return f"{len(lines)} proxy entries:\n" + "\n".join(lines)

        if tool_name == "burp_passive_intel":
            findings = result.get("findings", result)
            if isinstance(findings, list):
                return f"{len(findings)} intel hits:\n" + str(findings[:10])[:1500]
            return str(findings)[:1500]

        if tool_name == "burp_analyze_request":
            return (
                f"Method: {result.get('method','?')} {result.get('url','?')}\n"
                f"Params: {result.get('parameters', [])}\n"
                f"Cookies: {result.get('cookies', {})}\n"
                f"Headers: {result.get('headers', {})}"
                "".replace(str(result))[:1500]
            )

        return str(result)[:2000]


# ══════════════════════════════════════════════════════════════════
# 3. 一键注册 → aimy loop
# ══════════════════════════════════════════════════════════════════

def register_burp_tools(runner, call_mcp: Optional[Callable] = None):
    """把 Burp MCP 工具注册到 aimy tool runner。

    runner: ToolRunner 实例（from aimy.tools.runner）
    call_mcp: 可选的 MCP 调用函数，None 时降级为说明模式
    """
    adapter = BurpMCPAdapter(call_mcp=call_mcp)
    for schema in adapter.tool_schemas:
        name = schema["function"]["name"]
        runner.register_tool(name, schema, adapter.dispatch)
    return adapter
