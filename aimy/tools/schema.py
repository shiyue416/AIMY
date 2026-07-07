"""Tool schemas — JSON Schema (OpenAI function-calling format) for all tools.

Includes:
  - 17 agent.py tools (recon, vuln_scan, js_analysis, secret_hunt, etc.)
  - 4 built-in tools (terminal, read_file, write_file, web_search)
  - Shell tool auto-wrapping support
"""

BUILTIN_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "terminal",
            "description": "Run a shell command and return stdout+stderr. Use for: recon, scanning, file ops, git. Timeout: 60s.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "workdir": {"type": "string", "description": "Working directory"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 60},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file with line numbers. Supports offset/limit for large files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute or relative file path"},
                    "offset": {"type": "integer", "description": "Start line (0-indexed)"},
                    "limit": {"type": "integer", "description": "Max lines to return", "default": 200},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file. Creates parent directories automatically. Overwrites existing files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to write"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for CVE details, exploit PoCs, technology documentation, or any information needed during a hunt.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query string"},
                    "limit": {"type": "integer", "description": "Max results", "default": 10},
                },
                "required": ["query"],
            },
        },
    },
]

# ── Security tools (from agent.py TOOLS) ─────────────────────────
SECURITY_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_recon",
            "description": "Run full subdomain enumeration + live host discovery on a target domain. Requires a target domain. Use FIRST when recon data doesn't exist. DO NOT call without a target domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain to recon (REQUIRED)"},
                    "scope_lock": {"type": "boolean", "description": "Only probe exact target, skip subdomain enum", "default": False},
                    "max_urls": {"type": "integer", "description": "Max URLs to collect", "default": 100},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vuln_scan",
            "description": "Run vulnerability scanner: nuclei templates + custom checks for CVEs, misconfigs, exposed panels, default creds, takeover candidates. Returns finding count by severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "quick": {"type": "boolean", "description": "Fast subset of templates only", "default": False},
                    "full": {"type": "boolean", "description": "All templates including slow ones", "default": False},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_js_analysis",
            "description": "Download and analyze JavaScript files from recon. Extracts: API keys, secrets, internal endpoints, GraphQL schemas, auth-bypass hints.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secret_hunt",
            "description": "Scan for leaked secrets: TruffleHog on JS/git repos, hardcoded AWS/GCP/Azure keys, API tokens, private keys.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_param_discovery",
            "description": "Discover hidden GET/POST parameters using arjun/paramspider on all live hosts. Returns new parameterized URLs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {"type": "string", "description": "Session cookies for authenticated pages", "default": ""},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_fuzz",
            "description": "Fuzz API endpoints for IDOR, auth bypass, privilege escalation. Tests REST + GraphQL + gRPC.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cors_check",
            "description": "Test live hosts for CORS misconfigurations: null origin, wildcard with credentials, trusted subdomain bypass.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cms_exploit",
            "description": "Run CMS-specific exploits: Drupalgeddon, WordPress plugin vulns, Joomla RCE, Magento SQLi. Use when CMS detected.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_rce_scan",
            "description": "Scan for RCE vectors: Log4Shell, Tomcat PUT upload, JBoss admin, SSTI, Shellshock. Use when Java/Tomcat/JBoss/Struts detected.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_targeted",
            "description": "Run sqlmap against parameterized URLs found in recon. Tests error-based, boolean-blind, time-blind, UNION injection.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_on_file",
            "description": "Run sqlmap against a specific saved HTTP request file (Burp-style). For POST endpoints needing manual SQLi testing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "request_file": {"type": "string", "description": "Path to raw HTTP request file"},
                    "level": {"type": "integer", "description": "sqlmap level 1-5", "default": 5},
                    "risk": {"type": "integer", "description": "sqlmap risk 1-3", "default": 3},
                },
                "required": ["request_file"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_jwt_audit",
            "description": "Audit JWT tokens: algorithm confusion, weak HMAC cracking, forged claims. Use when JWT tokens found.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_recon_summary",
            "description": "Read and summarize current recon data: live hosts, tech stack, URLs, CMS detections. Use to refresh context before deciding next action.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_findings_summary",
            "description": "Read and summarize all findings so far. Returns severity breakdown, top findings, suggested exploit chains.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_working_memory",
            "description": "Update your running notes about this target. Call after significant discoveries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "notes": {"type": "string", "description": "Updated notes about target, findings, next priorities."},
                },
                "required": ["notes"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Signal hunt complete. Call when high-priority tools have run or time budget exhausted.",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "description": "Brief summary: findings, what's worth reporting."},
                },
                "required": ["verdict"],
            },
        },
    },
]

# ── WAF/Bypass tools ─────────────────────────────────────────────
WAF_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_bypass_403",
            "description": "Test header/method/encoding bypass techniques against a 403/401 URL. Uses byp4xx matrix.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL returning 403/401"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_waf_analysis",
            "description": "Analyze WAF behavior: detect WAF type, encode payloads to bypass rules, test response variations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL behind WAF"},
                    "payload": {"type": "string", "description": "Payload to test encoding variants for", "default": "' OR 1=1--"},
                },
                "required": ["url"],
            },
        },
    },
]

# ── Asset expansion tools (six-dimensions) ────────────────────────
ASSET_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_asn_discovery",
            "description": "ASN-to-IP-range-to-domain reverse mapping. Discover assets via network ownership.",
            "parameters": {
                "type": "object",
                "properties": {
                    "org": {"type": "string", "description": "Organization name"},
                    "domain": {"type": "string", "description": "Target domain for ASN lookup"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_favicon_hunt",
            "description": "Discover hidden assets via favicon hash association (FOFA + Shodan).",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to extract favicon from"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_js_sourcemap",
            "description": "Recover TypeScript source from .js.map files. Extract endpoints, secrets, internal hosts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "recon_dir": {"type": "string", "description": "Recon directory with JS files"},
                },
                "required": ["recon_dir"],
            },
        },
    },
]


def get_all_tools() -> list[dict]:
    """Return complete tool schema list (21 tools)."""
    all_tools = []
    all_tools.extend(BUILTIN_TOOLS)
    all_tools.extend(SECURITY_TOOLS)
    all_tools.extend(WAF_TOOLS)
    all_tools.extend(ASSET_TOOLS)
    return all_tools


def get_tool_names() -> set[str]:
    return {t["function"]["name"] for t in get_all_tools()}
