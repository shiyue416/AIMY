"""Orchestrator — ties Skills + Tools + ReAct Loop + Memory together.

The main entry point for running a hunt: loads relevant skills,
assembles context, selects tools, runs the agent loop, and records results.
"""

from __future__ import annotations

import os
import re
import time
import json
from datetime import datetime
from typing import Any, Callable

from aimy.core.loop import ReActLoop
from aimy.core.state import AgentState
from aimy.llm.client import LLMClient
from aimy.tools.registry import ToolRegistry, create_default_registry
from aimy.tools.runner import ToolRunner, create_default_runner
from aimy.skills.loader import SkillLoader
from aimy.skills.registry import SkillRegistry
from aimy.skills.router import SkillRouter
from aimy.skills.formatter import SkillFormatter


class Orchestrator:
    """Top-level coordinator that wires everything together.

    Usage:
        orch = Orchestrator(
            skills_dir="C:/Users/PC/tools/claude-bug-bounty/skills",
            tools_dir="C:/Users/PC/tools/claude-bug-bounty/tools",
        )
        result = orch.run("hunt example.com for IDOR vulnerabilities")
    """

    def __init__(
        self,
        skills_dir: str = "",
        tools_dir: str = "",
        references_dir: str = "",
        provider: str | None = None,
        model: str = "",
        max_turns: int = 30,
        time_budget: int = 3600,
        verbose: bool = True,
    ):
        self.skills_dir = skills_dir
        self.tools_dir = tools_dir
        self.references_dir = references_dir
        self.verbose = verbose

        # LLM
        self.client = LLMClient(provider)
        self.model = model

        # Skills — auto-discover all available sources
        self.skill_loader = SkillLoader()
        # Auto-discover skill sources relative to project root
        _project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        _default_dirs = [
            os.path.join(_project_root, "skills"),              # 101 attack skills
            os.path.join(_project_root, "anthropic-skills"),    # 818 defense/forensics
            os.path.join(_project_root, "claude-extra-skills"), # 16 custom fusion skills
        ]
        if skills_dir and os.path.isdir(skills_dir):
            self.skill_loader.add_source(skills_dir, "internal")
        for d in _default_dirs:
            if os.path.isdir(d):
                self.skill_loader.add_source(d, "external")
        self.skill_registry = SkillRegistry()
        self.skill_router = SkillRouter(self.skill_registry)
        self.skill_formatter = SkillFormatter()

        # Tools
        self.tool_registry = create_default_registry(tools_dir) if tools_dir else create_default_registry()
        self.tool_runner = create_default_runner(self.tool_registry, tools_dir)

        # Register security tool handlers (claude-bug-bounty scripts)
        try:
            from aimy.tools.adapters.security_tools import register_all
            register_all(self.tool_runner)
        except Exception:
            pass

        # References — 小十月 H1 reports, payloads, playbooks, dictionaries
        self.ref_loader = None
        self._init_references()

        # MCP Consumer — auto-connect BurpMCP + Fiddler
        self.mcp_consumer = None
        self._auto_connect_mcp()

        # Loop config
        self.max_turns = max_turns
        self.time_budget = time_budget

        # Memory (in-memory for now)
        self._findings: list[dict] = []
        self._patterns: list[dict] = []

        # Current target (injected into tool args automatically)
        self._current_target = ""

    # ── References init ──────────────────────────────────────────────

    def _init_references(self) -> None:
        """Index 小十月 references (H1 reports, payloads, playbooks, etc.)."""
        if self.references_dir and os.path.isdir(self.references_dir):
            try:
                from aimy.references.loader import ReferenceLoader
                self.ref_loader = ReferenceLoader(self.references_dir)
                count = self.ref_loader.index()
                if self.verbose:
                    cats = self.ref_loader.categories
                    cat_str = ", ".join(f"{k}:{v}" for k, v in cats.items())
                    print(f"[Orchestrator] References indexed: {count} files ({cat_str})")
            except Exception as e:
                if self.verbose:
                    print(f"[Orchestrator] References init skipped: {e}")

    # ── Multi-source skill loading ──────────────────────────────────

    def add_skill_source(self, directory: str, source_label: str = "external") -> None:
        """Add another skill directory (e.g. 小十月, anthropic-skills)."""
        if directory and os.path.isdir(directory):
            self.skill_loader.add_source(directory, source_label)
            if self.verbose:
                print(f"[Orchestrator] +skill source: {source_label} → {directory}")

    # ── MCP auto-connect ────────────────────────────────────────────

    def _auto_connect_mcp(self) -> None:
        """Auto-discover and connect to local MCP servers (Burp, Fiddler, Playwright)."""
        try:
            from aimy.tools.adapters.mcp_consumer import MCPConsumer
            self.mcp_consumer = MCPConsumer()

            # BurpMCP-Ultra (SSE port: 9876, HTTP port: 9877)
            burp_endpoints = [
                "http://127.0.0.1:9876/sse",
                "http://127.0.0.1:9444/mcp",
            ]
            for ep in burp_endpoints:
                try:
                    self.mcp_consumer.connect_sse("burp", ep)
                    tools = self.mcp_consumer.list_tools("burp")
                    if tools:
                        if self.verbose:
                            print(f"[Orchestrator] BurpMCP connected: {len(tools)} tools @ {ep}")
                        # Register Burp tools in tool_registry
                        for t in tools:
                            self.tool_registry.register_mcp_tool("burp", t)
                        break
                except Exception:
                    continue

            # Fiddler MCP
            try:
                self.mcp_consumer.connect_sse("fiddler", "http://127.0.0.1:8866/sse")
                ftools = self.mcp_consumer.list_tools("fiddler")
                if ftools and self.verbose:
                    print(f"[Orchestrator] Fiddler connected: {len(ftools)} tools")
                    for t in ftools:
                        self.tool_registry.register_mcp_tool("fiddler", t)
            except Exception:
                pass

        except ImportError:
            self.mcp_consumer = None
            if self.verbose:
                print("[Orchestrator] MCP consumer not available")

    # ── Main entry ────────────────────────────────────────────────

    def run(self, task: str, target: str = "",
            extra_context: str = "") -> dict[str, Any]:
        """Execute a full hunt for the given task.

        Returns: {
            "verdict": final agent response,
            "findings": [...],
            "state": AgentState.to_dict(),
            "stats": {...},
        }
        """
        # 1. Load and index skills
        if self.skill_registry.count == 0:
            skills = self.skill_loader.load_all()
            self.skill_registry.index(skills)
            if self.verbose:
                print(f"[Orchestrator] Indexed {self.skill_registry.count} skills")

        # 2. Route to relevant skills
        relevant = self.skill_router.relevant_skills(task, max_skills=5)
        if self.verbose:
            names = [s.name for s in relevant]
            print(f"[Orchestrator] Skills: {names}")

        # 2b. Find relevant references (H1 reports, playbooks, payloads)
        phase = self.skill_router._infer_phase(
            self.skill_router._extract_keywords(task)
        )
        ref_context = ""
        if self.ref_loader:
            vuln_class = self._infer_vuln_class(task)
            refs = self.ref_loader.find_relevant(
                task=task, phase=phase, vuln_class=vuln_class, max_results=5,
            )
            if refs:
                ref_context = self._format_ref_context(refs, vuln_class)
                if self.verbose:
                    ref_names = [r.title[:40] for r in refs]
                    print(f"[Orchestrator] References: {ref_names}")

        # 3. Build system prompt
        skill_text = self.skill_formatter.format(relevant, task)
        system_prompt = self._build_system_prompt(skill_text, phase, ref_context)

        # 4. Select tools for this phase (include search_references tool)
        tool_schemas = self.tool_registry.get_schemas_for_phase(phase)
        if self.ref_loader:
            tool_schemas.append(SEARCH_REFERENCES_SCHEMA)
        if len(tool_schemas) < 3:
            # Ensure at least built-in tools available
            tool_schemas = self.tool_registry.get_schemas()

        # 5. Create state
        target = target or self._extract_target(task)
        self._current_target = target  # for auto-injection into tool args
        state = AgentState(
            session_id=datetime.now().strftime("%Y%m%d-%H%M%S"),
            target=target,
            max_turns=self.max_turns,
            time_budget_seconds=self.time_budget,
            provider=self.client.provider,
            model=self.model,
        )

        # 6. Run the agent loop
        loop = ReActLoop(
            client=self.client,
            state=state,
            system_prompt=system_prompt,
            tools=tool_schemas,
            tool_executor=self._tool_executor,
            max_turns=self.max_turns,
            time_budget=self.time_budget,
            verbose=self.verbose,
        )
        verdict = loop.run(task, extra_context)

        # 7. Collect results
        mcp_tool_count = len(self.tool_registry.list_by_source("mcp"))
        mcp_servers = list(self.mcp_consumer._servers.keys()) if self.mcp_consumer else []

        return {
            "verdict": verdict,
            "findings": list(state.findings),
            "state": state.to_dict(),
            "stats": {
                "turns": state.turn,
                "tool_calls": state.tool_call_count,
                "tool_errors": state.tool_error_count,
                "elapsed": state.elapsed_seconds,
                "skills_loaded": [s.name for s in relevant],
                "phase": phase,
                "mcp_tools": mcp_tool_count,
                "mcp_servers": mcp_servers,
                "total_tools": self.tool_registry.tool_count,
            },
        }

    # ── Tool executor ─────────────────────────────────────────────

    def _tool_executor(self, name: str, args: dict[str, Any]) -> str:
        """Bridge from ReActLoop tool calls to ToolRunner.

        Auto-injects target/domain into security tool args if the LLM
        didn't provide them explicitly. Routes MCP tools to MCPConsumer.
        """
        # Security tools need domain/target — inject if missing
        if name.startswith("run_") and "domain" not in args and "target" not in args:
            if self._current_target:
                args = {**args, "domain": self._current_target}

        # Route MCP tools to appropriate MCP server
        entry = self.tool_registry.get(name)
        if entry and entry.source == "mcp":
            if self.mcp_consumer:
                result = self.mcp_consumer.call_tool_any(name, args)
                if result:
                    return result
            return f"[MCP] Tool '{name}' unavailable (no MCP connection)"

        # search_references — query H1 reports / playbooks / payloads
        if name == "search_references":
            return self._search_references_handler(args)

        return self.tool_runner.dispatch(name, args)

    # ── Reference helpers ──────────────────────────────────────────

    def _search_references_handler(self, args: dict[str, Any]) -> str:
        """Handle search_references tool call from the agent."""
        query = args.get("query", args.get("q", ""))
        category = args.get("category", "")
        max_results = int(args.get("max_results", 5))

        if not self.ref_loader:
            return "No reference library loaded. Set references_dir to 小十月skill/references."

        results = self.ref_loader.search(query, max_results=max_results)

        if category:
            results = [r for r in results if r.category == category]

        if not results:
            return f"No references found for: {query}"

        parts = []
        for i, r in enumerate(results, 1):
            parts.append(f"--- [{i}] {r.title} ({r.category}) ---")
            content = self.ref_loader.load_content(r, max_chars=2000)
            parts.append(content)
        return "\n\n".join(parts)

    def _infer_vuln_class(self, task: str) -> str:
        """Extract vulnerability class from task description."""
        t = task.lower()
        patterns = [
            ("ssrf", r"\bssrf\b|server.side.request"),
            ("sqli", r"\bsqli\b|sql.injection"),
            ("xss", r"\bxss\b|cross.site.script"),
            ("idor", r"\bidor\b|broken.object|direct.object.reference"),
            ("rce", r"\brce\b|remote.code|command.injection|cmdi"),
            ("ssti", r"\bssti\b|server.side.template"),
            ("xxe", r"\bxxe\b|xml.external"),
            ("lfi", r"\blfi\b|path.traversal|local.file"),
            ("csrf", r"\bcsrf\b|cross.site.request"),
            ("jwt", r"\bjwt\b|token.attack"),
            ("oauth", r"\boauth\b|oidc|saml"),
            ("race", r"\brace.condition|toctou"),
            ("upload", r"\bupload\b|file.upload"),
            ("logic", r"\blogic\b|business.logic"),
            ("smuggling", r"\bsmuggling\b|http.smuggling"),
            ("cache", r"\bcache\b|web.cache"),
            ("prompt", r"\bprompt.injection|llm|ai.ml"),
            ("proto", r"\bprototype.pollution"),
            ("deser", r"\bdeserial"),
        ]
        for vclass, pat in patterns:
            if re.search(pat, t):
                return vclass
        return ""

    def _format_ref_context(self, refs: list, vuln_class: str) -> str:
        """Format relevant references as context for the system prompt."""
        if not refs:
            return ""

        parts = ["\n## Reference Library (小十月)\n"]
        parts.append("The following real-world references are available. Use search_references(query=...) to get full details.\n")

        for i, r in enumerate(refs, 1):
            kw_tags = ", ".join(r.keywords[:6]) if r.keywords else "—"
            parts.append(f"{i}. [{r.category}] **{r.title}** — `{kw_tags}`")

        parts.append(f"\nTotal indexed: {self.ref_loader.total} files across {list(self.ref_loader.categories.keys())}")
        return "\n".join(parts)

    # ── General helpers ─────────────────────────────────────────────

    def _build_system_prompt(self, skill_text: str, phase: str,
                             ref_context: str = "") -> str:
        """Build the full system prompt."""
        base = DEFAULT_SYSTEM
        if skill_text:
            base += f"\n\n{skill_text}"
        if ref_context:
            base += f"\n\n{ref_context}"
        if phase:
            base += f"\n\nCurrent phase: {phase.upper()}"
        return base

    def _extract_target(self, task: str) -> str:
        """Try to extract a target domain from the task."""
        import re
        # Match domain patterns
        m = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)', task)
        return m.group(1) if m else ""


# ── Default system prompt ─────────────────────────────────────────
DEFAULT_SYSTEM = """You are AIMY — an autonomous AI bug bounty hunting agent with access to security tools.

You have:
- Reconnaissance tools (subdomain enum, live host discovery, JS analysis, param discovery)
- Vulnerability scanning tools (nuclei, custom checks, secret hunts)
- Exploitation tools (sqlmap, API fuzzing, CMS exploits, JWT audit, 403 bypass)
- File/terminal access for reading/writing data

Your workflow:
1. UNDERSTAND what the user wants to achieve
2. PLAN your approach based on the loaded skills above
3. EXECUTE tools methodically — one tool at a time
4. OBSERVE results and adapt
5. REPORT findings with clear severity and impact

Rules:
- NEVER run the same tool twice with the same arguments
- If a tool fails, try a different approach
- When recon is sparse, expand with wider tools
- Prioritize HIGH and CRITICAL findings
- Call finish() when done — with a clear verdict

Remember: you are hunting for REAL vulnerabilities with REAL impact. Theoretical bugs don't count.

Use search_references(query=...) to look up real HackerOne reports, payload collections, and attack playbooks from the reference library."""


# ── search_references tool schema ─────────────────────────────────
SEARCH_REFERENCES_SCHEMA = {
    "type": "function",
    "function": {
        "name": "search_references",
        "description": "Search the reference library (H1 reports, playbooks, payload collections, dictionaries). Use when you need real-world examples, payload ideas, or attack flow guidance.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query, e.g. 'SSRF to RCE', 'file upload bypass', 'XSS payload'",
                },
                "category": {
                    "type": "string",
                    "description": "Optional category filter: 'h1-reports', 'playbooks', 'payloader', 'methodology', 'dictionaries', 'templates'",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max results (default 5, max 10)",
                },
            },
            "required": ["query"],
        },
    },
}
