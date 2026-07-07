"""AIMY MCP Server — expose tools as Model Context Protocol server.

Usage:
    aimy-mcp                  # Start MCP server (stdio)
    aimy-mcp --port 9876      # Start with SSE on specific port
    aimy mcp-server           # From CLI
"""

from __future__ import annotations

import json
import sys
import os


def run_stdio_server(tools_dir: str = "", skills_dir: str = "") -> None:
    """Run AIMY as an MCP server over stdio (for Claude Code config)."""
    # Minimal MCP stdio server
    server_info = {
        "name": "aimy",
        "version": "0.1.0",
    }

    # Read JSON-RPC messages from stdin, write responses to stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method", "")
        req_id = request.get("id")

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": server_info,
                    "capabilities": {"tools": {}},
                },
            }
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": _get_tool_definitions()},
            }
        elif method == "tools/call":
            tool_name = request.get("params", {}).get("name", "")
            args = request.get("params", {}).get("arguments", {})
            result_text = _execute_tool_stdio(tool_name, args)
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": result_text}],
                },
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


def _get_tool_registry_and_runner():
    """Build the full tool registry with all sources."""
    import os
    from aimy.tools.registry import create_default_registry
    from aimy.tools.runner import create_default_runner
    from aimy.tools.adapters.security_tools import register_all

    # Scan all tool directories in the AIMY project + linked sources
    import os as _os
    tool_dirs = []
    # AIMY project's own tool directories
    for d in [
        "C:/Users/PC/aimy/security-tools",
        "C:/Users/PC/aimy/claude-extra-skills",
        "C:/Users/PC/tools/claude-bug-bounty/tools",
        "C:/Users/PC/Desktop/小十月skill/security-tools",
        "C:/Users/PC/Desktop/小十月skill/claude-extra-skills/pentest-agents/tools",
    ]:
        if _os.path.isdir(d) and d not in tool_dirs:
            tool_dirs.append(d)

    reg = create_default_registry(tool_dirs[0] if tool_dirs else "")
    for d in tool_dirs[1:]:
        reg.discover_shell_tools(d)

    runner = create_default_runner(registry=reg, tools_dir=tool_dirs[0] if tool_dirs else "")
    try:
        register_all(runner)
    except Exception:
        pass
    return reg, runner


def _get_tool_definitions() -> list[dict]:
    """Get all tool definitions including security tools and auto-discovered scripts."""
    reg, _ = _get_tool_registry_and_runner()
    tools = []
    for name in reg.list_all():
        entry = reg.get(name)
        if entry:
            tools.append({
                "name": entry.name,
                "description": entry.description,
                "inputSchema": entry.schema.get("function", {}).get("parameters", {"type": "object", "properties": {}}),
            })

    # Add knowledge-retrieval tools
    tools.append({
        "name": "search_skills",
        "description": "Search 900+ cybersecurity skills by keyword. Returns matching skill names and descriptions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g. 'XSS', 'SQL injection', 'recon')"},
                "limit": {"type": "integer", "description": "Max results", "default": 10},
            },
            "required": ["query"],
        },
    })
    tools.append({
        "name": "get_skill",
        "description": "Retrieve the full content of a specific security skill by name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Exact skill name (e.g. 'xss-cross-site-scripting')"},
            },
            "required": ["name"],
        },
    })
    tools.append({
        "name": "search_references",
        "description": "Search 3000+ H1 reports, payloads, and playbooks for real-world exploit examples.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "category": {"type": "string", "description": "Filter: h1-reports, payloads, playbooks, methodology, all", "default": "all"},
                "limit": {"type": "integer", "description": "Max results", "default": 10},
            },
            "required": ["query"],
        },
    })
    tools.append({
        "name": "list_skill_categories",
        "description": "List cybersecurity skill categories and their counts (XSS, SQLi, Recon, etc.).",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    })
    return tools


def _execute_tool_stdio(name: str, args: dict) -> str:
    """Execute a tool with full security handlers + knowledge tools."""
    # Knowledge tools
    if name == "search_skills":
        return _search_skills(args.get("query", ""), args.get("limit", 10))
    if name == "get_skill":
        return _get_skill(args.get("name", ""))
    if name == "search_references":
        return _search_references(args.get("query", ""), args.get("category", "all"), args.get("limit", 10))
    if name == "list_skill_categories":
        return _list_skill_categories()

    # Regular tools
    _, runner = _get_tool_registry_and_runner()
    return runner.dispatch(name, args)


def _search_skills(query: str, limit: int = 10) -> str:
    """Search skills by keyword."""
    from aimy.skills import SkillLoader, SkillRegistry, SkillRouter
    loader = SkillLoader()
    for d in ["C:/Users/PC/aimy/skills", "C:/Users/PC/aimy/anthropic-skills",
              "C:/Users/PC/aimy/claude-extra-skills"]:
        if os.path.isdir(d):
            loader.add_source(d, "internal")
    reg = SkillRegistry()
    reg.index(loader.load_all())
    router = SkillRouter(reg)
    skills = router.relevant_skills(query, max_skills=limit)
    results = [f"{s.name}: {s.description[:150]}" for s in skills]
    return f"Found {len(results)} matching skills:\n" + "\n".join(results)


def _get_skill(name: str) -> str:
    """Get full skill content by name."""
    from aimy.skills import SkillLoader, SkillRegistry
    loader = SkillLoader()
    for d in ["C:/Users/PC/aimy/skills", "C:/Users/PC/aimy/anthropic-skills",
              "C:/Users/PC/aimy/claude-extra-skills"]:
        if os.path.isdir(d):
            loader.add_source(d, "internal")
    reg = SkillRegistry()
    reg.index(loader.load_all())
    skill = reg.get(name)
    if skill:
        return f"# {skill.name}\n\n{skill.description}\n\n{skill.body[:5000]}"
    return f"Skill '{name}' not found. Use search_skills to find available skills."


def _search_references(query: str, category: str = "all", limit: int = 10) -> str:
    """Search reference files (H1 reports, payloads, playbooks)."""
    import glob as _glob
    results = []
    ref_dirs = []
    base = "C:/Users/PC/aimy/references"
    if category == "all" or category == "h1-reports":
        ref_dirs.append(f"{base}/h1-reports")
    if category == "all" or category == "payloads":
        ref_dirs.append(f"{base}/payloader")
    if category == "all" or category == "playbooks":
        ref_dirs.append(f"{base}/playbooks")

    for d in ref_dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    if query.lower() in content.lower():
                        size = os.path.getsize(fp)
                        results.append(f"{os.path.relpath(fp, base)} ({size}B)")
                except Exception:
                    pass
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break

    return f"Found {len(results)} matching references:\n" + "\n".join(results[:limit])


def _list_skill_categories() -> str:
    """List skill categories with counts."""
    from aimy.skills import SkillLoader, SkillRegistry
    from collections import Counter
    loader = SkillLoader()
    for d in ["C:/Users/PC/aimy/skills", "C:/Users/PC/aimy/anthropic-skills",
              "C:/Users/PC/aimy/claude-extra-skills"]:
        if os.path.isdir(d):
            loader.add_source(d, "internal")
    reg = SkillRegistry()
    reg.index(loader.load_all())
    cats = Counter()
    for skill in reg._skills.values():
        for phase in skill.phases:
            cats[phase] += 1
    return f"Skill categories:\n" + "\n".join(f"  {k}: {v} skills" for k, v in cats.most_common())


def main():
    """Entry point for aimy-mcp command."""
    import argparse
    parser = argparse.ArgumentParser(description="AIMY MCP Server")
    parser.add_argument("--port", type=int, help="Port for SSE mode (default: stdio)")
    parser.add_argument("--tools-dir", help="Additional tools directory")
    parser.add_argument("--skills-dir", help="Skills directory")
    args = parser.parse_args()

    if args.port:
        print(f"SSE mode on port {args.port} — not yet implemented. Use stdio mode.")
        sys.exit(1)
    else:
        run_stdio_server(args.tools_dir, args.skills_dir)


if __name__ == "__main__":
    main()
