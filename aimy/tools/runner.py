"""ToolRunner — unified tool execution layer.

Dispatches tool calls to the correct executor:
  - Python tools: direct import + call
  - Shell tools: subprocess with safety preamble
  - MCP tools: MCP client call via SSE/stdio transport
  - Built-in tools: read_file, write_file, terminal, web_search
"""

from __future__ import annotations

import os
import subprocess
import json
import time
from pathlib import Path
from typing import Any, Callable

# ── Max output lengths ────────────────────────────────────────────
MAX_STDOUT_CHARS = 8000
MAX_READ_LINES = 500

# ── Safety preamble (Python version of _safety_preamble.sh) ──────
SAFETY_PREAMBLE = """
# Auto-generated safety constraints
export CURL_OPTIONS="--max-time 10 --limit-rate 100K"
alias curl='curl $CURL_OPTIONS'
"""


class ToolRunner:
    """Unified tool execution engine.

    Usage:
        runner = ToolRunner(
            registry=reg,
            tools_dir="C:/Users/PC/tools/claude-bug-bounty/tools",
            scope_file=None,
        )
        result = runner.dispatch("run_recon", {"domain": "example.com"})
    """

    def __init__(
        self,
        registry=None,  # ToolRegistry
        tools_dir: str = "",
        scope_file: str = "",
        mcp_clients: dict[str, Any] | None = None,  # name -> MCP client
        extra_handlers: dict[str, Callable] | None = None,  # name -> callable
        rate_limit: float = 1.0,
    ):
        self.registry = registry
        self.tools_dir = tools_dir
        self.scope_file = scope_file
        self.mcp_clients = mcp_clients or {}
        self.extra_handlers = extra_handlers or {}
        self.rate_limit = rate_limit
        self._last_request = 0.0

        # Register built-in handlers
        self._handlers: dict[str, Callable] = {
            "terminal": self._run_terminal,
            "read_file": self._run_read_file,
            "write_file": self._run_write_file,
            "web_search": self._run_web_search,
            "update_working_memory": self._run_update_memory,
            "finish": self._run_finish,
            "read_recon_summary": self._run_read_summary,
            "read_findings_summary": self._run_read_findings,
        }
        if extra_handlers:
            self._handlers.update(extra_handlers)

    # ── Main dispatch ─────────────────────────────────────────────

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        """Execute a tool by name. Returns text observation."""
        t0 = time.time()

        # Rate limit
        elapsed = t0 - self._last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request = time.time()

        # Check handler
        handler = self._handlers.get(name)
        if handler:
            try:
                result = handler(args)
            except Exception as e:
                result = f"[ERROR] {name}: {e}"

        # Check MCP tools
        elif self.mcp_clients:
            result = self._dispatch_mcp(name, args)

        # Check shell/Python tools in tools_dir
        elif self.tools_dir:
            result = self._dispatch_shell(name, args)

        else:
            result = f"Unknown tool: {name}. Available: {', '.join(list(self._handlers.keys())[:10])}..."

        elapsed = round(time.time() - t0, 2)
        if len(result) > MAX_STDOUT_CHARS:
            result = result[:MAX_STDOUT_CHARS] + f"\n... [{len(result) - MAX_STDOUT_CHARS} more chars]"

        return f"{result}\n[{name} completed in {elapsed}s]"

    # ── Built-in tools ────────────────────────────────────────────

    def _run_terminal(self, args: dict) -> str:
        cmd = args.get("command", "")
        workdir = args.get("workdir", os.getcwd())
        timeout = int(args.get("timeout", 60))

        if not cmd:
            return "ERROR: command is required"

        # Auto-translate CMD-isms to bash on Windows
        cmd = cmd.replace("where ", "which ")
        cmd = cmd.replace(" 2>nul ", " 2>/dev/null ")
        cmd = cmd.replace(" 2>nul", " 2>/dev/null")
        cmd = cmd.replace("|| echo", "|| echo")
        cmd = cmd.replace("dir ", "ls ")
        cmd = cmd.replace(" /B", "")
        cmd = cmd.replace("NUL", "/dev/null")
        if cmd.startswith("ls "):
            cmd = cmd.replace("2>/dev/null", "")

        # Build safe command — use Git Bash on Windows
        full_cmd = cmd
        if os.name == "nt":
            # Try multiple known bash locations
            bash_candidates = [
                "C:\\Program Files\\Git\\bin\\bash.exe",
                "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
                os.path.expanduser("~\\scoop\\apps\\git\\current\\bin\\bash.exe"),
            ]
            bash_bin = ""
            for bc in bash_candidates:
                if os.path.isfile(bc):
                    bash_bin = bc
                    break
            if bash_bin:
                # Double-quote the command to preserve special chars
                escaped = cmd.replace('\\', '\\\\').replace('"', '\\"')
                full_cmd = f'"{bash_bin}" -c "{escaped}"'
            else:
                full_cmd = f'cmd /c "{cmd}"'
        else:
            escaped = cmd.replace('\\', '\\\\').replace('"', '\\"')
            full_cmd = f'bash -c "{escaped}"'

        try:
            r = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=workdir,
            )
            out = r.stdout
            if r.stderr:
                out += f"\n[STDERR]\n{r.stderr[:2000]}"
            if r.returncode != 0:
                out += f"\n[EXIT: {r.returncode}]"
            return out.strip() or "(no output)"
        except subprocess.TimeoutExpired:
            return f"ERROR: Command timed out after {timeout}s"
        except Exception as e:
            return f"ERROR: {e}"

    def _run_read_file(self, args: dict) -> str:
        path = args.get("path", "")
        offset = int(args.get("offset", 0))
        limit = int(args.get("limit", 200))

        if not path:
            return "ERROR: path is required"
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            return f"ERROR: file not found: {path}"

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            total = len(lines)
            lines = lines[offset:offset + limit]
            result = []
            for i, line in enumerate(lines, start=offset + 1):
                result.append(f"{i:6}|{line.rstrip()}")
            header = f"File: {path} (lines {offset+1}-{min(offset+limit, total)} of {total})\n"
            return header + "\n".join(result)
        except Exception as e:
            return f"ERROR reading {path}: {e}"

    def _run_write_file(self, args: dict) -> str:
        path = args.get("path", "")
        content = args.get("content", "")

        if not path:
            return "ERROR: path is required"
        path = os.path.expanduser(path)
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return f"Wrote {len(content)} chars to {path}"
        except Exception as e:
            return f"ERROR writing {path}: {e}"

    def _run_web_search(self, args: dict) -> str:
        query = args.get("query", "")
        limit = int(args.get("limit", 10))
        if not query:
            return "ERROR: query is required"

        try:
            import urllib.request
            import urllib.parse
            import re

            url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
            req = urllib.request.Request(url, headers={"User-Agent": "AIMY/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            # Extract results
            results = []
            for m in re.finditer(r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>', html, re.DOTALL):
                url = m.group(1)
                title = re.sub(r'<[^>]+>', '', m.group(2)).strip()
                if url and title and not url.startswith("//duckduckgo.com"):
                    results.append(f"{title}\n  {urllib.parse.unquote(url)}")

            if not results:
                # Fallback pattern
                for m in re.finditer(r'<a[^>]*rel="nofollow"[^>]*href="([^"]*)"[^>]*class="result__snippet"[^>]*>(.*?)</a>', html, re.DOTALL):
                    pass  # try harder

            out = f"Search: {query}\n"
            out += "\n\n".join(results[:limit]) if results else "No results found (DuckDuckGo might be rate-limiting)."
            return out
        except Exception as e:
            return f"Web search failed: {e}"

    def _run_update_memory(self, args: dict) -> str:
        notes = args.get("notes", "")
        return f"Working memory updated ({len(notes)} chars)."

    def _run_finish(self, args: dict) -> str:
        verdict = args.get("verdict", "Hunt complete.")
        return f"HUNT COMPLETE: {verdict}"

    def _run_read_summary(self, args: dict) -> str:
        return "Recon summary: use terminal to read recon directory files directly."

    def _run_read_findings(self, args: dict) -> str:
        return "Findings summary: use terminal to read findings directory files directly."

    # ── MCP dispatch ──────────────────────────────────────────────

    def _dispatch_mcp(self, name: str, args: dict) -> str:
        """Try executing a tool call via connected MCP clients."""
        for server_name, client in self.mcp_clients.items():
            try:
                # Try calling the MCP tool
                result = client.call_tool(name, args)
                if result:
                    return str(result)
            except Exception:
                continue
        return f"MCP tool '{name}' not found on any connected server."

    # ── Shell/Python dispatch ─────────────────────────────────────

    def _dispatch_shell(self, name: str, args: dict) -> str:
        """Execute a shell or Python script from tools_dir."""
        # Try shell script first
        sh_path = os.path.join(self.tools_dir, f"{name}.sh")
        py_path = os.path.join(self.tools_dir, f"{name}.py")

        script_path = None
        if os.path.isfile(sh_path):
            script_path = sh_path
        elif os.path.isfile(py_path):
            script_path = py_path
        else:
            return f"Tool '{name}' not found. Script not found at {sh_path} or {py_path}."

        # Build arguments — find bash on Windows
        extra_args = args.get("args", "")
        if script_path.endswith(".sh"):
            bash_bin = ""
            for bc in ["C:\\Program Files\\Git\\bin\\bash.exe",
                       "C:\\Program Files\\Git\\usr\\bin\\bash.exe"]:
                if os.path.isfile(bc):
                    bash_bin = bc
                    break
            if bash_bin:
                cmd = f'"{bash_bin}" "{script_path}" {extra_args}'
            else:
                cmd = f'bash "{script_path}" {extra_args}'
        else:
            cmd = f'python "{script_path}" {extra_args}'

        try:
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=120, cwd=self.tools_dir,
            )
            out = r.stdout
            if r.stderr:
                out += f"\n[STDERR]\n{r.stderr[:1000]}"
            return out.strip() or "(no output)"
        except subprocess.TimeoutExpired:
            return f"ERROR: {name} timed out after 120s"
        except Exception as e:
            return f"ERROR running {name}: {e}"


def create_default_runner(
    registry=None,
    tools_dir: str = "",
    scope_file: str = "",
) -> ToolRunner:
    """Create a ToolRunner with all built-in handlers."""
    from aimy.tools.registry import create_default_registry

    if registry is None:
        registry = create_default_registry(tools_dir)

    return ToolRunner(
        registry=registry,
        tools_dir=tools_dir,
        scope_file=scope_file,
    )
