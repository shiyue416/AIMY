"""ReActLoop — Think → Act → Observe → Repeat agent loop.

Usage:
    from aimy.core.loop import ReActLoop
    from aimy.llm.client import LLMClient
    from aimy.core.state import AgentState

    state = AgentState(target="example.com")
    client = LLMClient("deepseek")

    loop = ReActLoop(
        client=client,
        state=state,
        system_prompt="You are a bug bounty hunter...",
        tools=[...tool schemas...],
        tool_executor=my_executor,
    )
    loop.run("Hunt example.com for vulnerabilities")
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, Callable

from aimy.core.state import AgentState

# ── Defaults ──────────────────────────────────────────────────────
MAX_TURNS = 30
MAX_OBS_CHARS = 3000
COMPRESS_EVERY_N = 5

# ── Colours ───────────────────────────────────────────────────────
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"


class ReActLoop:
    """A reusable ReAct (Reasoning + Acting) agent loop.

    The loop:
      1. Sends system prompt + user input + tool list to LLM
      2. LLM returns text reply OR tool call(s)
      3. If tool calls: execute them, inject results, go to step 1
      4. If no tool calls: return final text — done
      5. Repeat until max_turns or time budget exhausted

    Features:
      - Working memory compression (every N steps)
      - Observation buffer (sliding window of last 5 outputs)
      - Turn counting + time budget
      - Persistable state (to_dict / from_dict)
    """

    def __init__(
        self,
        client,  # LLMClient
        state: AgentState | None = None,
        system_prompt: str = "",
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
        max_turns: int = MAX_TURNS,
        time_budget: int = 3600,
        verbose: bool = True,
    ):
        self.client = client
        self.state = state or AgentState()
        self.state.max_turns = max_turns
        self.state.time_budget_seconds = time_budget

        self.system_prompt = system_prompt
        self.tools = tools or []
        self.tool_executor = tool_executor or self._default_executor

        self.max_turns = max_turns
        self.time_budget = time_budget
        self.verbose = verbose

        self._compress_at = COMPRESS_EVERY_N

    # ── Main entry ────────────────────────────────────────────────

    def run(self, user_input: str, extra_context: str = "") -> str:
        """Execute the full ReAct loop. Returns the final assistant reply."""
        state = self.state
        state.extra_context = extra_context
        state.started_loop_at = time.time()
        state.done = False

        # Build initial messages
        system_msg = self.system_prompt
        if extra_context:
            system_msg += f"\n\n--- Additional Context ---\n{extra_context}"

        state.messages = [{"role": "system", "content": system_msg}]
        state.messages.append({"role": "user", "content": user_input})

        self._log(f"\n{CYAN}▸ Target: {BOLD}{state.target}{NC}")
        self._log(f"{DIM}  Provider: {self.client.description}  |  Tools: {len(self.tools)}  |  Max turns: {self.max_turns}{NC}\n")

        # ── MAIN LOOP ──────────────────────────────────────
        _recent_calls = []  # track last 5 (tool, args) for loop detection

        while state.turn < state.max_turns and not state.done:
            state.turn += 1
            # ── Loop detection: same tool+args 3x in a row = force stop
            if len(_recent_calls) >= 3 and len(set(_recent_calls[-3:])) == 1:
                state.done = True
                state.verdict = "Loop detected — same tool called 3 times. Stopping."
                self._log(f"\n{RED}Loop detected — stopping.{NC}")
                break
            turn_start = time.time()

            self._compress_context()

            # ── Call LLM ───────────────────────────────────────────
            self._log(f"{GREEN}▸ Thinking... (turn {state.turn}){NC}", end=" ")
            try:
                text, tool_calls = self.client.chat_with_tools(
                    model=state.model or None,
                    system="",  # already in messages[0]
                    user=self._messages_to_user_prompt(),
                    tools=self._filtered_tools(),
                    max_tokens=4000,
                )
            except Exception as e:
                self._log(f"{RED}LLM error: {e}{NC}")
                self.state.observation_buffer.append(f"[LLM ERROR] {e}")
                continue

            elapsed = time.time() - turn_start
            self._log(f"({elapsed:.1f}s)")

            # ── No tool calls → done ──────────────────────────────
            if not tool_calls:
                state.done = True
                state.verdict = text
                state.messages.append({"role": "assistant", "content": text})
                self._log(f"\n{CYAN}✓ Done.{NC}")
                break

            # ── Tool calls ────────────────────────────────────────
            assistant_msg = {"role": "assistant", "content": text, "tool_calls": []}
            tool_results = {}  # name → result, for correct message building

            for tc in tool_calls:
                name = tc["name"]
                args = tc.get("arguments", {})
                self._log(f"\n  {YELLOW}▸ {name}{NC} ", end="")
                self._log(f"{DIM}{self._brief_args(args)}{NC}")

                # Execute tool
                state.tool_call_count += 1
                try:
                    result = self.tool_executor(name, args)
                except Exception as e:
                    result = f"[ERROR] {e}"
                    state.tool_error_count += 1
                    self._log(f"  {RED}✗ {e}{NC}")

                tool_results[name] = result
                _recent_calls.append(f"{name}:{json.dumps(args, sort_keys=True)}")
                if len(_recent_calls) > 5:
                    _recent_calls = _recent_calls[-5:]

                # Truncate observation for display
                obs = result[:MAX_OBS_CHARS]
                if len(result) > MAX_OBS_CHARS:
                    obs += f"\n... [{len(result) - MAX_OBS_CHARS} more chars]"

                state.observation_buffer.append(f"[{name}]: {obs}")
                if len(state.observation_buffer) > 5:
                    state.observation_buffer = state.observation_buffer[-5:]

                assistant_msg["tool_calls"].append({
                    "id": f"call_{state.turn}_{name}",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args) if isinstance(args, dict) else str(args)},
                })

            # Add assistant + tool results to messages (correct per-tool results)
            state.messages.append(assistant_msg)
            for tc in tool_calls:
                name = tc["name"]
                result = tool_results.get(name, "")
                state.messages.append({
                    "role": "tool",
                    "tool_call_id": f"call_{state.turn}_{name}",
                    "content": result[:MAX_OBS_CHARS],
                })

            # Check time budget
            if state.is_time_up:
                self._log(f"\n{YELLOW}⏰ Time budget exhausted ({self.time_budget}s){NC}")
                state.done = True
                state.verdict = "Time budget exhausted."
                break

        # ── End of loop ────────────────────────────────────────────
        if state.turn >= state.max_turns:
            state.done = True
            state.verdict = f"Max turns ({state.max_turns}) reached."

        self._print_stats()
        self._auto_record()          # EVX: auto-feed findings into flywheel
        return state.verdict

    # ── Context compression ───────────────────────────────────────

    def _compress_context(self) -> None:
        """When messages grow too large, compress older ones into a summary."""
        state = self.state
        if state.turn > 0 and state.turn % self._compress_at == 0:
            # Keep system + last 8 messages; compress the rest
            if len(state.messages) > 10:
                keep = state.messages[-8:]
                older = state.messages[1:-8]  # skip system
                summary = f"[History: {len(older)} earlier exchanges compressed. "
                snippets = []
                for m in older:
                    c = str(m.get("content", ""))[:60].strip()
                    if c:
                        snippets.append(c)
                summary += " | ".join(snippets[:6])
                summary += "]"
                state.messages = [state.messages[0], {"role": "user", "content": summary}] + keep
                self._log(f"  {DIM}[compressed context: {len(state.messages)} messages]{NC}")

    def _messages_to_user_prompt(self) -> str:
        """Convert message history (excluding system) to a single user prompt string.

        For providers that don't support multi-message history natively,
        we flatten everything after system into the user prompt.
        """
        parts = []
        for m in self.state.messages[1:]:  # skip system
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "assistant":
                parts.append(f"[ASSISTANT]: {content}")
            elif role == "tool":
                parts.append(f"[TOOL RESULT]: {content}")
            else:
                parts.append(content)
        return "\n\n".join(parts)

    def _filtered_tools(self) -> list[dict[str, Any]]:
        """Return tools, filtered by allowlist if set."""
        if self.state.tool_allowlist is None:
            return self.tools
        allowed = set(self.state.tool_allowlist)
        return [t for t in self.tools
                if t.get("function", {}).get("name") in allowed]

    # ── Default tool executor (override this) ─────────────────────

    def _default_executor(self, name: str, args: dict[str, Any]) -> str:
        """Default tool executor — just echoes what was called.

        Override this by passing `tool_executor` to __init__.
        """
        return f"Called {name} with args: {json.dumps(args)} — no executor configured."

    # ── Helpers ───────────────────────────────────────────────────

    def _brief_args(self, args: dict[str, Any]) -> str:
        """Brief string representation of tool arguments."""
        if not args:
            return ""
        parts = []
        for k, v in args.items():
            if isinstance(v, str) and len(v) > 60:
                v = v[:57] + "..."
            parts.append(f"{k}={v}")
        return "(" + ", ".join(parts[:3]) + ")"

    # ── EVX auto-record ───────────────────────────────────────────

    def _auto_record(self) -> None:
        """Loop 结束后自动把 findings 写入 EVX 飞轮。老鸟模式自动过滤低价值发现。"""
        try:
            from aimy.memory.flywheel import record_finding
        except ImportError:
            return

        target = self.state.target or "unknown"
        recorded = 0
        filtered = 0

        # ── 老鸟模式过滤 ──
        from aimy.tools.settings import settings
        LOW_PATTERNS = ["reflected_xss", "xss_reflected", "open_redirect",
                        "info_disclosure", "info", "information",
                        "spf", "dmarc", "missing_header"]
        is_veteran = settings.is_veteran()

        # ── 来源1：state.findings（明确记录的漏洞）─────────────────
        for f in self.state.findings:
            vuln_class = f.get("tool", f.get("vuln_class", "unknown"))
            severity   = f.get("severity", "")
            summary    = f.get("summary", f.get("finding", ""))
            endpoint   = f.get("endpoint", "")
            if not summary:
                continue
            # 老鸟过滤
            if is_veteran:
                check = (summary + vuln_class + severity).lower()
                if any(p in check for p in LOW_PATTERNS):
                    filtered += 1
                    continue
            record_finding(
                target=target,
                vuln_class=vuln_class,
                severity=severity,
                technique=summary[:200],
                endpoint=endpoint,
                outcome="",
            )
            recorded += 1

        # ── 来源2：verdict 文本关键词扫描─────────────────────────
        _VULN_SIGNALS = [
            ("ssrf",              "ssrf",         "medium"),
            ("rce",               "rce",          "critical"),
            ("sql inject",        "sqli",         "high"),
            ("xss",               "xss",          "medium"),
            ("idor",              "idor",         "medium"),
            ("auth bypass",       "auth_bypass",  "high"),
            ("command inject",    "rce",          "high"),
            ("lfi",               "lfi",          "medium"),
            ("xxe",               "xxe",          "high"),
            ("ssti",              "ssti",         "high"),
            ("open redirect",     "open_redirect","low"),
            ("csrf",              "csrf",         "low"),
        ]
        verdict_lower = self.state.verdict.lower()
        already = {f.get("summary","")[:50] for f in self.state.findings}

        for keyword, vuln_class, severity in _VULN_SIGNALS:
            if keyword in verdict_lower:
                # Extract a brief context snippet around the keyword
                idx = verdict_lower.find(keyword)
                snippet = self.state.verdict[max(0,idx-30):idx+80].strip()
                if snippet[:50] in already:
                    continue
                record_finding(
                    target=target,
                    vuln_class=vuln_class,
                    severity=severity,
                    technique=f"[auto-detected] {snippet[:120]}",
                    outcome="",
                )
                recorded += 1
                already.add(snippet[:50])

        if recorded and self.verbose:
            print(f"{DIM}  [EVX] auto-recorded {recorded} finding(s) into flywheel{NC}")

    def _log(self, msg: str, end: str = "\n") -> None:
        if self.verbose:
            print(msg, end=end, flush=True)

    def _print_stats(self) -> None:
        if not self.verbose:
            return
        state = self.state
        elapsed = state.elapsed_seconds
        self._log(f"\n{DIM}─── {BOLD}{GREEN}{state.turn}{DIM} turns  ·  "
                  f"⏱ {elapsed:.1f}s  ·  "
                  f"🛠 {state.tool_call_count} tools  ·  "
                  f"📋 {len(state.findings)} findings{DIM} ───{NC}\n")
