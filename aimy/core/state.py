"""AgentState — shared state across the agent lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AgentState:
    """Shared state for a hunt session.

    Passed between agent loop iterations, persisted to disk for resume.
    """

    # ── Session identity ──────────────────────────────────────────
    session_id: str = ""
    target: str = ""
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # ── Messages ──────────────────────────────────────────────────
    messages: list[dict[str, Any]] = field(default_factory=list)
    """Full message history (system + user + assistant + tool results)."""

    # ── Tools ─────────────────────────────────────────────────────
    available_tools: list[dict[str, Any]] = field(default_factory=list)
    """Tool schemas available to the LLM (OpenAI function-calling format)."""

    tool_allowlist: list[str] | None = None
    """If set, only these tool names are available."""

    # ── Working memory ────────────────────────────────────────────
    working_memory: str = ""
    """LLM-maintained running notes — compressed every N steps."""

    observation_buffer: list[str] = field(default_factory=list)
    """Last 5 raw tool outputs (sliding window)."""

    # ── Findings ──────────────────────────────────────────────────
    findings: list[dict[str, Any]] = field(default_factory=list)
    """[{tool, severity, summary, finding, timestamp}, ...]."""

    # ── Loop control ──────────────────────────────────────────────
    turn: int = 0
    max_turns: int = 30
    time_budget_seconds: int = 3600
    started_loop_at: float = 0.0

    done: bool = False
    verdict: str = ""

    # ── Stats ─────────────────────────────────────────────────────
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    tool_call_count: int = 0
    tool_error_count: int = 0

    # ── Extra context ─────────────────────────────────────────────
    extra_context: str = ""
    """Additional context injected into system prompt (skills, patterns, etc.)."""

    scope_file: str = ""
    """Path to scope file for safety checks."""

    # ── Providers ─────────────────────────────────────────────────
    provider: str = "deepseek"
    model: str = ""

    @property
    def elapsed_seconds(self) -> float:
        """Seconds since loop started."""
        if not self.started_loop_at:
            return 0.0
        import time
        return time.time() - self.started_loop_at

    @property
    def time_remaining(self) -> float:
        """Seconds remaining in time budget."""
        return max(0.0, self.time_budget_seconds - self.elapsed_seconds)

    @property
    def is_time_up(self) -> bool:
        return self.elapsed_seconds >= self.time_budget_seconds

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "started_at": self.started_at,
            "messages": self.messages,
            "working_memory": self.working_memory,
            "findings": self.findings,
            "turn": self.turn,
            "max_turns": self.max_turns,
            "done": self.done,
            "verdict": self.verdict,
            "stats": {
                "prompt_tokens": self.total_prompt_tokens,
                "completion_tokens": self.total_completion_tokens,
                "tool_calls": self.tool_call_count,
                "tool_errors": self.tool_error_count,
            },
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentState":
        """Restore from serialized dict."""
        s = cls(
            session_id=d.get("session_id", ""),
            target=d.get("target", ""),
            started_at=d.get("started_at", ""),
            messages=d.get("messages", []),
            working_memory=d.get("working_memory", ""),
            findings=d.get("findings", []),
            turn=d.get("turn", 0),
            max_turns=d.get("max_turns", 30),
            done=d.get("done", False),
            verdict=d.get("verdict", ""),
        )
        stats = d.get("stats", {})
        s.total_prompt_tokens = stats.get("prompt_tokens", 0)
        s.total_completion_tokens = stats.get("completion_tokens", 0)
        s.tool_call_count = stats.get("tool_calls", 0)
        s.tool_error_count = stats.get("tool_errors", 0)
        return s
