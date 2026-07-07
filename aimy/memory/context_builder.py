"""ContextBuilder — assemble optimal prompt prefix from memory layers."""

from __future__ import annotations


class ContextBuilder:
    """Builds the context that gets injected into the system prompt.

    Layers (in order of priority):
      1. Relevant skills (from SkillFormatter)
      2. Similar past patterns (from PatternDB)
      3. Target profile (from HuntJournal)
      4. Recent observations (from AgentState)
    """

    def __init__(self, max_context_chars: int = 3000):
        self.max_chars = max_context_chars

    def build(self, task: str = "", target: str = "",
              skills_text: str = "", patterns: list[dict] | None = None,
              journal_entries: list[dict] | None = None,
              working_memory: str = "") -> str:
        """Assemble the context prefix for the system prompt."""

        parts = []
        chars_left = self.max_chars

        # Layer 1: Skills (most important — always first)
        if skills_text and chars_left > 500:
            parts.append(skills_text)
            chars_left -= min(len(skills_text), 1500)

        # Layer 2: Past patterns (if any match)
        if patterns and chars_left > 300:
            pattern_text = self._format_patterns(patterns[:5], chars_left)
            if pattern_text:
                parts.append(pattern_text)
                chars_left -= len(pattern_text)

        # Layer 3: Target profile from journal
        if journal_entries and chars_left > 200:
            profile = self._format_profile(target, journal_entries, chars_left)
            if profile:
                parts.append(profile)
                chars_left -= len(profile)

        # Layer 4: Working memory
        if working_memory and chars_left > 200:
            wm = working_memory[:chars_left]
            parts.append(f"[Working Memory]\n{wm}")
            chars_left -= len(wm)

        return "\n\n".join(parts)

    # ── Formatters ────────────────────────────────────────────────

    def _format_patterns(self, patterns: list[dict], budget: int) -> str:
        lines = ["[Relevant Past Patterns]"]
        for p in patterns[:3]:
            line = (f"- {p.get('vuln_class','?')} ({p.get('severity','?')}): "
                    f"{p.get('technique','')[:120]}")
            if len("\n".join(lines)) + len(line) > budget:
                break
            lines.append(line)
        return "\n".join(lines) if len(lines) > 1 else ""

    def _format_profile(self, target: str, entries: list[dict], budget: int) -> str:
        if not target:
            return ""
        lines = [f"[Target Profile: {target}]"]
        types = set(e.get("type", "") for e in entries[-50:])
        if "finding" in types:
            finding_entries = [e for e in entries if e.get("type") == "finding"]
            lines.append(f"  Previous findings: {len(finding_entries)}")
        return "\n".join(lines)
