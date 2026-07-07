"""SkillFormatter — assemble skills into system prompt chunks.

Handles context budget: fits as many skills as possible into the
available token budget, prioritizing by relevance score.
"""

from __future__ import annotations

from aimy.skills.loader import Skill

# ── Context budget defaults ───────────────────────────────────────
DEFAULT_MAX_CHARS = 3000      # max chars for skill content in system prompt
MAX_SKILL_LENGTH = 1200       # truncate individual skill body to this
MAX_SKILLS = 5                # max number of skills to include


class SkillFormatter:
    """Assembles selected skills into a coherent system prompt prefix."""

    def __init__(self, max_chars: int = DEFAULT_MAX_CHARS):
        self.max_chars = max_chars

    # ── Main formatting ───────────────────────────────────────────

    def format(self, skills: list[Skill], task: str = "",
               extra_context: str = "") -> str:
        """Build the skills section of a system prompt.

        Args:
            skills: Ranked list of skills (most relevant first)
            task: The user's task description (for header)
            extra_context: Additional context to inject

        Returns:
            Formatted string ready to append to system prompt.
        """
        if not skills:
            return ""

        parts = []
        chars_used = 0

        # Header
        header = self._make_header(task)
        parts.append(header)
        chars_used += len(header)

        # Skills
        included = 0
        for skill in skills[:MAX_SKILLS]:
            block = self._format_skill(skill)
            if chars_used + len(block) > self.max_chars:
                # Try truncated version
                block = self._format_skill_short(skill)
                if chars_used + len(block) > self.max_chars:
                    break

            parts.append(block)
            chars_used += len(block)
            included += 1

        # Footer
        if included > 0:
            footer = f"\n--- End of skills ({included} loaded, {chars_used} chars) ---\n"
            parts.append(footer)

        return "\n".join(parts)

    def format_minimal(self, skills: list[Skill]) -> str:
        """Ultra-compact format: just skill names + key rules."""
        if not skills:
            return ""
        lines = ["[Skills loaded: "]
        lines.append(", ".join(s.name for s in skills[:MAX_SKILLS]))
        lines.append("]")
        return "".join(lines)

    # ── Internal ──────────────────────────────────────────────────

    def _make_header(self, task: str) -> str:
        task_note = f" for: {task[:100]}" if task else ""
        return f"--- Loaded Skills{task_note} ---\n"

    def _format_skill(self, skill: Skill) -> str:
        """Format a skill as a compact text block."""
        body = skill.body
        if len(body) > MAX_SKILL_LENGTH:
            # Truncate intelligently: keep headings + first paragraphs
            lines = body.split("\n")
            result = []
            length = 0
            for line in lines:
                if length > MAX_SKILL_LENGTH:
                    break
                # Always include headings
                if line.startswith("#"):
                    result.append(line)
                    length += len(line)
                elif length < 800:
                    result.append(line)
                length += len(line)
            body = "\n".join(result)
            if len(body) > MAX_SKILL_LENGTH:
                body = body[:MAX_SKILL_LENGTH] + "\n... [truncated]"

        return f"""
### [{skill.name}] {skill.description[:150]}
{body}
"""

    def _format_skill_short(self, skill: Skill) -> str:
        """Ultra-short format: name + description only."""
        return f"\n### [{skill.name}] {skill.description[:200]}\n"
