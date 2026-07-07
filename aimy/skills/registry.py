"""SkillRegistry — inverted index for fast skill lookup.

Indexes:
  - By trigger word → skill names
  - By phase → skill names
  - By required tool → skill names
  - By source → skill names
  - Full-text search over descriptions
"""

from __future__ import annotations

from collections import defaultdict

from aimy.skills.loader import Skill


class SkillRegistry:
    """Inverted index for skills."""

    def __init__(self):
        self._skills: dict[str, Skill] = {}              # name → Skill
        self._by_trigger: dict[str, set[str]] = defaultdict(set)
        self._by_phase: dict[str, set[str]] = defaultdict(set)
        self._by_tool: dict[str, set[str]] = defaultdict(set)
        self._by_source: dict[str, set[str]] = defaultdict(set)
        self._by_tag: dict[str, set[str]] = defaultdict(set)

    # ── Indexing ──────────────────────────────────────────────────

    def index(self, skills: dict[str, Skill]) -> int:
        """Index a batch of skills. Returns count of indexed skills."""
        count = 0
        for name, skill in skills.items():
            self._index_one(name, skill)
            count += 1
        return count

    def _index_one(self, name: str, skill: Skill) -> None:
        """Index a single skill."""
        self._skills[name] = skill

        # Index triggers in description
        for trigger in skill.triggers:
            # Also index individual words from multi-word triggers
            words = trigger.lower().split()
            for word in words:
                if len(word) > 2 and word not in ("the", "and", "for", "use", "when", "that", "with", "from"):
                    self._by_trigger[word].add(name)
            self._by_trigger[trigger.lower()].add(name)

        # Index skill name as trigger
        self._by_trigger[name.lower()].add(name)
        for word in name.lower().replace("-", " ").replace("_", " ").split():
            if len(word) > 2:
                self._by_trigger[word].add(name)

        # Index phases
        for phase in skill.phases:
            self._by_phase[phase].add(name)

        # Index required tools
        for tool in skill.required_tools:
            self._by_tool[tool.lower()].add(name)

        # Index source
        self._by_source[skill.source].add(name)

        # Index tags
        for tag in skill.tags:
            self._by_tag[tag.lower()].add(name)

    # ── Query ─────────────────────────────────────────────────────

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def by_trigger(self, *words: str) -> list[Skill]:
        """Find skills matching trigger words. Returns skills sorted by relevance."""
        scores: dict[str, int] = defaultdict(int)
        for word in words:
            w = word.lower().strip()
            if w in self._by_trigger:
                for name in self._by_trigger[w]:
                    scores[name] += 1
            # Partial match
            for key, names in self._by_trigger.items():
                if w in key:
                    for name in names:
                        scores[name] += 0.5
        # Sort by score desc, then priority desc
        result = [(name, score) for name, score in scores.items()]
        result.sort(key=lambda x: (-x[1], -self._skills[x[0]].priority))
        return [self._skills[name] for name, _ in result]

    def by_phase(self, phase: str) -> list[Skill]:
        names = self._by_phase.get(phase, set()) | self._by_phase.get("any", set())
        return sorted(
            [self._skills[n] for n in names if n in self._skills],
            key=lambda s: -s.priority,
        )

    def by_tool(self, tool_name: str) -> list[Skill]:
        names = self._by_tool.get(tool_name.lower(), set())
        return [self._skills[n] for n in names if n in self._skills]

    def list_all(self) -> list[str]:
        return sorted(self._skills.keys())

    @property
    def count(self) -> int:
        return len(self._skills)

    @property
    def sources(self) -> dict[str, int]:
        return {k: len(v) for k, v in self._by_source.items()}

    @property
    def trigger_count(self) -> int:
        return len(self._by_trigger)
