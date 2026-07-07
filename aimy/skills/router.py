"""SkillRouter — relevance scoring and Top-N skill selection.

Given a task description or user query, finds the most relevant skills
using keyword matching and phase routing.
"""

from __future__ import annotations

import re
from collections import defaultdict

from aimy.skills.registry import SkillRegistry
from aimy.skills.loader import Skill


class SkillRouter:
    """Routes tasks to the most relevant skills."""

    # Keyword → phase mapping for task routing
    PHASE_KEYWORDS: dict[str, list[str]] = {
        "recon": [
            "recon", "subdomain", "enum", "asset", "discover", "收集", "枚举",
            "domain", "host", "live", "url", "crawl", "dns", "cdn",
        ],
        "map": [
            "map", "surface", "attack", "fingerprint", "tech", "攻击面",
        ],
        "find": [
            "hunt", "vuln", "bug", "xss", "ssrf", "sqli", "idor", "漏洞",
            "挖掘", "测试", "find", "scan", "detect", "inject",
        ],
        "prove": [
            "prove", "exploit", "chain", "poc", "bypass", "利用",
            "绕过", "race", "fuzz",
        ],
        "report": [
            "report", "validate", "triage", "write", "submit", "报告",
            "验证", "cvss",
        ],
    }

    def __init__(self, registry: SkillRegistry, feedback_db=None):
        self.registry = registry
        self._feedback = feedback_db  # optional FeedbackDB for flywheel boost

    # ── Main routing ──────────────────────────────────────────────

    def relevant_skills(self, task: str, max_skills: int = 5,
                        phase: str | None = None) -> list[Skill]:
        """Return the top-N most relevant skills for a task.

        Args:
            task: Natural language task description
            max_skills: Maximum skills to return
            phase: Optional phase filter ("recon"|"find"|"prove"|"report")
        """
        # Extract keywords from task
        keywords = self._extract_keywords(task)

        # If no phase specified, infer from task keywords
        if phase is None:
            phase = self._infer_phase(keywords)

        # Get skills by trigger words
        trigger_matches = self.registry.by_trigger(*keywords)

        # Get skills by phase
        phase_matches = self.registry.by_phase(phase)

        # Merge and score
        scores: dict[str, float] = defaultdict(float)

        # Trigger match scoring (primary)
        for skill in trigger_matches:
            matched_triggers = sum(
                1 for kw in keywords
                if kw in skill.description.lower() or kw in skill.name.lower()
            )
            # Boost: exact name match
            name_boost = 3.0 if task.lower() in skill.name.lower() else 0.0
            # Boost: methodology skills always rank high
            method_boost = 2.0 if "methodology" in skill.name.lower() else 0.0
            scores[skill.name] = matched_triggers * 2 + name_boost + method_boost + skill.priority * 0.1

        # Phase match scoring (secondary boost)
        for skill in phase_matches:
            if skill.name not in scores:
                scores[skill.name] = skill.priority * 0.1
            else:
                scores[skill.name] += 1.0  # phase match bonus

        # Flywheel boost: reward techniques with high H1 acceptance rate
        if self._feedback:
            top = set(self._feedback.top_techniques(n=20))
            for name in list(scores):
                if any(t.lower() in name.lower() or name.lower() in t.lower() for t in top):
                    scores[name] += 3.0

        # Sort by score desc
        ranked = sorted(scores.items(), key=lambda x: -x[1])

        # Return top N
        result = []
        for name, score in ranked[:max_skills]:
            skill = self.registry.get(name)
            if skill:
                result.append(skill)

        return result

    # ── Keyword extraction ────────────────────────────────────────

    def _extract_keywords(self, task: str) -> list[str]:
        """Extract meaningful keywords from task description."""
        task_lower = task.lower()

        # Extract English keywords
        keywords = []
        # Known security/tech terms
        patterns = [
            r'\b(xss|ssrf|sqli|idor|csrf|rce|lfi|rfi|xxe|ssti|jwt|oauth|graphql|api)\b',
            r'\b(recon|scan|hunt|exploit|report|validate|triage|fuzz|bypass|inject)\b',
            r'\b(subdomain|domain|host|url|endpoint|param|header|cookie|token|auth)\b',
            r'\b(java|spring|php|python|go|node|react|angular|aws|gcp|azure|cloud)\b',
        ]
        for pattern in patterns:
            for m in re.findall(pattern, task_lower):
                if m not in keywords:
                    keywords.append(m)

        # Extract Chinese keywords
        chinese = re.findall(r'[一-鿿]{2,}', task)
        keywords.extend(chinese[:5])

        # Extract quoted phrases
        quoted = re.findall(r'"([^"]+)"', task)
        keywords.extend(quoted)

        # Fallback: use individual words
        if not keywords:
            words = re.findall(r'\b[a-z]{3,}\b', task_lower)
            # Filter stop words
            stop = {"the", "and", "for", "use", "how", "what", "when", "where", "that", "this", "with", "from", "have", "been", "can", "does", "will"}
            keywords = [w for w in words if w not in stop][:10]

        return keywords

    def _infer_phase(self, keywords: list[str]) -> str:
        """Infer hunting phase from keywords."""
        phase_scores = defaultdict(int)
        joined = " ".join(keywords)
        for phase, kws in self.PHASE_KEYWORDS.items():
            for kw in kws:
                if kw in joined:
                    phase_scores[phase] += 1
        if not phase_scores:
            return "find"  # default hunting phase
        return max(phase_scores, key=phase_scores.get)
