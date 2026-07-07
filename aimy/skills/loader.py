"""SkillLoader — parse SKILL.md files. Zero external dependencies."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


@dataclass
class Skill:
    """A loaded skill with metadata and body content."""

    name: str
    description: str
    body: str
    source_path: str = ""
    source: str = "internal"

    triggers: list[str] = field(default_factory=list)
    phases: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    cost: str = "free"
    priority: int = 5
    tags: list[str] = field(default_factory=list)

    @property
    def body_length(self) -> int:
        return len(self.body)


class SkillLoader:
    """Parse SKILL.md files from skill directories."""

    def __init__(self):
        self._sources: list[tuple[str, str]] = []
        self._skills: dict[str, Skill] = {}

    def add_source(self, directory: str, source_label: str = "internal") -> None:
        self._sources.append((directory, source_label))

    def load_all(self) -> dict[str, Skill]:
        for directory, source_label in self._sources:
            self._load_directory(directory, source_label)
        return self._skills

    def _load_directory(self, directory: str, source_label: str) -> None:
        if not os.path.isdir(directory):
            return
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fn in files:
                if fn.upper() == "SKILL.MD":
                    fp = os.path.join(root, fn)
                    skill = self._parse_file(fp, source_label)
                    if skill and skill.name:
                        existing = self._skills.get(skill.name)
                        if not existing or len(skill.triggers) > len(existing.triggers):
                            self._skills[skill.name] = skill

    def _parse_file(self, filepath: str, source_label: str) -> Skill | None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return None

        frontmatter, body = self._parse_frontmatter(content)
        if not frontmatter:
            return None

        name = frontmatter.get("name", os.path.basename(os.path.dirname(filepath)))
        description = frontmatter.get("description", "")

        triggers = self._extract_triggers(description)
        explicit_triggers = frontmatter.get("triggers", "")
        if isinstance(explicit_triggers, list):
            triggers.extend(explicit_triggers)
        elif explicit_triggers:
            triggers.extend(t.strip() for t in str(explicit_triggers).split(","))

        phases = frontmatter.get("phase", [])
        if isinstance(phases, str):
            phases = [p.strip() for p in phases.split(",")]

        required_tools = frontmatter.get("required_tools", [])
        if isinstance(required_tools, str):
            required_tools = [t.strip() for t in required_tools.split(",")]

        return Skill(
            name=name,
            description=description,
            body=body.strip(),
            source_path=filepath,
            source=source_label,
            triggers=triggers,
            phases=phases if phases else self._infer_phases(name, description),
            required_tools=required_tools,
            cost=str(frontmatter.get("cost", "free")),
            priority=int(frontmatter.get("priority", 5)),
            tags=frontmatter.get("tags", []) if isinstance(frontmatter.get("tags", []), list) else [],
        )

    def _parse_frontmatter(self, content: str) -> tuple[dict, str]:
        """Parse YAML-like frontmatter without PyYAML dependency."""
        m = re.match(r'^---\s*\n(.*?)\n---\s*\n?(.*)', content, re.DOTALL)
        if not m:
            return {}, content

        yaml_text = m.group(1)
        body = m.group(2).strip()

        # Simple key: value parser (handles nested basic YAML)
        result = {}
        current_key = None
        current_list = None

        for line in yaml_text.split("\n"):
            # Skip empty lines and comments
            if not line.strip() or line.strip().startswith("#"):
                continue

            # List item
            list_match = re.match(r'^\s+-\s+(.+)', line)
            if list_match and current_list is not None:
                current_list.append(list_match.group(1).strip().strip('"').strip("'"))
                continue

            # Key: value
            kv_match = re.match(r'^(\w[\w_-]*)\s*:\s*(.+)', line)
            if kv_match:
                key = kv_match.group(1)
                value = kv_match.group(2).strip()

                # Remove surrounding quotes
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]

                # Check if this starts a list (value is empty or just '[')
                if value in ("", "[]"):
                    current_key = key
                    current_list = []
                    result[key] = current_list
                else:
                    current_key = None
                    current_list = None
                    result[key] = value
            else:
                current_key = None
                current_list = None

        return result, body

    # ── Trigger extraction ────────────────────────────────────────

    def _extract_triggers(self, description: str) -> list[str]:
        triggers = []

        # Extract "use when/for/at ..." patterns
        for m in re.finditer(r'use\s+(?:when|for|at\s+the\s+start\s+of|before|after|during)\s+([^.]*?)(?:\.|$)', description):
            text = m.group(1).strip()
            for part in re.split(r',| or ', text):
                part = part.strip().lower()
                if part and len(part) > 3:
                    triggers.append(part)

        # Chinese triggers after "中文触发词："
        cn_match = re.search(r'[一-鿿]{2,}[：:]\s*(.+)', description)
        if cn_match:
            cn_text = cn_match.group(1)
            triggers.extend(t.strip() for t in cn_text.split("、") if t.strip())

        # Chinese keywords in description
        cn_words = re.findall(r'[一-鿿]{2,}', description)
        # Filter for security-related ones
        sec_cn = [w for w in cn_words if any(kw in w for kw in
            ['测试', '扫描', '挖掘', '枚举', '审计', '发现', '检测', '绕过', '注入', '攻击',
             '利用', '渗透', '提权', '收集', '漏洞', '赏金', '安全', '信息'])]
        triggers.extend(sec_cn[:10])

        return list(set(triggers))

    def _infer_phases(self, name: str, description: str) -> list[str]:
        text = (name + " " + description).lower()
        phases = []
        if any(kw in text for kw in ("recon", "subdomain", "enum", "asset", "discover")):
            phases.append("recon")
        if any(kw in text for kw in ("map", "surface", "fingerprint")):
            phases.append("map")
        if any(kw in text for kw in ("hunt", "vuln", "bug", "xss", "ssrf", "sqli", "idor")):
            phases.append("find")
        if any(kw in text for kw in ("prove", "exploit", "chain", "poc", "bypass")):
            phases.append("prove")
        if any(kw in text for kw in ("report", "validate", "triage", "write")):
            phases.append("report")
        if any(kw in text for kw in ("methodology", "start", "workflow")):
            phases = ["recon", "find", "prove", "report"]
        return phases if phases else ["any"]
