"""SkillQuality — Skill 质量门

判断一个知识点/技法是否值得写成独立的 Skill 文件。
基于《邪修打法》skill-creator 框架：
  - is_ai_likely_known（AI 是否本来就知道）
  - source_quality（来源权威性）
  - migration_potential（迁移潜力 — 能否用在多个场景）
  - scene_frequency（出现频率）
  - worth_skill → 最终决策

两种模式:
  1. heuristic（启发式规则）: 纯 Python 快速判断，无 LLM 依赖
  2. llm（LLM 判断）: 加载 skill_quality_prompt.md，调用 LLM 深度评估

用法:
    from aimy.tools.skill_quality import SkillQualityGate

    gate = SkillQualityGate()
    result = gate.evaluate("Java Ghost Bits 截断", "char→byte 8位...")
    # → {"worth_skill": true, "reason": "...", "skill_framework": {...}}
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from aimy.tools.log_utils import get_logger

logger = get_logger("skill_quality")

# ── AI 已知技术列表（启发式用） ──────────────────────────────────
_KNOWN_TECHNIQUES: dict[str, str] = {
    # 技术关键词 → 建议归属的 Skill
    "sql injection": "sqli-sql-injection",
    "sql注入": "sqli-sql-injection",
    "xss": "xss-cross-site-scripting",
    "cross.site scripting": "xss-cross-site-scripting",
    "csrf": "csrf-cross-site-request-forgery",
    "ssrf": "ssrf-server-side-request-forgery",
    "idor": "idor-broken-object-authorization",
    "command injection": "cmdi-command-injection",
    "cmd注入": "cmdi-command-injection",
    "ssti": "ssti-server-side-template-injection",
    "xxe": "xxe-xml-external-entity",
    "open redirect": "open-redirect",
    "clickjacking": "clickjacking",
    "cors": "cors-cross-origin-misconfiguration",
    "host header": "http-host-header-attacks",
    "crlf": "crlf-injection",
    "request smuggling": "request-smuggling",
    "cache poisoning": "web-cache-deception",
    "cache deception": "web-cache-deception",
    "prototype pollution": "prototype-pollution",
    "jwt": "jwt-oauth-token-attacks",
    "oauth": "oauth-oidc-misconfiguration",
    "saml": "saml-sso-assertion-attacks",
    "deserialization": "deserialization-insecure",
    "反序列化": "deserialization-insecure",
    "race condition": "race-condition",
    "business logic": "business-logic-vulnerabilities",
    "业务逻辑": "business-logic-vulnerabilities",
    "lfi": "file-access-vuln",
    "rfi": "file-access-vuln",
    "file upload": "file-access-vuln",
    "insecure source": "insecure-source-code-management",
    ".git": "insecure-source-code-management",
    "type juggling": "type-juggling",
    "strcmp": "type-juggling",
    "graphql": "graphql-audit",
    "waf": "waf-bypass-techniques",
    "bypass 403": "401-403-bypass-techniques",
    "bypass 401": "401-403-bypass-techniques",
    "credential": "credential-attack",
    "password spray": "credential-attack",
    "llm": "llm-prompt-injection",
    "prompt injection": "llm-prompt-injection",
    "subdomain takeover": "subdomain-takeover",
    "linux privilege": "linux-privilege-escalation",
    "windows privilege": "windows-privilege-escalation",
    "container escape": "container-escape-techniques",
    "kerberos": "active-directory-kerberos-attacks",
    "certificate service": "active-directory-certificate-services",
    "acl abuse": "active-directory-acl-abuse",
}

# 来源权威性权重
_SOURCE_WEIGHTS: dict[str, int] = {
    "blackhat": 5,
    "defcon": 5,
    "cansecwest": 5,
    "usenix": 5,
    "project zero": 5,
    "google p0": 5,
    "portswigger": 4,
    "hackerone #1": 4,
    "top 10 h1": 4,
    "0day": 5,
    "cve": 3,
    "ctf": 2,
    "writeup": 2,
    "blog": 2,
    "twitter": 1,
}

# 高迁移性关键词
_HIGH_MIGRATION = [
    "bypass", "绕过", "evade", "waf", "filter",
    "unicode", "encoding", "protocol",
    "chain", "组合", "multi-step",
    "ssrf", "rce", "sandbox",
]


@dataclass
class SkillDecision:
    """Skill 质量门决策结果"""
    knowledge_point: str = ""
    is_ai_likely_known: bool = True
    reason: str = ""
    source_quality: str = ""
    scene_frequency: str = ""
    migration_potential: str = ""
    worth_skill: bool = False
    suggested_handling: str = ""
    skill_framework: Optional[dict] = None
    existing_skill: str = ""  # 如果已有对应 Skill

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        if self.worth_skill:
            return f"✅ [{self.knowledge_point}] ★ 值得写 Skill → {self.suggested_handling}"
        else:
            return f"⏭ [{self.knowledge_point}] 已有覆盖 → {self.suggested_handling}"


class SkillQualityGate:
    """Skill 质量门 — 决定是否将技法写成独立 Skill。"""

    # Prompt 文件路径
    PROMPT_PATH = Path(__file__).parent.parent / "references" / "skill_quality_prompt.md"

    def __init__(self, use_heuristic: bool = True):
        self.use_heuristic = use_heuristic

    # ── 主入口 ──────────────────────────────────────────────────

    def evaluate(self, knowledge_point: str, description: str = "",
                 source: str = "") -> SkillDecision:
        """评估一个知识点是否值得写 Skill。

        Args:
            knowledge_point: 技法名称，如 "Java Ghost Bits"
            description: 详细描述
            source: 来源，如 "BlackHat 2026"

        返回: SkillDecision
        """
        if self.use_heuristic:
            return self._heuristic_judge(knowledge_point, description, source)
        else:
            # LLM 模式暂返回启发式结果
            return self._heuristic_judge(knowledge_point, description, source)

    # ── 启发式判断 ──────────────────────────────────────────────

    def _heuristic_judge(self, name: str, desc: str, source: str) -> SkillDecision:
        text = f"{name} {desc}".lower()
        source_lower = source.lower()

        # Step 1: 检查是否在已知列表中
        existing = self._find_existing(text)
        if existing and not self._is_advanced_variant(text, existing):
            return SkillDecision(
                knowledge_point=name,
                is_ai_likely_known=True,
                reason=f"AI 已知技术，已有 Skill 覆盖: {existing}",
                source_quality=source or "通用",
                scene_frequency=self._estimate_frequency(text),
                migration_potential=self._estimate_migration(text),
                worth_skill=False,
                suggested_handling=f"在 {existing} Skill 中补充一条参考即可",
                existing_skill=existing,
            )

        # Step 2: 评估来源权威性
        source_score = self._score_source(source_lower)
        if source_score >= 4:
            # 顶级会议/研究 → 高概率值得写
            if self._has_migration_potential(text):
                framework = self._build_framework(name, desc, text)
                return SkillDecision(
                    knowledge_point=name,
                    is_ai_likely_known=False,
                    reason=f"顶级来源({source})，AI 训练数据可能未覆盖",
                    source_quality=source,
                    scene_frequency=self._estimate_frequency(text),
                    migration_potential=self._estimate_migration(text),
                    worth_skill=True,
                    suggested_handling=f"创建独立 Skill: {name}",
                    skill_framework=framework,
                )

        # Step 3: 检查是否高迁移性
        if self._has_migration_potential(text):
            framework = self._build_framework(name, desc, text)
            return SkillDecision(
                knowledge_point=name,
                is_ai_likely_known=False,
                reason="高迁移性，可跨场景复用",
                source_quality=source or "社区",
                scene_frequency=self._estimate_frequency(text),
                migration_potential=self._estimate_migration(text),
                worth_skill=True,
                suggested_handling=f"创建独立 Skill: {name}",
                skill_framework=framework,
            )

        # Step 4: 默认 — 不值得
        return SkillDecision(
            knowledge_point=name,
            is_ai_likely_known=True,
            reason="常规技术，AI 训练数据已充分覆盖，或迁移潜力低",
            source_quality=source or "通用",
            scene_frequency=self._estimate_frequency(text),
            migration_potential=self._estimate_migration(text),
            worth_skill=False,
            suggested_handling="不创建独立 Skill，在相关 Skill 中补充参考",
            existing_skill=existing or "",
        )

    def _find_existing(self, text: str) -> str:
        """在已有 Skill 列表中查找匹配。"""
        for keyword, skill_name in _KNOWN_TECHNIQUES.items():
            if keyword in text:
                return skill_name
        return ""

    def _is_advanced_variant(self, text: str, existing: str) -> bool:
        """判断是否是已有 Skill 的高级变体（可能值得独立写）。"""
        # 如果同时有 bypass/chain/0day 等高级修饰词
        advanced = any(w in text for w in ["bypass", "evade", "chain", "variant",
                                             "bypass", "0day", "filter", "waf"])
        weak_advanced = any(w in text for w in ["basic", "simple", "基础", "入门"])
        return advanced and not weak_advanced

    def _score_source(self, source: str) -> int:
        for keyword, score in _SOURCE_WEIGHTS.items():
            if keyword in source:
                return score
        return 1

    def _has_migration_potential(self, text: str) -> bool:
        return any(w in text for w in _HIGH_MIGRATION)

    def _estimate_frequency(self, text: str) -> str:
        if any(w in text for w in ["ctf", "challenge", "靶机"]):
            return "低（仅 CTF 场景）"
        if any(w in text for w in ["enterprise", "cloud", "k8s", "kubernetes"]):
            return "高（企业场景普遍）"
        return "中"

    def _estimate_migration(self, text: str) -> str:
        scenarios = []
        if "waf" in text or "bypass" in text:
            scenarios.append("WAF 绕过")
        if "json" in text or "api" in text:
            scenarios.append("API/JSON")
        if "smtp" in text or "email" in text:
            scenarios.append("SMTP/邮件")
        if "unicode" in text or "encoding" in text:
            scenarios.append("编码处理")
        if "protocol" in text or "http" in text:
            scenarios.append("协议层")
        if "cloud" in text or "aws" in text or "azure" in text:
            scenarios.append("云环境")
        return "/".join(scenarios) if scenarios else "单场景"

    def _build_framework(self, name: str, desc: str, text: str) -> dict:
        """构建 Skill 框架建议。"""
        return {
            "name": name,
            "description": desc[:200] if desc else name,
            "detection_steps": [
                "确认输入点可控",
                "发送探测 payload",
                "观察响应异常",
            ],
            "logic": [
                f"IF 存在 {name} 的触发条件",
                "THEN 存在安全风险",
            ],
            "bypass_scenarios": self._estimate_migration(text).split("/") if self._estimate_migration(text) != "单场景" else [],
        }

    # ── Prompt 加载 ────────────────────────────────────────────

    def load_prompt(self) -> str:
        """加载 skill_quality_prompt.md 参考文件。"""
        path = self.PROMPT_PATH
        if path.exists():
            return path.read_text(encoding="utf-8")
        return ""

    # ── 批量评估 ────────────────────────────────────────────────

    def evaluate_many(self, candidates: list[dict]) -> list[SkillDecision]:
        """批量评估多个候选技法。

        candidates: [{"name": "...", "desc": "...", "source": "..."}, ...]
        """
        results = []
        for c in candidates:
            result = self.evaluate(
                c.get("name", ""),
                c.get("desc", c.get("description", "")),
                c.get("source", ""),
            )
            results.append(result)
        # 按 worth_skill 排序（值得的在前）
        results.sort(key=lambda x: (not x.worth_skill, x.reason))
        return results

    def summary_text(self, decisions: list[SkillDecision]) -> str:
        """生成可读摘要。"""
        worth = [d for d in decisions if d.worth_skill]
        skip = [d for d in decisions if not d.worth_skill]

        lines = [
            f"📋 Skill 质量门评估: {len(decisions)} 个候选",
            f"    ✅ 值得写: {len(worth)} 个",
            f"    ⏭ 跳过:   {len(skip)} 个",
        ]
        if worth:
            lines.append("")
            lines.append("  建议创建:")
            for d in worth:
                lines.append(f"    ★ {d.knowledge_point} — {d.source_quality}")
        if skip:
            lines.append("")
            lines.append("  已有覆盖的:")
            for d in skip[:10]:
                existing = f"→ 补充到 {d.existing_skill}" if d.existing_skill else ""
                lines.append(f"    · {d.knowledge_point} {existing}")

        return "\n".join(lines)


def should_create_skill(name: str, description: str = "",
                        source: str = "") -> SkillDecision:
    """快速判定: 是否值得写 Skill。"""
    return SkillQualityGate().evaluate(name, description, source)


def evaluate_candidates(candidates: list[dict]) -> list[SkillDecision]:
    """批量评估。"""
    return SkillQualityGate().evaluate_many(candidates)
