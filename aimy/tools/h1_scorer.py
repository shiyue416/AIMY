"""H1Scorer — HackerOne 报告 4维评分引擎

基于《邪修打法》PDF 评分体系:
  value_score = unexpectedness(0-3) + elegance(0-3) + chain(0-2) + reproducibility(0-2)

用法:
    from aimy.tools.h1_scorer import H1Scorer, score_report, rank_reports

    scorer = H1Scorer()
    result = scorer.score(report_data)
    # → {"value_score": 8, "verdict": "exceptional", ...}

批量:
    ranked = scorer.rank(reports_list)
    # → sorted by value_score desc
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional
from pathlib import Path

from aimy.tools.log_utils import get_logger

logger = get_logger("h1_scorer")

# ── 评分维度定义 ──────────────────────────────────────────────────
UNEXPECTEDNESS = "unexpectedness"   # 意外性 0-3
ELEGANCE = "elegance"               # 优雅度 0-3
CHAIN = "chain"                     # 利用链长度 0-2
REPRODUCIBILITY = "reproducibility" # 可复现性 0-2


@dataclass
class ScoreBreakdown:
    """四维评分明细"""
    unexpectedness: int = 0     # 0-3
    elegance: int = 0           # 0-3
    chain: int = 0              # 0-2
    reproducibility: int = 0    # 0-2

    @property
    def value_score(self) -> int:
        return self.unexpectedness + self.elegance + self.chain + self.reproducibility

    @property
    def verdict(self) -> str:
        vs = self.value_score
        if vs >= 7:
            return "exceptional"    # ★★★★ 写 Skill
        elif vs >= 5:
            return "noteworthy"     # ★★★  学习
        else:
            return "skip"           # ★★   过

    @property
    def stars(self) -> str:
        return {"exceptional": "★★★★", "noteworthy": "★★★", "skip": "★★"}.get(self.verdict, "★★")

    def to_dict(self) -> dict:
        return {
            "unexpectedness": self.unexpectedness,
            "elegance": self.elegance,
            "chain": self.chain,
            "reproducibility": self.reproducibility,
            "value_score": self.value_score,
            "verdict": self.verdict,
        }


@dataclass
class ScoredReport:
    """带评分的 H1 报告"""
    id: int
    title: str = ""
    url: str = ""
    severity: str = ""
    category: str = ""
    award: float = 0.0
    score: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    reasoning: str = ""
    attack_chain: str = ""
    bypass_technique: str = ""
    defensive_insight: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score.to_dict()
        return d


# ── 关键词启发式评分（不依赖 LLM 的快速版本） ──────────────────
_KEYWORD_WEIGHTS: dict[str, tuple[int, int, int, int]] = {
    # (unexpectedness, elegance, chain, reproducibility)
    "chain":          (2, 2, 2, 1),   # 利用链
    "bypass":         (2, 2, 1, 2),   # 绕过技巧
    "race":           (2, 1, 1, 0),   # 竞态条件
    "sandbox":        (3, 2, 1, 1),   # 沙箱逃逸
    "rce":            (1, 1, 1, 2),   # RCE
    "ssrf":           (1, 1, 1, 2),   # SSRF
    "idor":           (1, 1, 0, 2),   # IDOR
    "xss":            (0, 0, 0, 2),   # XSS
    "sqli":           (0, 0, 0, 2),   # SQL 注入
    "csrf":           (0, 0, 0, 2),   # CSRF
    "oauth":          (2, 1, 1, 1),   # OAuth
    "jwt":            (1, 1, 0, 2),   # JWT
    "prototype":      (2, 2, 1, 2),   # 原型链污染
    "graphql":        (1, 1, 1, 2),   # GraphQL
    "ssti":           (1, 1, 1, 1),   # SSTI
    "xxe":            (1, 1, 1, 2),   # XXE
    "deserialization":(2, 2, 2, 1),   # 反序列化
    "business":       (2, 2, 1, 1),   # 业务逻辑
    "logic":          (2, 2, 1, 1),   # 逻辑漏洞
    "information":    (0, 0, 0, 2),   # 信息泄露
    "misconfiguration":(0, 0, 0, 2),  # 配置错误
    "0day":           (3, 2, 2, 1),   # 0day
    "container":      (2, 1, 1, 1),   # 容器逃逸
    "kubernetes":     (2, 1, 1, 1),   # K8s
    "cloud":          (2, 1, 1, 1),   # 云安全
}

# 加重关键词（额外加分）
_BOOST_WORDS = [
    "blackhat", "defcon", "cansecwest", "usenix",
    "project zero", "google p0", "portswigger research",
    "novel", "unpublished", "0-day", "chain",
]

# 降级关键词（已经有大量 Skill 覆盖的）
_DEPRIORITIZE_WORDS = [
    "reflected xss", "open redirect", "self-xss",
    "information disclosure",
]


class H1Scorer:
    """H1 报告评分器 — 支持启发式和结构化两种模式。"""

    def __init__(self, use_heuristic: bool = True):
        self.use_heuristic = use_heuristic

    # ── 单报告评分 ──────────────────────────────────────────────

    def score(self, report: dict | ScoredReport,
              title: str = "", body: str = "", category: str = "",
              award: float = 0.0, report_id: int = 0) -> ScoredReport:
        """对一份报告评分。

        支持传入 dict 或裸字段。
        """
        if isinstance(report, ScoredReport):
            return self._score_scored(report)

        if isinstance(report, dict):
            title = report.get("title", report.get("vulnerability_information", ""))
            body = report.get("vulnerability_information", report.get("body", ""))
            category = report.get("category", report.get("weakness", ""))
            award = float(report.get("award", report.get("bounty", 0)))
            report_id = int(report.get("id", report.get("report_id", 0)))

        text = f"{title} {body}".lower()

        if self.use_heuristic:
            score = self._heuristic(text, category, award)
        else:
            score = ScoreBreakdown()

        # 提取关键信息
        return ScoredReport(
            id=report_id,
            title=title[:120] if isinstance(title, str) else str(title)[:120],
            severity=self._detect_severity(text, award),
            category=category,
            award=award,
            score=score,
            reasoning=self._generate_reasoning(text, score),
            attack_chain=self._extract_chain(text),
            bypass_technique=self._extract_bypass(text),
        )

    def _score_scored(self, report: ScoredReport) -> ScoredReport:
        """对已评分的报告重新打分（如果分数为 0）。"""
        if report.score.value_score > 0:
            return report
        text = f"{report.title} {report.reasoning}".lower()
        report.score = self._heuristic(text, report.category, report.award)
        report.reasoning = self._generate_reasoning(text, report.score)
        return report

    def _heuristic(self, text: str, category: str, award: float) -> ScoreBreakdown:
        """基于关键词的启发式评分。"""
        u, e, c, r = 0, 0, 0, 0

        # 基于漏洞类型的基准分
        for keyword, (ku, ke, kc, kr) in _KEYWORD_WEIGHTS.items():
            if keyword in text or keyword in category.lower():
                u = max(u, ku)
                e = max(e, ke)
                c = max(c, kc)
                r = max(r, kr)

        # 加分：高赏金
        if award >= 5000:
            e = min(3, e + 1)
            u = min(3, u + 1)
        elif award >= 2000:
            e = min(3, e + 1)

        # 加分：顶级会议/研究词汇
        for word in _BOOST_WORDS:
            if word in text:
                u = min(3, u + 1)
                e = min(3, e + 1)
                break

        # 降级：低价值类型
        for word in _DEPRIORITIZE_WORDS:
            if word in text:
                r = max(0, r - 1)
                break

        return ScoreBreakdown(
            unexpectedness=min(3, u),
            elegance=min(3, e),
            chain=min(2, c),
            reproducibility=min(2, r),
        )

    def _detect_severity(self, text: str, award: float) -> str:
        if "critical" in text or award >= 10000:
            return "critical"
        if "high" in text or award >= 3000:
            return "high"
        if "medium" in text or award >= 500:
            return "medium"
        return "low"

    def _generate_reasoning(self, text: str, score: ScoreBreakdown) -> str:
        parts = []
        if score.unexpectedness >= 2:
            parts.append("技巧性强，非标准检测能发现")
        if score.elegance >= 2:
            parts.append("利用链精妙，有学习价值")
        if score.chain >= 1:
            parts.append("多步组合，非单一漏洞")
        if score.reproducibility <= 0:
            parts.append("复现稳定性存疑")
        if score.value_score >= 7:
            parts.append("★★★ 高价值报告，建议详细学习并提炼 Skill")
        elif score.value_score >= 5:
            parts.append("★★ 中等价值，可参考思路")
        else:
            parts.append("★ 基础类型，已有充分覆盖")
        return "；".join(parts) if parts else "常规报告"

    def _extract_chain(self, text: str) -> str:
        # 简单启发式提取攻击链描述
        for pattern in [r"step[:\s]*\d+", r"attack chain[:\s]",
                         r"exploitation steps", r"to exploit"]:
            m = re.search(pattern + r".{0,200}", text, re.IGNORECASE)
            if m:
                return m.group()[:150]
        return ""

    def _extract_bypass(self, text: str) -> str:
        for pattern in [r"bypass[:\s]*\w+", r"evad[ei]", r"bypass technique"]:
            m = re.search(pattern + r".{0,100}", text, re.IGNORECASE)
            if m:
                return m.group()[:100]
        return ""

    # ── 批量评分 ────────────────────────────────────────────────

    def score_many(self, reports: list[dict | ScoredReport]) -> list[ScoredReport]:
        """批量评分，返回按 value_score 降序排列。"""
        scored = [self.score(r) for r in reports]
        return self.rank(scored)

    def rank(self, scored: list[ScoredReport]) -> list[ScoredReport]:
        """按 value_score 降序排列。"""
        return sorted(scored, key=lambda x: x.score.value_score, reverse=True)

    # ── 排序摘要 ────────────────────────────────────────────────

    def summary(self, scored: list[ScoredReport]) -> dict:
        """批量评分摘要统计。"""
        if not scored:
            return {"total": 0, "exceptional": 0, "noteworthy": 0, "skip": 0, "avg_score": 0.0}

        n = len(scored)
        exceptional = sum(1 for r in scored if r.score.verdict == "exceptional")
        noteworthy = sum(1 for r in scored if r.score.verdict == "noteworthy")
        skip = sum(1 for r in scored if r.score.verdict == "skip")
        avg = sum(r.score.value_score for r in scored) / n

        return {
            "total": n,
            "exceptional": exceptional,
            "noteworthy": noteworthy,
            "skip": skip,
            "avg_score": round(avg, 1),
            "top_reports": [r.to_dict() for r in scored[:5]],
        }

    def summary_text(self, scored: list[ScoredReport]) -> str:
        """可读的摘要文本。"""
        s = self.summary(scored)
        lines = [
            f"📊 H1 报告评分: 共 {s['total']} 份",
            f"    ★★★★ exceptional: {s['exceptional']} 份（建议写 Skill）",
            f"    ★★★  noteworthy:  {s['noteworthy']} 份（建议学习）",
            f"    ★★   skip:        {s['skip']} 份（已有覆盖）",
            f"    均分: {s['avg_score']}",
        ]
        if s.get("top_reports"):
            lines.append("   Top 5:")
            for r in s["top_reports"][:5]:
                vs = r["score"]["value_score"]
                title = r["title"][:60]
                lines.append(f"      [{vs}] {title}")
        return "\n".join(lines)

    # ── 持久化 ──────────────────────────────────────────────────

    def save_ranking(self, scored: list[ScoredReport],
                     path: str | Path = "") -> Path:
        """保存评分结果到 JSONL。"""
        if not path:
            path = Path.home() / ".aimy" / "h1_rankings.jsonl"
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            for r in scored:
                f.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")

        logger.info(f"Saved {len(scored)} scored reports to {path}")
        return path

    def load_ranking(self, path: str | Path = "") -> list[ScoredReport]:
        """加载历史评分。"""
        if not path:
            path = Path.home() / ".aimy" / "h1_rankings.jsonl"
        path = Path(path)
        if not path.exists():
            return []

        reports = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    sd = ScoreBreakdown(**data.get("score", {}))
                    reports.append(ScoredReport(
                        id=data.get("id", 0),
                        title=data.get("title", ""),
                        score=sd,
                        **{k: data.get(k, "") for k in
                           ["url", "severity", "category", "reasoning",
                            "attack_chain", "bypass_technique",
                            "defensive_insight", "created_at"]}
                    ))
                except Exception:
                    continue
        return reports


# ── 便捷函数 ──────────────────────────────────────────────────────

def score_report(report: dict) -> ScoredReport:
    """快速评分配置。"""
    return H1Scorer().score(report)


def rank_reports(reports: list[dict]) -> list[ScoredReport]:
    """快速批量评分 + 排序。"""
    return H1Scorer().score_many(reports)


def summary_text(reports: list[dict]) -> str:
    """快速摘要。"""
    scored = H1Scorer().score_many(reports)
    return H1Scorer().summary_text(scored)
