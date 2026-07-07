"""AutoJudge — 自动化验证流水线（不需要经验）

四步验证链:
  Step 1: Validator 重放    (curl重新发一次, True/False)
  Step 2: H1Scorer 打分     (value_score 0-10)
  Step 3: PatternDB 查历史   (类似技法被accepted/rejected? )
  Step 4: H1案例对比         (看H1上同类洞长什么样)

输出:
  verdict: confirmed / suspicious / rejected
  confidence: 0.0 - 1.0
  recommended_action: 写报告 / 学案例 / 放弃
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from aimy.tools.log_utils import get_logger

logger = get_logger("auto_judge")

# colours
G = "\033[0;32m"; Y = "\033[1;33m"
C = "\033[0;36m"; B = "\033[1m"; D = "\033[2m"
R = "\033[0;31m"; NC = "\033[0m"


@dataclass
class Finding:
    """一个待验证的发现"""
    vuln_class: str
    url: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    title: str = ""
    id: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    """验证结论"""
    verdict: str = "pending"       # confirmed / suspicious / rejected
    confidence: float = 0.0        # 0.0 - 1.0
    value_score: int = 0           # H1Scorer 评分
    validator_result: str = ""     # True / False / not_run
    pattern_match: str = ""        # accepted / rejected / no_history
    similar_h1_count: int = 0      # H1 同类报告数
    reasoning: list[str] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        stars = {"confirmed": "★★★", "suspicious": "★★", "rejected": "★"}
        return f"{stars.get(self.verdict, '?')} {self.verdict} (confidence={self.confidence:.0%})"


class AutoJudge:
    """自动化验证流水线 — 不需要安全经验。"""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    # ── 主入口 ──────────────────────────────────────────────────

    def judge(self, finding: Finding | dict) -> Verdict:
        """四步验证一个发现。"""
        if isinstance(finding, dict):
            finding = Finding(**{k: v for k, v in finding.items()
                                  if k in Finding.__dataclass_fields__})

        verdict = Verdict()
        reasoning = []

        print(f"\n{C}{'='*50}{NC}")
        print(f"{B}AutoJudge — {finding.vuln_class} @ {finding.url[:80]}{NC}")
        print(f"{C}{'='*50}{NC}")

        # Step 1: Validator 重放 ─────────────────────────────────
        self._step(1, "Validator 重放")
        v_result = self._run_validator(finding)
        verdict.validator_result = "True" if v_result else "False"
        if v_result:
            reasoning.append(f"Validator 重放确认")
            verdict.confidence += 0.4
        else:
            reasoning.append(f"Validator 重放未确认（可能无回显/WAF/参数不对）")

        # Step 2: H1Scorer 打分 ──────────────────────────────────
        self._step(2, "H1Scorer 打分")
        score = self._run_h1_scorer(finding)
        verdict.value_score = score
        if score >= 7:
            reasoning.append(f"H1评分{score}/10 — 高价值")
            verdict.confidence += 0.3
        elif score >= 5:
            reasoning.append(f"H1评分{score}/10 — 中等价值")
            verdict.confidence += 0.15
        else:
            reasoning.append(f"H1评分{score}/10 — 低分（常规漏洞）")
            verdict.confidence -= 0.1

        # Step 3: PatternDB 查历史 ────────────────────────────────
        self._step(3, "PatternDB 历史匹配")
        p_result = self._check_pattern(finding)
        verdict.pattern_match = p_result
        if p_result == "accepted":
            reasoning.append(f"类似技法之前被 accepted")
            verdict.confidence += 0.2
        elif p_result == "rejected":
            reasoning.append(f"类似技法之前被 rejected")
            verdict.confidence -= 0.3
        else:
            reasoning.append(f"无历史记录")

        # Step 4: H1案例对比 ─────────────────────────────────────
        self._step(4, "H1 案例对比")
        h1_count = self._check_h1_cases(finding)
        verdict.similar_h1_count = h1_count
        if h1_count > 10:
            reasoning.append(f"H1上 {h1_count}+ 同类案例 — 成熟漏洞类")
            verdict.confidence += 0.1
        elif h1_count > 0:
            reasoning.append(f"H1上有 {h1_count} 个同类案例")
        else:
            reasoning.append(f"H1上无直接匹配案例")

        # ── 最终 verdict ────────────────────────────────────────
        verdict.confidence = max(0.0, min(1.0, verdict.confidence))

        if verdict.confidence >= 0.7:
            verdict.verdict = "confirmed"
            verdict.recommended_action = "写报告提交"
        elif verdict.confidence >= 0.3:
            verdict.verdict = "suspicious"
            verdict.recommended_action = "先学H1同类案例再决定"
        else:
            verdict.verdict = "rejected"
            verdict.recommended_action = "建议放弃"

        verdict.reasoning = reasoning
        self._print_result(verdict)
        return verdict

    # ── Step 1: Validator ───────────────────────────────────────

    def _run_validator(self, finding: Finding) -> bool:
        """用 Validator 重放验证。"""
        try:
            from aimy.tools.validator import Validator
            v = Validator(verbose=False)

            # 构造验证参数
            result = v.validate(
                vuln_class=finding.vuln_class,
                url=finding.url,
                payload=finding.payload,
            )
            ok = result.verdict == "confirmed"
            if self.verbose:
                status = f"{G}[v] 通过{NC}" if ok else f"{Y}[!] 未确认{NC}"
                print(f"  {status}", end="")
                if result.reason:
                    print(f"  {D}{result.reason[:100]}{NC}")
                else:
                    print()
            return ok
        except Exception as e:
            if self.verbose:
                print(f"  {Y}[!] 跳过: {e}{NC}")
            return False

    # ── Step 2: H1Scorer ───────────────────────────────────────

    def _run_h1_scorer(self, finding: Finding) -> int:
        """H1 报告评分。"""
        try:
            from aimy.tools.h1_scorer import H1Scorer
            s = H1Scorer()
            scored = s.score({
                "id": finding.id,
                "title": finding.title or finding.vuln_class,
                "vulnerability_information": finding.evidence,
                "category": finding.vuln_class,
                "award": 0,
            })
            if self.verbose:
                print(f"  value_score={scored.score.value_score}/10 {scored.score.verdict}")
            return scored.score.value_score
        except Exception as e:
            if self.verbose:
                print(f"  {Y}[!] 跳过: {e}{NC}")
            return 0

    # ── Step 3: PatternDB ──────────────────────────────────────

    def _check_pattern(self, finding: Finding) -> str:
        """查历史记录中类似技法的结果。"""
        try:
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            # 搜最近30条同类漏洞
            rows = db._conn.execute(
                """SELECT outcome FROM reports
                   WHERE vuln_class=? ORDER BY id DESC LIMIT 30""",
                (finding.vuln_class,)
            ).fetchall()
            db.close()

            if not rows:
                return "no_history"

            accepted = sum(1 for r in rows if r[0] == "accepted")
            rejected = sum(1 for r in rows if r[0] != "accepted")

            if self.verbose:
                print(f"  同类历史: accept={accepted} reject={rejected} / {len(rows)}")

            return "accepted" if accepted > rejected else "rejected"
        except Exception as e:
            if self.verbose:
                print(f"  {Y}[!] 跳过: {e}{NC}")
            return "no_history"

    # ── Step 4: H1案例 ─────────────────────────────────────────

    def _check_h1_cases(self, finding: Finding) -> int:
        """统计 H1 案例库中同类报告数。"""
        base = Path(__file__).parent.parent / "references" / "h1-reports" / "by-weakness"
        if not base.exists():
            return 0

        # 映射漏洞类到H1分类文件名
        vuln_map = {
            "ssrf": "server-side-request-forgery-ssrf",
            "sqli": "blind-sql-injection",
            "xss": "cross-site-scripting-xss",
            "idor": "insecure-direct-object-reference-idor",
            "xxe": "xml-external-entity-xxe",
            "cmdi": "code-injection",
            "ssti": "server-side-template-injection-ssti",
            "lfi": "path-traversal",
            "cors": "cors",
            "csrf": "cross-site-request-forgery-csrf",
            "jwt": "jwt",
        }

            # 找H1报告文件
        h1_key = vuln_map.get(finding.vuln_class.lower(), "")
        if not h1_key:
            pattern = f"*{finding.vuln_class.lower()}*"
            matches = list(base.glob(pattern))
            if not matches:
                return 0
            h1_key = matches[0].stem

        h1_file = base / f"{h1_key}.md"
        if not h1_file.exists():
            return 0

        # 统计报告数（行数约等于报告数）
        count = sum(1 for _ in open(h1_file, encoding="utf-8"))
        if self.verbose:
            print(f"  H1案例: {h1_key}.md ({count} 行)")
        return count

    # ── 辅助 ───────────────────────────────────────────────────

    def _step(self, n: int, name: str):
        if self.verbose:
            print(f"\n  {D}[{n}/4] {name}{NC}")

    def _print_result(self, v: Verdict):
        stars = {"confirmed": "★★★", "suspicious": "★★", "rejected": "★"}
        print(f"\n  {B}结果: {stars.get(v.verdict, '?')} {G if v.verdict=='confirmed' else Y if v.verdict=='suspicious' else R}{v.verdict}{NC}")
        print(f"  置信度: {v.confidence:.0%}")
        print(f"  建议: {v.recommended_action}")
        for r in v.reasoning:
            print(f"    {D}→ {r}{NC}")


# ── 快速入口 ──────────────────────────────────────────────────

def judge_finding(vuln_class: str, url: str = "",
                  param: str = "", payload: str = "",
                  evidence: str = "", **kwargs) -> Verdict:
    """快速验证一条发现。"""
    finding = Finding(
        vuln_class=vuln_class, url=url,
        param=param, payload=payload, evidence=evidence,
        **{k: v for k, v in kwargs.items() if k in Finding.__dataclass_fields__}
    )
    return AutoJudge().judge(finding)


# ── CLI ────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="AutoJudge — 自动化验证")
    ap.add_argument("vuln_class", help="漏洞类 (ssrf/sqli/xss/...)")
    ap.add_argument("--url", required=True, help="目标URL")
    ap.add_argument("--param", default="", help="参数名")
    ap.add_argument("--payload", default="", help="payload")
    ap.add_argument("--evidence", default="", help="证据文本")
    args = ap.parse_args()

    result = judge_finding(**vars(args))
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
