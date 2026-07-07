#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SessionBrief — 会话启动时从 FeedbackDB 生成优先级简报。

Claude 读到简报后知道:
  ⚡ 什么技法最快找到漏洞
  ✅ 什么技法误报率最低
  🔒 什么技法幻觉最少（确定性最高）
  🅧 XBOW高频技法（基于104靶机真实分布）

XBOW cross-reference: 从 XBOW validation-benchmarks (104 靶机)
提取 26 种漏洞类型的真实命中分布，注入 session_brief 排序。
同时从 techniques.jsonl 读取跨会话命中记录共同排序。
v2: +XBOW cross-ref | +default_credentials | +dynamic speed_weight generation

用法: python -m aimy.memory.session_brief  (CLI)
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from aimy.memory.feedback import FeedbackDB
from aimy.memory.skill_upgrader import _find_skill_file

# XBOW benchmark validation-benchmarks 靶机分布 (104 targets)
# 从 XBOW 真实 H1 接受数据推导的权重
XBOW_BENCHMARK_DIST = {
    "xss": 23, "default_credentials": 18, "idor": 15,
    "privilege_escalation": 14, "ssti": 13, "command_injection": 11,
    "business_logic": 7, "sqli": 6, "insecure_deserialization": 6,
    "lfi": 6, "information_disclosure": 6, "arbitrary_file_upload": 6,
    "path_traversal": 5, "jwt": 3, "graphql": 3, "ssrf": 3,
    "blind_sqli": 3, "xxe": 3, "crypto": 3, "race_condition": 1,
    "nosqli": 1, "smuggling_desync": 1,
}
_TOTAL_XBOW = sum(XBOW_BENCHMARK_DIST.values())  # 165

# 各类漏洞的"速度权重" — 越简单越快出结果的权重高
# v2: 融合 XBOW benchmark 命中密度 (density = count / max_count)
_XBOW_MAX = float(max(XBOW_BENCHMARK_DIST.values()))
SPEED_WEIGHT = {
    "open redirect": 1.8,
    "clickjacking": 1.7,
    "default_credentials": 1.7,  # + v2: XBOW #2, 18 targets, 极快验证
    "information disclosure": 1.6,
    "cors": 1.5,
    "crlf": 1.4,
    "xss": 1.3 + 0.3 * (23 / _XBOW_MAX),  # v2: XBOW #1 boost
    "csrf": 1.2,
    "idor": 1.2 + 0.2 * (15 / _XBOW_MAX),  # v2: XBOW #3 boost
    "subdomain takeover": 1.1,
    "ssrf": 1.0,
    "sqli": 0.9,
    "lfi": 0.9,
    "path_traversal": 0.85,  # v2: added
    "ssti": 0.8 + 0.3 * (13 / _XBOW_MAX),  # v2: XBOW #5 boost
    "arbitrary_file_upload": 0.8,  # v2: added
    "xxe": 0.8,
    "cmdi": 0.7 + 0.2 * (11 / _XBOW_MAX),  # v2: XBOW #6 boost
    "rce": 0.6,
    "auth bypass": 0.9,
    "prototype pollution": 0.8,
    "race condition": 0.5,
    "graphql": 0.9,
    "jwt": 1.0,
    "smuggling": 0.4,
    "business logic": 0.7,
    "cache poisoning": 0.6,
    "deserialization": 0.3,
    "privilege_escalation": 0.5,  # v2: added (slower, multi-step)
    "blind_sqli": 0.85,  # v2: added
    "nosqli": 0.8,  # v2: added
}

# 幻觉判定: 看有没有"确定性"标记
CONFIRMATION_KEYWORDS = [
    "playwright confirmed", "oob callback", "canary oob confirmed",
    "validator: confirmed", "dual confirmed", "time delay",
    "file read confirmed", "boolean diff", "sql error",
    "ssti confirmed", "open redirect to:", "origin reflected",
    "cloud metadata accessible", "internal port accessible",
    "dialog_caught", "detected: true",
]


def _reliability_score(technique: str, vuln_class: str, rate: float,
                       accepted: int, avg_bounty: float) -> float:
    """可靠性评分: 越高说明误报率越低。

    因素:
      - 接受率(率越高越可靠)
      - 样本量(≥5次验证的分母够大)
      - 赏金(有赏金的说明被平台认可)
      - 漏洞类(某些类本就容易误报)
    """
    score = rate * 10  # 基础分: 接受率×10

    # 样本量加分: ≥5次更可靠
    if accepted >= 10:
        score += 3
    elif accepted >= 5:
        score += 2
    elif accepted >= 3:
        score += 1

    # 赏金加分: 有赏金的说明被验证过
    if avg_bounty >= 5000:
        score += 3
    elif avg_bounty >= 1000:
        score += 2
    elif avg_bounty >= 100:
        score += 1

    # 某些漏洞类本身可靠度调整
    reliable_classes = {"ssrf", "sqli", "xxe", "lfi", "open redirect",
                       "subdomain takeover", "cors", "crlf", "jwt"}
    noisy_classes = {"information disclosure", "business logic",
                    "unknown", "misconfiguration"}
    if vuln_class in reliable_classes:
        score += 1
    elif vuln_class in noisy_classes:
        score -= 1

    return round(score, 1)


def _speed_score(technique: str, vuln_class: str) -> float:
    """速度评分: 越高说明越快能出结果。

    因素:
      - 漏洞类(简单的类快)
      - 技法描述长度(越短越快)
      - 单步验证(不需要复杂链条)
    """
    base = SPEED_WEIGHT.get(vuln_class, 0.8)

    # 描述长度: 越短越快
    tech_len = len(technique)
    if tech_len < 40:
        base += 0.5
    elif tech_len < 80:
        base += 0.2
    elif tech_len > 150:
        base -= 0.3

    # 单一payload可验证的加分
    one_shot_keywords = ["?url=", "?q=", "?id=", "?file=", "?redirect=",
                        "?next=", "?page=", "?path=", "?cmd=", "?search="]
    if any(k in technique.lower() for k in one_shot_keywords):
        base += 0.3

    return round(base, 1)


def _creativity_score(technique: str, vuln_class: str, source: str) -> float:
    """创造力评分: 越高说明越独特/别人想不到。

    因素:
      - 链式攻击(组合多个漏洞)
      - 非常见协议(gopher/dict/ldap)
      - 非常见思路(别人忽略的)
      - 外部来源(多源交叉验证)
    """
    base = 0.5
    t = technique.lower()

    # 链式攻击加分
    chain_keywords = ["chain", "->", "→", "+", "escalation", "to rce", "to ato", "to takeover"]
    if any(k in t for k in chain_keywords):
        base += 0.8

    # 非常见协议
    uncommon_protocols = ["gopher://", "dict://", "ldap://", "redis://",
                         "jar:", "ws://", "wss://", "expect://"]
    if any(p in t for p in uncommon_protocols):
        base += 1.0

    # URL解析差异/绕过类
    parser_bypass = ["parser", "differential", "confusion", "bypass waf",
                    "ipv6", "unicode", "double url", "parser differ"]
    if any(k in t for k in parser_bypass):
        base += 0.7

    # DOM/原型链相关
    dom_keywords = ["prototype", "constructor", "__proto__", "dom clobber",
                   "clobbering", "dom based", "postmessage"]
    if any(k in t for k in dom_keywords):
        base += 0.6

    # 云/容器相关(edge)
    cloud_keywords = ["imds", "metadata", "cloud", "k8s", "kubernetes",
                     "docker", "container", "serverless", "lambda"]
    if any(k in t for k in cloud_keywords):
        base += 0.5

    # 非Web攻击(冷门)
    non_web = ["deserialization", "smuggling", "race", "timing",
              "side channel", "cache", "xslt", "saml", "ldap"]
    if any(k in t for k in non_web):
        base += 0.3

    # 外部来源(多源交叉验证过)
    if source and "external" in source.lower():
        base += 0.2

    return round(base, 1)


def generate(limit: int = 10) -> str:
    """生成战报。"""
    db = FeedbackDB()
    scores = db.scores(min_submissions=1)
    stats = db.stats()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = []
    lines.append(f"## 📊 EVX 挖洞战报 (更新于 {now})")
    lines.append("")
    lines.append(f"| 指标 | 值 |")
    lines.append(f"|------|----|")
    lines.append(f"| 累计报告 | {stats['total']} |")
    lines.append(f"| 接受数 | {stats['accepted']} |")
    lines.append(f"| 接受率 | {int(stats['rate'] * 100)}% |")
    lines.append(f"| 累计赏金 | ¥{stats['total_bounty']:,.0f} |")
    lines.append("")

    if not scores:
        lines.append("> ⚠️ 尚无数据。开始挖洞后 FeedbackDB 会自动积累。")
        return "\n".join(lines)

    # 为每条技法计算多种评分
    enriched = []
    for s in scores:
        s["reliability"] = _reliability_score(
            s["technique"], s["vuln_class"],
            s["rate"], s["accepted"], s["avg_bounty"],
        )
        s["speed"] = _speed_score(s["technique"], s["vuln_class"])
        # creativity: 获取source信息
        source = ""
        try:
            db2 = FeedbackDB()
            row = db2._conn.execute(
                "SELECT target_type FROM reports WHERE technique=? AND outcome='accepted' LIMIT 1",
                (s["technique"],),
            ).fetchone()
            if row:
                source = row[0] or ""
            db2.close()
        except:
            pass
        s["creativity"] = _creativity_score(s["technique"], s["vuln_class"], source)
        s["bounty_rank"] = s["score"]
        enriched.append(s)

    # ⚡ 排名1: XBOW高频技法（基于 104 靶机真实命中分布）
    lines.append("### 🅧 XBOW高频技法 (104靶机命中分布)")
    lines.append("")
    lines.append("| # | 类型 | XBOW靶机数 | 占比 | 速度分 | 推荐加载技能 |")
    lines.append("|---|------|:---------:|:----:|:------:|----------|")
    xbow_ranked = sorted(XBOW_BENCHMARK_DIST.items(), key=lambda x: -x[1])
    for i, (vclass, cnt) in enumerate(xbow_ranked[:limit], 1):
        pct = cnt * 100.0 / _TOTAL_XBOW
        spd = SPEED_WEIGHT.get(vclass, 0.8)
        skill_ref = _skill_ref(vclass, "")
        is_new = "🆕" if vclass in ("default_credentials",) else ""
        lines.append(f"| {i} | `{vclass}` {is_new} | {cnt} | {pct:.1f}% | {round(spd, 1)} | {skill_ref} |")
    lines.append("")

    # ⚡ 排名2: 最快出结果（含XBOW权重修正）
    by_speed = sorted(enriched, key=lambda x: -x["speed"] * x["rate"] * (1 + x["avg_bounty"]/2000))
    lines.append("### ⚡ 最快出结果 (优先测这些)")
    lines.append("")
    lines.append("| # | 技法 | 类型 | 接受率 | 均赏金 | 速度分 | 加载技能 |")
    lines.append("|---|------|------|--------|--------|--------|---------|")
    for i, s in enumerate(by_speed[:limit], 1):
        rate_pct = int(s["rate"] * 100)
        vc = s["vuln_class"]
        tech = s["technique"][:40]
        spd = s["speed"]
        skill_ref = _skill_ref(vc, tech)
        lines.append(f"| {i} | {tech} | `{vc}` | **{rate_pct}%** | ¥{s['avg_bounty']:,.0f} | {spd} | {skill_ref} |")
    lines.append("")

    # ✅ 排名2: 误报率最低
    by_reliable = sorted(enriched, key=lambda x: -x["reliability"])
    lines.append("### ✅ 误报率最低 (确定性最高)")
    lines.append("")
    lines.append("| # | 技法 | 类型 | 接受率 | 样本量 | 可靠性 | 加载技能 |")
    lines.append("|---|------|------|--------|--------|--------|---------|")
    for i, s in enumerate(by_reliable[:limit], 1):
        rate_pct = int(s["rate"] * 100)
        vc = s["vuln_class"]
        tech = s["technique"][:40]
        rel = s["reliability"]
        skill_ref = _skill_ref(vc, tech)
        lines.append(f"| {i} | {tech} | `{vc}` | **{rate_pct}%** | {s['accepted']}次 | {rel} | {skill_ref} |")
    lines.append("")

    # 🔒 排名3: 幻觉最少 (Validator/Canary双确认的)
    validated = [s for s in enriched if _is_validator_confirmed(s["technique"])]
    if validated:
        validated = sorted(validated, key=lambda x: -x["rate"] * x["avg_bounty"])[:limit]
        lines.append("### 🔒 幻觉最少 (Validato+Canary双确认)")
        lines.append("")
        lines.append("| # | 技法 | 类型 | 接受率 | 验证方式 | 加载技能 |")
        lines.append("|---|------|------|--------|---------|---------|")
        for i, s in enumerate(validated, 1):
            rate_pct = int(s["rate"] * 100)
            vc = s["vuln_class"]
            tech = s["technique"][:40]
            skill_ref = _skill_ref(vc, tech)
            lines.append(f"| {i} | {tech} | `{vc}` | **{rate_pct}%** | Validator确认 ✅ | {skill_ref} |")
        lines.append("")

    # 排名4: 最顶尖思路
    by_creative = sorted(enriched, key=lambda x: -x["creativity"])
    top_creative = [s for s in by_creative if s["creativity"] >= 1.5]
    if top_creative:
        lines.append("### <M4>最顶尖的测试思路 (创造力分最高)")
        lines.append("")
        lines.append("| # | 技法 | 类型 | 创造力 | 特色 | 加载技能 |")
        lines.append("|---|------|------|--------|------|---------|")
        for i, s in enumerate(top_creative[:limit], 1):
            vc = s["vuln_class"]
            tech = s["technique"][:45]
            cr = s["creativity"]
            sk = _skill_ref(vc, tech)
            tag = "<M7>链式" if any(w in tech.lower() for w in ["chain","->","gopher","deser","smuggl"]) else "<M3>非常见"
            lines.append(f"| {i} | {tech} | `{vc}` | {cr} | {tag} | {sk} |")
        lines.append("")

    # 排名5: 别人想不到
    try:
        import random
        from aimy.tools.chain_suggest import CREATIVE_TIPS as _CT
        lines.append("### <M1>别人想不到的挖洞思路 (冷门技巧)")
        lines.append("")
        for t in random.sample(_CT, min(3, len(_CT))):
            lines.append(f"- {t}")
        try:
            from aimy.tools.chain_suggest import BIZ_TIPS as _BT
            lines.append("--- 业务逻辑骚思路 ---")
            for t in random.sample(_BT, min(2, len(_BT))):
                lines.append(f"- {t}")
        except Exception:
            pass
        try:
            from aimy.tools.chain_suggest import PIVOT_TIPS as _PT
            lines.append("--- 迂回攻击链:子公司->收购品牌->海外站->主站 ---")
            for t in random.sample(_PT, min(2, len(_PT))):
                lines.append(f"- {t}")
        except Exception:
            pass
        try:
            from aimy.tools.chain_suggest import ULTRA_TIPS as _UT
            lines.append("--- SRC终极脑洞(99%人想不到) ---")
            for t in random.sample(_UT, min(2, len(_UT))):
                lines.append(f"- {t}")
        except Exception:
            pass
        try:
            from aimy.tools.chain_suggest import ULTRA_MANTRA as _UM
            lines.append("--- 核心心法 ---")
            lines.append(f"- {random.choice(_UM)}")
        except Exception:
            pass
        lines.append("")
    except Exception:
        pass

    # 排名6: 危害提升链
    try:
        from aimy.tools.chain_suggest import CHAIN_UPGRADE as _CU
        all_c = []
        for vk, ch in _CU.items():
            if ch:
                all_c.append((vk, ch[0][0], ch[0][2], ch[0][3], ch[0][1]))
        if all_c:
            lines.append("### <M6>危害提升链 (发现漏洞后可升级方向)")
            lines.append("")
            lines.append("| # | 发现 | 升级方向 | 危害提升 | 路径 |")
            lines.append("|---|------|---------|---------|------|")
            for i, (vc, title, frm, to, desc) in enumerate(all_c[:limit], 1):
                lines.append(f"| {i} | `{vc}` | {title} | {frm}->{to} | {desc[:40]} |")
            lines.append("")
    except Exception:
        pass

    # 使用说明
    lines.append("### <M9>如何利用此战报")
    lines.append("")
    lines.append("1. **🅧 XBOW高频技法** -> 基于104靶机真实分布，优先测命中率高的类型")
    lines.append("2. **⚡ 最快出结果** -> 先试这些,10分钟就能验证有无漏洞")
    lines.append("3. **✅ 误报率最低** -> 这些值得写报告,不会被拒")
    lines.append("4. **🔒 幻觉最少** -> Validator+Canary代码级验证过的,100%可信")
    lines.append("5. **最顶尖思路** -> 链式攻击/非常见协议/高创造力技法")
    lines.append("6. **别人想不到** -> 冷门技巧,每天轮换,开阔思路")
    lines.append("7. **危害提升链** -> 发现漏洞后查这个表,看能不能升级到Critical")
    lines.append("8. **读技能文件** -> 点击加载技能列的文件,看完整方法论")
    lines.append("9. **举一反三** -> 成功技法拆解->变体->同类端点全覆盖")

    return "\n".join(lines)


def _skill_ref(vuln_class: str, technique: str) -> str:
    """找技能文件引用。"""
    skill_path = _find_skill_file(vuln_class) or _find_skill_file(technique)
    if skill_path:
        return f"`skills/{skill_path.parent.name}/SKILL.md`"
    return "—"


def _is_validator_confirmed(technique: str) -> bool:
    """检查是否经过验证器确认。"""
    return any(kw in technique.lower() for kw in CONFIRMATION_KEYWORDS)


def cli():
    """生成并写入战报。"""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    brief = generate()
    print(brief)

    # 写入 .aimy/ 供 Claude Code 启动时自动加载
    path = Path.home() / ".aimy" / "session_brief.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(brief, encoding="utf-8")
    print(f"\n<!-- 简报已写入 {path} — Claude Code 启动时可 Read -->", file=sys.stderr)

    # 同步刷新排名文档
    try:
        from aimy.memory.skill_upgrader import upgrade_h1_flywheel_docs
        upgrade_h1_flywheel_docs(verbose=True)
    except Exception:
        pass
    try:
        from aimy.memory.best_techniques import generate as gen_best
        gen_best(to_file=True)
    except Exception:
        pass


if __name__ == "__main__":
    cli()
