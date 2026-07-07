"""SkillUpgrader — FeedbackDB accepted techniques → auto-append to skill SKILL.md.

Closed loop: 挖洞产出 → FeedbackDB 累计 → 自动追加到技能文件 → Claude 下次加载生效
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from aimy.memory.feedback import FeedbackDB

SKILLS_DIR = Path(__file__).parent.parent.parent / "skills"

# vuln_class → skill directory (fuzzy match on vuln_class.lower())
VULN_TO_SKILL: dict[str, str] = {
    "ssrf":                              "ssrf-server-side-request-forgery",
    "sqli":                              "sqli-sql-injection",
    "sql injection":                     "sqli-sql-injection",
    "xss":                               "xss-cross-site-scripting",
    "idor":                              "idor-broken-object-authorization",
    "cmdi":                              "cmdi-command-injection",
    "command injection":                 "cmdi-command-injection",
    "ssti":                              "ssti-server-side-template-injection",
    "jwt":                               "jwt-oauth-token-attacks",
    "auth bypass":                       "authbypass-authentication-flaws",
    "authentication bypass":             "authbypass-authentication-flaws",
    "lfi":                               "path-traversal-lfi",
    "path traversal":                    "path-traversal-lfi",
    "xxe":                               "xxe-xml-external-entity",
    "csrf":                              "csrf-cross-site-request-forgery",
    "race condition":                    "race-condition",
    "race":                              "race-condition",
    "cors":                              "cors-cross-origin-misconfiguration",
    "graphql":                           "graphql-audit",
    "smuggling":                         "request-smuggling",
    "http smuggling":                    "request-smuggling",
    "cache":                             "web-cache-deception",
    "cache poisoning":                   "web-cache-deception",
    "prototype pollution":               "prototype-pollution",
    "403 bypass":                        "401-403-bypass-techniques",
    "401 bypass":                        "401-403-bypass-techniques",
    "business logic":                    "business-logic-vulnerabilities",
    "llm":                               "llm-prompt-injection",
    "prompt injection":                  "llm-prompt-injection",
    "subdomain takeover":                "subdomain-takeover",
    "takeover":                          "subdomain-takeover",
    "open redirect":                     "open-redirect",
    "waf":                               "waf-bypass-techniques",
    "waf bypass":                        "waf-bypass-techniques",
    "deserialization":                   "deserialization-insecure",
    "deser":                             "deserialization-insecure",
    "saml":                              "saml-sso-assertion-attacks",
    "file upload":                       "upload-insecure-files",
    "upload":                            "upload-insecure-files",
    "oauth":                             "oauth-oidc-misconfiguration",
    "dependency confusion":              "dependency-confusion",
    "rce":                               "cmdi-command-injection",
    "php local file inclusion":          "path-traversal-lfi",
    "privilege escalation":              "linux-privilege-escalation",
    "access control":                    "idor-broken-object-authorization",
    "missing authentication":           "authbypass-authentication-flaws",
    "missing authorization":            "idor-broken-object-authorization",
    "improper authentication":          "authbypass-authentication-flaws",
    "improper access control":          "idor-broken-object-authorization",
    "code injection":                   "cmdi-command-injection",
    "memory corruption":                "deserialization-insecure",
    "buffer over":                      "stack-overflow-and-rop",
    "heap overflow":                    "heap-exploitation",
    "reliance on cookies":              "csrf-cross-site-request-forgery",
    "use after free":                   "heap-exploitation",
    "out-of-bounds":                    "stack-overflow-and-rop",
    "null pointer":                     "stack-overflow-and-rop",
    "cryptographic issues":             "symmetric-cipher-attacks",
    "man-in-the-middle":                "network-protocol-attacks",
    "modification of assumed-immutable": "business-logic-vulnerabilities",
    "insufficiently protected cred":    "authbypass-authentication-flaws",
    "use of hard-coded credential":     "credential-attack",
    "cleartext storage":                "insecure-source-code-management",
    "privacy violation":                "insecure-source-code-management",
    "violation of secure design":       "authbypass-authentication-flaws",
    "inclusion of functionality":       "xss-cross-site-scripting",
    "business logic":                   "business-logic-vulnerabilities",
    "http request smuggling":           "request-smuggling",
    "crlf":                             "crlf-injection",
    "double free":                      "heap-exploitation",
    "information disclosure":           "insecure-source-code-management",
    "information exposure":             "insecure-source-code-management",
    "insufficient session":             "authbypass-authentication-flaws",
    "missing encryption":               "insecure-source-code-management",
    "missing required crypto":          "symmetric-cipher-attacks",
    "phishing":                         "credential-attack",
    "plaintext storage":                "insecure-source-code-management",
    "session fixation":                 "authbypass-authentication-flaws",
    "clickjacking":                     "clickjacking",
    "unverified password":              "authbypass-authentication-flaws",
    "inherently dangerous":             "cmdi-command-injection",
    "weak password recovery":           "authbypass-authentication-flaws",
    "incorrect calculation":            "stack-overflow-and-rop",
    "cleartext transmission":           "insecure-source-code-management",

    # ── CBH 企业身份/云IAM (新技能映射) ──
    "entra":                            "m365-entra-attack",
    "m365":                             "m365-entra-attack",
    "azure ad":                         "m365-entra-attack",
    "microsoft 365":                    "m365-entra-attack",
    "okta":                             "okta-attack",
    "okta sso":                         "okta-attack",
    "cloud iam":                        "cloud-iam-deep",
    "iam":                              "cloud-iam-deep",
    "evidence":                         "evidence-hygiene",
    "poC evidence":                     "evidence-hygiene",
    "poC hygiene":                      "evidence-hygiene",
    "hunt dispatch":                    "hunt-dispatch",
    "hunting dispatch":                 "hunt-dispatch",
    "vcenter":                          "vmware-vcenter-attack",
    "vmware":                           "vmware-vcenter-attack",
    "enterprise vpn":                   "enterprise-vpn-attack",
    "vpn":                              "enterprise-vpn-attack",
    "supply chain":                     "supply-chain-attack-recon",
    "supplychain":                      "supply-chain-attack-recon",
    "offensive osint":                  "offensive-osint",
    "osint offensive":                  "offensive-osint",
    "redteam mindset":                  "redteam-mindset",
    "red team mindset":                 "redteam-mindset",
    "springboot":                       "hunt-springboot",
    "spring boot":                      "hunt-springboot",
    "laravel":                          "hunt-laravel",
    "asp.net":                          "hunt-aspnet",
    "aspnet":                           "hunt-aspnet",
    "sharepoint":                       "hunt-sharepoint",
    "next.js":                          "hunt-nextjs",
    "nextjs":                           "hunt-nextjs",
    "node.js":                          "hunt-nodejs",
    "nodejs":                           "hunt-nodejs",
    "bb local toolkit":                 "bb-local-toolkit",
    "bugcrowd reporting":               "bugcrowd-reporting",
    "redteam report":                   "redteam-report-template",

    # ── bug-reaper 补充 — 白盒审计/链式攻击 ──
    "source code audit":                "source-code-audit",
    "whitebox":                         "source-code-audit",
    "white box":                        "source-code-audit",
    "vulnerability chaining":           "vulnerability-chaining",
    "chaining":                         "vulnerability-chaining",
    "exploit validation":               "exploit-validation",
    "exploit validate":                 "exploit-validation",
}

# H1 verbose name → short keyword (for fuzzy matching only, not skill mapping)
VERBOSE_TO_KEYWORD: dict[str, str] = {
    "missing authentication for critical": "auth bypass",
    "missing authorization":               "idor",
    "improper authentication":             "auth bypass",
    "improper access control":             "idor",
    "violation of secure design":          "auth bypass",
    "plaintext storage of a password":     "information disclosure",
    "insufficiently protected credentials":"information disclosure",
    "use of hard-coded cryptographic":     "information disclosure",
    "inclusion of functionality from":     "xss",
    "reliance on cookies without":         "csrf",
    "cleartext storage":                   "information disclosure",
    "cleartext transmission":              "information disclosure",
    "classic buffer overflow":             "stack overflow",
    "array index underflow":               "memory corruption",
    "buffer over-read":                    "memory corruption",
    "buffer underflow":                    "memory corruption",
    "double free":                         "heap exploitation",
    "cryptographic issues":                "information disclosure",
}

FLYWHEEL_MARKER = "<!-- FLYWHEEL_APPEND -->"


def _find_skill_file(vuln_class: str) -> Path | None:
    """Map vuln_class string to the SKILL.md file path."""
    vc = vuln_class.lower().strip()

    # Exact match
    if vc in VULN_TO_SKILL:
        path = SKILLS_DIR / VULN_TO_SKILL[vc] / "SKILL.md"
        if path.exists():
            return path

    # Substring match on VULN_TO_SKILL keys
    for key, skill_dir in VULN_TO_SKILL.items():
        if key in vc or vc in key:
            path = SKILLS_DIR / skill_dir / "SKILL.md"
            if path.exists():
                return path

    # Verbose H1 name → keyword → skill lookup
    if vc in VERBOSE_TO_KEYWORD:
        kw = VERBOSE_TO_KEYWORD[vc]
    else:
        kw = next((v for k, v in VERBOSE_TO_KEYWORD.items() if k in vc), "")
    if kw:
        for key, skill_dir in VULN_TO_SKILL.items():
            if key == kw or kw in key or key in kw:
                path = SKILLS_DIR / skill_dir / "SKILL.md"
                if path.exists():
                    return path

    # Search all skill dirs for name containing vuln_class
    # Only match words of >=4 chars to avoid false positives ("key" ≠ kerberos)
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if skill_md.exists() and (vc in skill_dir.name.lower() or
            any(w in skill_dir.name.lower() for w in vc.replace('-',' ').split() if len(w) >= 4)):
            return skill_md

    return None


def _ensure_marker(skill_path: Path) -> None:
    """Append the FLYWHEEL_MARKER to a skill file if it doesn't exist."""
    content = skill_path.read_text(encoding="utf-8")
    if FLYWHEEL_MARKER in content:
        return
    with open(skill_path, "a", encoding="utf-8") as f:
        f.write(f"\n\n{FLYWHEEL_MARKER}\n")
        f.write("<!-- 以下内容由 EVX 飞轮自动维护，手动编辑会被覆盖 -->\n")


def _read_flywheel_section(skill_path: Path) -> str:
    """Read only the flywheel-maintained section (after the marker)."""
    content = skill_path.read_text(encoding="utf-8")
    if FLYWHEEL_MARKER not in content:
        return ""
    return content.split(FLYWHEEL_MARKER, 1)[1]


def _write_flywheel_section(skill_path: Path, techniques: list[dict]) -> None:
    """Replace the flywheel section with the single best technique only."""
    content = skill_path.read_text(encoding="utf-8")
    if FLYWHEEL_MARKER in content:
        content = content.split(FLYWHEEL_MARKER, 1)[0].rstrip()

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    section = f"\n\n{FLYWHEEL_MARKER}\n"
    section += "<!-- 以下内容由 EVX 飞轮自动维护，手动编辑会被覆盖 -->\n"
    section += f"\n## 🔄 飞轮进化技法 (auto-updated {now})\n\n"
    section += "> 以下技法是该漏洞类型中**H1 真实 accept 记录里综合得分最高的一项**。\n"
    section += "> 遇到此类漏洞时**优先尝试此技法**。\n\n"

    if not techniques:
        section += "_暂无已验证技法。挖洞后 accept 的记录会自动追加到此文件。_\n"
    else:
        # Only the #1 best technique
        best = techniques[0]
        rate_pct = int(best.get("rate", 0) * 100)
        section += f"### 🏆 {best['technique']}\n\n"
        section += f"| 指标 | 值 |\n|------|----|\n"
        section += f"| 接受率 | **{rate_pct}%** ({best.get('accepted', 0)}/{best.get('total', 0)}) |\n"
        section += f"| 平均赏金 | ¥{best.get('avg_bounty', 0):,.0f} |\n"
        section += f"| 漏洞类型 | `{best.get('vuln_class', '')}` |\n\n"
        # Include payload hints from payloader
        payload_text = _find_payload_for_technique(best['technique'], best.get('vuln_class', ''))
        if payload_text:
            section += f"**已验证 Payload:**\n\n```\n{payload_text[:800]}\n```\n"

    with open(skill_path, "w", encoding="utf-8") as f:
        f.write(content + section)


def _find_payload_for_technique(technique: str, vuln_class: str) -> str:
    """Try to find existing payload content for a technique."""
    from aimy.memory.flywheel_learner import PAYLOAD_FILE_MAP
    vc = vuln_class.lower()
    tech = technique.lower()
    for key, path in PAYLOAD_FILE_MAP.items():
        if (key in tech or key in vc) and path.exists():
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Return the first payload block found
            blocks = re.findall(r'```(?:bash|http|curl)?\n(.*?)```', content, re.DOTALL)
            if blocks:
                return "\n".join(b[:200] for b in blocks[:3])
            return content[:500]
    return ""


def upgrade_skills(db_path: str = "", min_accepted: int = 2,
                   verbose: bool = True) -> dict:
    """Main entry: query FeedbackDB and upgrade matching skill files.

    Returns counts of upgraded files.
    """
    db = FeedbackDB(db_path) if db_path else FeedbackDB()
    all_scores = db.scores(min_submissions=min_accepted)
    db.close()

    # Group by vuln_class
    by_class: dict[str, list[dict]] = {}
    for s in all_scores:
        vc = s["vuln_class"]
        by_class.setdefault(vc, []).append(s)

    result = {"upgraded": 0, "skipped": 0, "missing_skill_file": 0}
    for vuln_class, techniques in sorted(by_class.items()):
        skill_path = _find_skill_file(vuln_class)
        if not skill_path:
            result["missing_skill_file"] += 1
            if verbose:
                print(f"  [!] 无对应技能文件: {vuln_class}")
            continue

        _ensure_marker(skill_path)
        # Only the #1 best technique per skill
        _write_flywheel_section(skill_path, techniques[:1])
        result["upgraded"] += 1
        if verbose:
            print(f"  [+] {skill_path.parent.name}/SKILL.md ← {techniques[0]['technique'][:50]}")

    return result


def upgrade_single(technique: str, vuln_class: str, outcome: str = "",
                   bounty: float = 0.0, verbose: bool = True) -> bool:
    """Upgrade a single technique into its skill file (called after accept)."""
    if outcome.lower() != "accepted":
        return False

    skill_path = _find_skill_file(vuln_class)
    if not skill_path:
        return False

    db = FeedbackDB()
    scores = db.scores(min_submissions=1)
    db.close()

    # Filter to this vuln_class
    relevant = [s for s in scores if vuln_class.lower() in s["vuln_class"].lower()]

    if not relevant:
        return False

    _ensure_marker(skill_path)
    _write_flywheel_section(skill_path, relevant[:1])  # Only #1
    if verbose:
        best_name = relevant[0]['technique'][:50] if relevant else '-'
        print(f"  [+] {skill_path.parent.name}/SKILL.md 飞轮更新 → {best_name}")
    return True


# ── h1飞轮 文档升级 ──────────────────────────────────────────────

H1_FLYWHEEL_DIR = SKILLS_DIR.parent / "彦的h1飞轮"
H1_FLYWHEEL_00 = H1_FLYWHEEL_DIR / "00_飞轮运转说明.md"
H1_FLYWHEEL_05 = H1_FLYWHEEL_DIR / "05_举一反三机制.md"


def upgrade_h1_flywheel_docs(verbose: bool = True) -> dict:
    """Update 00_飞轮运转说明 and 05_举一反三 with live EVX stats."""
    result = {"00_updated": False, "05_updated": False}

    # ── 00: live stats ──────────────────────────────────────────
    if H1_FLYWHEEL_00.exists():
        try:
            _write_h1_flywheel_00()
            result["00_updated"] = True
            if verbose:
                print(f"  [+] 彦的h1飞轮/00_飞轮运转说明.md 飞轮更新")
        except Exception as e:
            if verbose:
                print(f"  [!] 00_飞轮运转说明 更新失败: {e}")

    # ── 05: implementation state + technique counts ─────────────
    if H1_FLYWHEEL_05.exists():
        try:
            _write_h1_flywheel_05()
            result["05_updated"] = True
            if verbose:
                print(f"  [+] 彦的h1飞轮/05_举一反三机制.md 飞轮更新")
        except Exception as e:
            if verbose:
                print(f"  [!] 05_举一反三机制 更新失败: {e}")

    return result


def _write_h1_flywheel_00() -> None:
    """Write live EVX stats to 00_飞轮运转说明.md."""
    content = H1_FLYWHEEL_00.read_text(encoding="utf-8")
    if FLYWHEEL_MARKER in content:
        content = content.split(FLYWHEEL_MARKER, 1)[0].rstrip()

    db = FeedbackDB()
    stats = db.stats()
    top5 = db.scores(min_submissions=2)[:5]
    # Count skill files with flywheel data
    flywheel_count = 0
    for d in SKILLS_DIR.iterdir():
        if not d.is_dir():
            continue
        skill_md = d / "SKILL.md"
        if skill_md.exists():
            try:
                if FLYWHEEL_MARKER in skill_md.read_text(encoding="utf-8", errors="ignore"):
                    flywheel_count += 1
            except Exception:
                pass
    db.close()

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    section = f"""

{FLYWHEEL_MARKER}
<!-- 以下内容由 EVX 飞轮每小时自动更新 -->

## 📊 实时飞轮数据 (更新于 {now})

| 指标 | 值 |
|------|----|
| **累计 H1 报告** | {stats['total']} |
| **接受数** | {stats['accepted']} |
| **接受率** | {int(stats['rate'] * 100)}% |
| **累计赏金** | ¥{stats['total_bounty']:,.0f} |
| **已升级技能文件** | {flywheel_count} 个 |
| **飞轮阶段** | {'🟢 阶段3: 1000+案例，举一反三稳定' if stats['accepted'] >= 1000 else '🟡 阶段2: 100-1000案例，RAG开始有效' if stats['accepted'] >= 100 else '🔴 阶段1: <100案例，靠Payload库匹配'} |

### 🏆 Top-5 高命中技法

| # | 技法 | 类型 | 接受率 | 均赏金 |
|---|------|------|--------|--------|
"""
    for i, s in enumerate(top5, 1):
        section += f"| {i} | {s['technique'][:45]} | `{s['vuln_class']}` | **{int(s['rate'] * 100)}%** | ¥{s['avg_bounty']:,.0f} |\n"

    H1_FLYWHEEL_00.write_text(content + section, encoding="utf-8")


def _write_h1_flywheel_05() -> None:
    """Write live implementation state to 05_举一反三机制.md."""
    content = H1_FLYWHEEL_05.read_text(encoding="utf-8")
    if FLYWHEEL_MARKER in content:
        content = content.split(FLYWHEEL_MARKER, 1)[0].rstrip()

    db = FeedbackDB()
    stats = db.stats()
    top_techniques = db.top_techniques(n=40)
    db.close()

    # Count techniques per vuln class
    db2 = FeedbackDB()
    rows = db2._conn.execute(
        "SELECT vuln_class, COUNT(*) FROM reports WHERE outcome='accepted' GROUP BY vuln_class ORDER BY COUNT(*) DESC"
    ).fetchall()
    db2.close()
    top_vuln_names = [r[0] for r in rows[:5]]
    top_vuln_counts = [r[1] for r in rows[:5]]

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    phase = "3 (1000+案例)" if stats['accepted'] >= 1000 else "2 (100-1000案例)" if stats['accepted'] >= 100 else "1 (<100案例)"
    section = f"""

{FLYWHEEL_MARKER}
<!-- 以下内容由 EVX 飞轮每小时自动更新 -->

## 🔄 飞轮实时状态 (更新于 {now})

```
当前阶段: 阶段{phase}
累计接受: {stats['accepted']} 案例
已升级技能文件: {sum(1 for d in SKILLS_DIR.iterdir() if d.is_dir() and (d / 'SKILL.md').exists() and FLYWHEEL_MARKER in (d / 'SKILL.md').read_text(encoding='utf-8', errors='ignore'))} 个
```

### 实现状态

```
✅ Step 1: record_finding() — PatternDB + FeedbackDB + Journal 三层自动写入
✅ Step 2: TechniqueAtomizer.decompose() — 成功技法拆解为原子(injection_point/protocol/encoding)
✅ Step 3: TechniqueAtomizer.recombine() — 基于历史原子重组 N 个变体
✅ Step 4: 持续飞轮 — 每条记录实时升级 Payload 库 + 技能文件
✅ Step 5: H1 飞轮文档自动更新 — 本文件每小时刷新
✅ Step 6: 技能文件 FLYWHEEL_APPEND — 每类漏洞保留 #1 最优技法
{'✅' if stats['accepted'] >= 1000 else '⬜'} Step 7: 积累1000+案例后 fine-tune
```

### Top-5 漏洞类型技法数

"""
    for name, count in zip(top_vuln_names, top_vuln_counts):
        section += f"- **{name}**: {count} 条 accept\n"

    section += f"""
### SmartAtomizer 状态

```python
from aimy.memory.flywheel import TechniqueAtomizer
ta = TechniqueAtomizer()
# 当前可重组的技法原子来自 {len(top_techniques)} 个已验证技法
# 每个技法生成 3-6 个变体 → 可覆盖 {(stats['accepted'] * 3)}-{(stats['accepted'] * 6)} 个测试场景
```
"""

    H1_FLYWHEEL_05.write_text(content + section, encoding="utf-8")

    import argparse
    ap = argparse.ArgumentParser(description="Skill Upgrader — FeedbackDB → SKILL.md")
    ap.add_argument("--min-accepted", type=int, default=2, help="最低 accept 次数 (default: 2)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    result = upgrade_skills(min_accepted=args.min_accepted, verbose=not args.quiet)
    print(f"\nupgraded={result['upgraded']}  "
          f"missing_skill={result['missing_skill_file']}  "
          f"skipped={result['skipped']}")
