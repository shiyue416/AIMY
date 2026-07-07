#!/usr/bin/env python3
"""Inject pentest-agents / Claude-BugHunter / communitytools → flywheel FeedbackDB

用法: python inject_github_compare.py
效果: 3 个仓库的技法以 synthetic_bounty 权重注入 → 飞轮自动优胜劣汰
"""
import sys, json, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from aimy.memory.feedback import FeedbackDB

BASE = Path(r"C:\Users\PC\Desktop\github_compare")
NOW = "2026-07-01"

# ─── 从 3 个仓库提取技法 ─────────────────────────────────────────

def extract_from_pentest_agents():
    """从 pentest-agents agent 描述中提取测试方法"""
    agents_dir = BASE / "pentest-agents" / ".claude" / "agents"
    techniques = []
    if not agents_dir.exists():
        return techniques
    for f in agents_dir.glob("*.md"):
        name = f.stem
        text = f.read_text(encoding="utf-8")
        # 提取 tools 行和描述
        tools = re.findall(r'tools:\s*(.+)', text)
        desc = re.findall(r'description:\s*"(.+)"', text)
        # 映射到漏洞类
        vuln_map = {
            "idor": "idor", "xss": "xss", "ssrf": "ssrf",
            "sqli": "sqli", "rce": "rce", "race": "race",
            "cors": "cors", "csrf": "csrf", "graphql": "graphql",
            "oauth": "oauth", "business": "business logic",
            "auth": "auth bypass", "recon": "recon",
        }
        vclass = "info"
        for k, v in vuln_map.items():
            if k in name.lower():
                vclass = v; break
        tech = f"[pentest-agents:{name}] {desc[0] if desc else name} | tools: {tools[0] if tools else 'N/A'}"
        techniques.append((tech[:200], vclass, "high" if vclass != "info" else "medium", 2000, "pentest-agents"))
    return techniques

def extract_from_claude_bughunter():
    """从 Claude-BugHunter skill 文件中提取技法"""
    skills_dir = BASE / "Claude-BugHunter" / "skills"
    techniques = []
    if not skills_dir.exists():
        return techniques
    for skill_dir in skills_dir.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue
        name = skill_dir.name
        text = skill_md.read_text(encoding="utf-8", errors="ignore")
        vuln_map = {
            "sqli": "sqli", "xss": "xss", "ssrf": "ssrf",
            "idor": "idor", "rce": "rce", "ssti": "ssti",
            "xxe": "xxe", "oauth": "oauth", "saml": "saml",
            "csrf": "csrf", "business": "business logic",
            "cache": "cache poisoning", "smuggling": "smuggling",
            "race": "race", "upload": "file upload",
            "graphql": "graphql", "mfa": "auth bypass",
            "llm": "llm", "ato": "auth bypass",
        }
        vclass = "info"
        for k, v in vuln_map.items():
            if k in name:
                vclass = v; break
        # 提取第一条 payload 或 curl 命令
        lines = text.split("\n")
        payload = ""
        for i, line in enumerate(lines):
            if any(k in line for k in ["curl ", "payload", "?param", "?id=", "?url="]):
                payload = line.strip()[:100]
                break
        if not payload:
            payload = name
        desc = text.split("\n")[0] if text else name
        tech = f"[Claude-BugHunter:{name}] {desc[:80]} | {payload}"
        techniques.append((tech[:200], vclass, "high", 2500, "Claude-BugHunter"))
    return techniques

def extract_from_communitytools():
    """从 communitytools skill 文件中提取技法"""
    skills_dir = BASE / "communitytools" / "skills"
    techniques = []
    if not skills_dir.exists():
        return techniques
    for cat_dir in skills_dir.iterdir():
        if not cat_dir.is_dir():
            continue
        for skill_dir in cat_dir.iterdir():
            if not skill_dir.is_dir():
                continue
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                continue
            name = skill_dir.name
            text = skill_md.read_text(encoding="utf-8", errors="ignore")
            # 提取参考文件中的 payload
            ref_dir = skill_dir / "reference"
            payloads = []
            if ref_dir.exists():
                for rf in ref_dir.glob("*.md"):
                    rt = rf.read_text(encoding="utf-8", errors="ignore")
                    for line in rt.split("\n"):
                        if any(k in line for k in ["curl ", "payload:", "?param", "example"]):
                            payloads.append(line.strip()[:80])
            vclass = cat_dir.name.replace("-", " ")
            tech = f"[communitytools:{cat_dir.name}/{name}] refs: {len(payloads)} payloads"
            techniques.append((tech[:200], vclass, "high", 3000, "communitytools"))
    return techniques


# ─── 注入飞轮 ────────────────────────────────────────────────────

def inject():
    print("="*60)
    print("注入 GitHub 3 仓库 → flywheel FeedbackDB")
    print("="*60)

    all_techs = []
    all_techs.extend(extract_from_pentest_agents())
    all_techs.extend(extract_from_claude_bughunter())
    all_techs.extend(extract_from_communitytools())

    print(f"\n提取到 {len(all_techs)} 条技法:")
    print(f"  pentest-agents:    {len(extract_from_pentest_agents())}")
    print(f"  Claude-BugHunter:  {len(extract_from_claude_bughunter())}")
    print(f"  communitytools:    {len(extract_from_communitytools())}")

    db = FeedbackDB()
    count = 0
    for tech, vclass, severity, bounty, source in all_techs:
        try:
            db.record(
                technique=tech,
                vuln_class=vclass,
                report_id=f"external_{source}_{count}",
                outcome="accepted",
                severity=severity,
                bounty=bounty,
            )
            count += 1
        except Exception as e:
            print(f"  ERR: {e}")
    db.close()

    print(f"\n[OK] 成功注入 {count} 条技法到 FeedbackDB")
    print(f"   飞轮下次运行时 (python aimy.py --flywheel) 会自动:")
    print(f"   1. 读取这些技法 -> 计算排名")
    print(f"   2. 与真实挖洞产出竞争 -> 优胜劣汰")
    print(f"   3. 排名高的进 FLYWHEEL_APPEND -> 排名低的自动淘汰")
    print(f"   (synthetic_bounty权重确保初期排在前列)")

    # 保存注入记录
    record_file = Path(__file__).parent / "github_compare_injected.json"
    record_file.write_text(json.dumps({
        "date": NOW,
        "sources": ["pentest-agents", "Claude-BugHunter", "communitytools"],
        "count": count,
        "status": "injected"
    }, ensure_ascii=False, indent=2))
    print(f"\n   注入记录: {record_file}")


if __name__ == "__main__":
    inject()
