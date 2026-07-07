"""Generate 116 vuln types × #1 best technique reference table."""
import sys
from pathlib import Path
from datetime import datetime
from aimy.memory.feedback import FeedbackDB
from aimy.memory.skill_upgrader import _find_skill_file

OUTPUT = Path(__file__).parent.parent.parent / "彦的h1飞轮" / "116类最佳技法.md"

def generate(to_file: bool = True):
    db = FeedbackDB()
    rows = db._conn.execute("""
        SELECT vuln_class, technique,
               COUNT(*) as total,
               SUM(CASE WHEN outcome='accepted' THEN 1 ELSE 0 END) as acc,
               AVG(CASE WHEN outcome='accepted' THEN bounty ELSE 0 END) as avg_b
        FROM reports WHERE outcome!=''
        GROUP BY vuln_class ORDER BY acc DESC
    """).fetchall()
    db.close()

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = []
    lines.append("# 彦 EVX — 116 类漏洞 #1 最佳技法")
    lines.append("")
    lines.append(f"> 每类漏洞从 3343 条 H1 accept 记录中精选综合得分最高的一条技法。自动刷新: {now}")
    lines.append("")
    lines.append("| # | 类型 | 接受率 | accept/总 | 均赏金 | #1 最佳技法 | 技能文件 |")
    lines.append("|---|------|--------|-----------|--------|-----------|---------|")

    i = 0
    for vuln_class, technique, total, acc, avg_b in rows:
        if acc == 0 or total == 0:
            continue
        i += 1
        rate = min(acc / total, 1.0)
        sk = _find_skill_file(vuln_class)
        skill_name = sk.parent.name if sk else "—"
        technique_short = technique[:55]
        lines.append(f"| {i} | `{vuln_class[:30]}` | **{int(rate*100)}%** | {int(acc)}/{int(total)} | ¥{int(avg_b or 0):,} | {technique_short} | `{skill_name}` |")

    lines.append("")
    lines.append(f"> {i} 类漏洞 · {int(sum(r[3] for r in rows))} 条 accept · 每小时自动刷新")
    lines.append("")
    lines.append("<!-- FLYWHEEL_APPEND -->")

    output = "\n".join(lines)

    if to_file:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(output, encoding="utf-8")
        print(f"  [+] 彦的h1飞轮/116类最佳技法.md 已刷新 ({i} 类)", file=sys.stderr)

    return output


if __name__ == "__main__":
    print(generate(to_file=True))
