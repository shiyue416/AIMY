"""Flywheel learner: hybrid XBOW-style generation + file persistence."""
from __future__ import annotations
import re
from pathlib import Path
from datetime import datetime
from aimy.memory.feedback import FeedbackDB

REFS = Path("C:/Users/PC/Desktop/彦/references")

PAYLOAD_FILE_MAP = {
    "xss":                  REFS / "payloader/by-category/web/xss跨站脚本.md",
    "ssrf":                 REFS / "payloader/by-category/web/ssrf服务端请求伪造.md",
    "rce":                  REFS / "payloader/by-category/web/rce远程代码执行.md",
    "sqli":                 REFS / "payloader/by-category/web/sql-nosql注入.md",
    "sql injection":        REFS / "payloader/by-category/web/sql-nosql注入.md",
    "lfi":                  REFS / "payloader/by-category/web/lfi-rfi文件包含.md",
    "xxe":                  REFS / "payloader/by-category/web/xxe实体注入.md",
    "csrf":                 REFS / "payloader/by-category/web/csrf跨站请求伪造.md",
    "ssti":                 REFS / "payloader/by-category/web/ssti模板注入.md",
    "jwt":                  REFS / "payloader/by-category/web/jwt安全.md",
    "oauth":                REFS / "payloader/by-category/web/认证漏洞.md",
    "smuggling":            REFS / "payloader/by-category/web/请求走私.md",
    "command injection":    REFS / "payloader/by-category/web/rce远程代码执行.md",
    "idor":                 REFS / "payloader/by-category/web/idor越权访问.md",
    "information disclosure": REFS / "payloader/by-category/web/信息泄露.md",
    "privilege escalation": REFS / "payloader/by-category/web/权限提升.md",
    "authentication bypass": REFS / "payloader/by-category/web/认证绕过.md",
    "access control":       REFS / "payloader/by-category/web/越权访问控制.md",
    "business logic":       REFS / "payloader/by-category/web/业务逻辑漏洞.md",
}


def get_payloads_for_technique(technique: str, llm_client=None) -> tuple[str, bool]:
    """Return (payload_content, from_file).

    File exists  → deterministic, fast (like 彦).
    No file      → LLM generates on-the-fly + persists to file (like XBOW).
    """
    vuln_lower = technique.lower()
    target_file = next((p for k, p in PAYLOAD_FILE_MAP.items() if k in vuln_lower), None)

    if target_file and target_file.exists():
        return target_file.read_text(encoding="utf-8", errors="ignore"), True

    if llm_client is None:
        return "", False

    prompt = (
        f"Generate 3 practical HTTP payloads/test cases for '{technique}' vulnerability. "
        f"Format as markdown with curl examples. Chinese labels. Be concise."
    )
    try:
        generated = llm_client.complete(prompt)
    except Exception:
        return "", False

    # Persist for next time (XBOW flywheel effect)
    slug = re.sub(r'\W+', '-', technique.lower()).strip('-')
    out_file = REFS / f"payloader/by-category/web/auto-{slug}.md"
    content = f"# {technique} (auto-generated {datetime.now().strftime('%Y-%m-%d')})\n\n{generated}\n"
    out_file.write_text(content, encoding="utf-8")
    return content, False


def compare_and_upgrade(verbose: bool = True) -> dict:
    """Compare accepted H1 techniques vs payloader files; append stubs for gaps."""
    db = FeedbackDB()
    rows = db._conn.execute("""
        SELECT technique, vuln_class,
               SUM(CASE WHEN outcome='accepted' THEN 1 ELSE 0 END) as acc
        FROM reports WHERE outcome='accepted'
        GROUP BY technique, vuln_class HAVING acc >= 2
        ORDER BY acc DESC
    """).fetchall()
    db.close()

    counts = {"upgraded": 0, "already_covered": 0, "no_file": 0}
    for technique, vuln_class, acc in rows:
        target_file = next(
            (p for k, p in PAYLOAD_FILE_MAP.items()
             if k in technique.lower() or k in vuln_class.lower()), None
        )
        if not target_file or not target_file.exists():
            counts["no_file"] += 1
            continue

        content = target_file.read_text(encoding="utf-8", errors="ignore")
        words = [w for w in re.split(r'\W+', technique.lower()) if len(w) >= 4]
        if any(w in content.lower() for w in words) if words else True:
            counts["already_covered"] += 1
            continue

        stub = (f"\n---\n### {technique}  "
                f"*(flywheel {datetime.now().strftime('%Y-%m-%d')} — {acc}x accepted)*\n"
                f"_vuln_class: {vuln_class}_\n\n**待补充。**\n")
        target_file.open("a", encoding="utf-8").write(stub)
        counts["upgraded"] += 1
        if verbose:
            print(f"  [+] {target_file.name} ← {technique}")
    return counts


if __name__ == "__main__":
    c = compare_and_upgrade()
    print(f"upgraded={c['upgraded']}  covered={c['already_covered']}  no_file={c['no_file']}")
