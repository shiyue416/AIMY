#!/usr/bin/env python3
"""
wooyun_inject_flywheel.py v2
解析 wooyun-legacy 数据 → 注入 techniques.jsonl + 飞轮技法排行

数据形态:
  - 15 个分类 .md 文件
  - 每个文件 ~15 个"典型案例"（含标题/payload/URL）
  - 每个文件数千 inline wooyun-XXXXX 引用
  - 总计 ~52,000 唯一 ID, ~85,000 次引用

输出:
  - techniques.jsonl: 详细案例 + 频次统计
  - 116类最佳技法.md: 追加 WooYun 章节
  - session_brief.md: 注入统计
"""
import os, re, json, time
from pathlib import Path
from datetime import datetime
from collections import Counter

BASE = Path("C:/Users/PC/Desktop/彦")
WOOYUN_DIR = BASE / "_external" / "wooyun-legacy" / "categories"
TECHNIQUES_FILE = BASE / "aimy" / "memory" / "techniques.jsonl"
SESSION_BRIEF = Path.home() / ".aimy" / "session_brief.md"
FLYWHEEL_DIR = BASE / "彦的h1飞轮"
BEST_TECH_FILE = FLYWHEEL_DIR / "116类最佳技法.md"

CATEGORY_MAP = {
    "sql-injection": "sqli",
    "xss": "xss",
    "command-execution": "cmdi",
    "ssrf": "ssrf",
    "file-traversal": "lfi",
    "file-upload": "upload",
    "rce": "rce",
    "csrf": "csrf",
    "xxe": "xxe",
    "unauthorized-access": "auth-bypass",
    "weak-password": "weak-cred",
    "info-disclosure": "info-disclosure",
    "logic-flaws": "business-logic",
    "misconfig": "misconfig",
    "other": "other",
}

def parse_categories():
    """解析所有分类文件，提取详细案例 + 频次统计"""
    id_by_type = {}       # vuln_type → Counter of wooyun IDs
    detail_cases = []      # 详细案例（含标题/payload）

    for md_path in sorted(WOOYUN_DIR.glob("*.md")):
        vuln_type = CATEGORY_MAP.get(md_path.stem, "other")
        text = md_path.read_text(encoding="utf-8", errors="replace")

        # 1. 提取所有 inline wooyun ID
        ids = re.findall(r'wooyun-\d{4}-\d{6}', text)
        if vuln_type not in id_by_type:
            id_by_type[vuln_type] = Counter()
        id_by_type[vuln_type].update(ids)

        # 2. 提取 "典型案例" 详细块
        blocks = re.split(r'\n### 案例 \d+: ', text)
        for block in blocks[1:]:
            case = {
                "source": "wooyun",
                "vuln_type": vuln_type,
                "wooyun_id": "",
                "title": "",
                "urls": [],
                "payload": "",
                "params": "",
            }
            lines = block.split('\n')
            for line in lines:
                m = re.search(r'wooyun-\d{4}-\d{6}', line)
                if m and not case["wooyun_id"]:
                    case["wooyun_id"] = m.group(0)
                if line.startswith("**标题**"):
                    case["title"] = line.split(":", 1)[-1].strip() if ":" in line else ""
                if "参数" in line and "`" in line:
                    case["params"] = line.split(":", 1)[-1].strip() if ":" in line else ""
                if "Payload" in line or "payload" in line:
                    case["payload"] = line.split(":", 1)[-1].strip() if ":" in line else ""
                if 'https://' in line:
                    case["urls"].extend(re.findall(r'https?://[^\s\)\]]+', line))
            if case["wooyun_id"]:
                detail_cases.append(case)

    return id_by_type, detail_cases


def inject_to_techniques(id_by_type, detail_cases):
    """注入 techniques.jsonl: 详细案例 + 类型频次排名"""
    existing_ids = set()
    if TECHNIQUES_FILE.exists():
        for line in TECHNIQUES_FILE.read_text(encoding="utf-8").strip().split('\n'):
            line = line.strip()
            if line:
                try:
                    d = json.loads(line)
                    if d.get("wooyun_id") and d.get("source") == "wooyun":
                        existing_ids.add(d["wooyun_id"])
                except:
                    pass

    new_entries = []
    with open(TECHNIQUES_FILE, "a", encoding="utf-8") as f:
        # 先写详细案例
        for case in detail_cases:
            if case["wooyun_id"] in existing_ids:
                continue
            entry = {
                "ts": int(time.time()),
                "source": "wooyun",
                "wooyun_id": case["wooyun_id"],
                "vuln_type": case["vuln_type"],
                "title": case["title"][:300] if case["title"] else case["wooyun_id"],
                "payload": case["payload"][:500],
                "params": case["params"],
                "url_example": case["urls"][0] if case["urls"] else "",
                "accept_rate": 85,
                "avg_bounty": 0,
                "type": "detail",
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            existing_ids.add(case["wooyun_id"])
            new_entries.append(entry)

        # 再写频次统计条目（按类型汇总 Top ID）
        for vuln_type, counter in sorted(id_by_type.items()):
            total = sum(counter.values())
            unique = len(counter)
            top_10 = counter.most_common(10)

            # 类型统计条目
            stat_entry = {
                "ts": int(time.time()),
                "source": "wooyun",
                "vuln_type": vuln_type,
                "wooyun_id": f"__stat_{vuln_type}__",
                "title": f"WooYun {vuln_type}: {unique} 唯一案例 / {total} 次引用",
                "payload": f"Top5: {', '.join(f'{id_}({cnt})' for id_, cnt in top_10[:5])}",
                "accept_rate": 85,
                "avg_bounty": 0,
                "type": "stat",
            }
            f.write(json.dumps(stat_entry, ensure_ascii=False) + "\n")

    return len(new_entries), sum(len(c) for c in id_by_type.values()), sum(len(set(c.keys())) for c in id_by_type.values())


def write_flywheel_section(id_by_type):
    """写入 116类最佳技法.md WooYun 章节"""
    lines = []
    lines.append("\n---")
    lines.append("## WooYun 乌云案例 (52,000+ 唯一ID / 85,000+ 引用)")
    lines.append(f"> 注入时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("")

    for vuln_type, counter in sorted(id_by_type.items()):
        total = sum(counter.values())
        unique = len(counter)
        lines.append(f"### {vuln_type} — {unique} 唯一案例, {total} 次引用")
        lines.append("")
        lines.append("| WooYun ID | 引用次数 |")
        lines.append("|-----------|---------|")
        for id_, cnt in counter.most_common(10):
            lines.append(f"| `{id_}` | {cnt} |")
        lines.append("")

    section = "\n".join(lines)
    if BEST_TECH_FILE.exists():
        content = BEST_TECH_FILE.read_text(encoding="utf-8")
        # Remove old section if exists
        content = re.sub(r'\n---\n## WooYun.*?(?=\n## |\Z)', '', content, flags=re.DOTALL)
        content += section
        BEST_TECH_FILE.write_text(content, encoding="utf-8")


def update_session_brief(detail_count, ref_total, unique_total):
    """更新 session_brief"""
    if not SESSION_BRIEF.exists():
        return
    content = SESSION_BRIEF.read_text(encoding="utf-8")

    wooyun_block = f"""
### 📦 WooYun 乌云历史案例 (已注入飞轮)
| 指标 | 值 |
|------|------|
| 详细案例（含标题/payload） | {detail_count} |
| 唯一 WooYun ID | {unique_total}+ |
| 总引用次数 | {ref_total}+ |
| 覆盖类型 | 15 类 |
| 来源 | wooyun-legacy |
"""
    # Remove old block
    content = re.sub(r'\n### 📦 WooYun.*?(?=\n### |\Z)', '', content, flags=re.DOTALL)
    content += wooyun_block
    SESSION_BRIEF.write_text(content, encoding="utf-8")


def main():
    print("=" * 60)
    print("WooYun 案例 → 飞轮注入器 v2")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 60)

    print("\n[1/3] 解析分类文件...")
    id_by_type, detail_cases = parse_categories()
    detail_wooyun = [c for c in detail_cases if c["wooyun_id"]]
    print(f"  详细案例: {len(detail_wooyun)}")
    for vuln_type, counter in sorted(id_by_type.items()):
        total = sum(counter.values())
        unique = len(counter)
        print(f"  {vuln_type}: {unique} 唯一 ID / {total} 引用")

    print("\n[2/3] 注入 techniques.jsonl...")
    new_detail, ref_total, unique_total = inject_to_techniques(id_by_type, detail_wooyun)
    print(f"  新增详细案例: {new_detail}")
    print(f"  总引用: {ref_total}")
    print(f"  唯一 ID: {unique_total}")

    print("\n[3/3] 更新飞轮文档...")
    write_flywheel_section(id_by_type)
    print(f"  更新 116类最佳技法.md ✓")
    update_session_brief(len(detail_wooyun), ref_total, unique_total)
    print(f"  更新 session_brief.md ✓")

    print(f"\n✅ 完成! 总引用 {ref_total}, 唯一ID {unique_total}, 详情 {new_detail}")

if __name__ == "__main__":
    main()
