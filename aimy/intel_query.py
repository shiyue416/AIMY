#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os
sys.stdout.reconfigure(encoding='utf-8')
"""
H1报告快速查询工具 — 情报层激活脚本
用法:
  python intel_query.py --type idor          # 查IDOR相关H1报告
  python intel_query.py --type ssrf --top 5  # 查SSRF前5条高赏金报告
  python intel_query.py --keyword jwt        # 关键词搜索
  python intel_query.py --stats              # 统计漏洞类型分布
"""
import os, json, re, argparse, glob
from pathlib import Path

H1_RAW = r"C:\Users\PC\Desktop\小十月skill\references\h1-reports\raw\reports"
H1_BY_WEAKNESS = r"C:\Users\PC\Desktop\小十月skill\references\h1-reports\by-weakness"
TECHNIQUES = r"C:\Users\PC\.claude\targets\techniques.jsonl"

VULN_MAP = {
    "idor": ["idor", "broken-object", "authorization", "bola"],
    "ssrf": ["ssrf", "server-side-request"],
    "sqli": ["sql-injection", "blind-sql"],
    "xss": ["cross-site-scripting", "xss"],
    "rce": ["rce", "remote-code", "command-injection", "code-injection"],
    "jwt": ["jwt", "authentication-bypass", "token"],
    "lfi": ["lfi", "path-traversal", "file-inclusion"],
    "race": ["race-condition", "concurrent"],
    "business": ["business-logic", "logic-errors"],
    "ssti": ["ssti", "template-injection"],
}


def query_by_weakness(vuln_type: str, top: int = 10):
    """查询by-weakness目录中的H1报告"""
    keywords = VULN_MAP.get(vuln_type.lower(), [vuln_type.lower()])
    results = []
    for md_file in glob.glob(os.path.join(H1_BY_WEAKNESS, "*.md")):
        fname = os.path.basename(md_file).lower()
        if any(k in fname for k in keywords):
            with open(md_file, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            # 提取报告列表
            reports = re.findall(
                r'###\s+\[(.+?)\]\((https://hackerone\.com/reports/\d+)\).*?'
                r'\*\*Severity:\*\*\s+(\w+).*?'
                r'\*\*Bounty:\*\*\s+([\d,]+|[-])\s+usd',
                content, re.DOTALL
            )
            for title, url, severity, bounty in reports:
                bounty_val = int(bounty.replace(",", "")) if bounty.replace(",","").isdigit() else 0
                results.append({
                    "title": title.strip(),
                    "url": url,
                    "severity": severity,
                    "bounty": bounty_val,
                    "file": os.path.basename(md_file),
                })
    results.sort(key=lambda x: x["bounty"], reverse=True)
    return results[:top]


def query_techniques(keyword: str = None):
    """查询本地techniques.jsonl"""
    if not os.path.exists(TECHNIQUES):
        return []
    results = []
    with open(TECHNIQUES, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if keyword is None or keyword.lower() in json.dumps(entry).lower():
                    results.append(entry)
            except json.JSONDecodeError:
                pass
    return results


def stats():
    """统计by-weakness目录中的漏洞类型分布"""
    files = glob.glob(os.path.join(H1_BY_WEAKNESS, "*.md"))
    counts = {}
    for f in files:
        name = os.path.basename(f).replace(".md", "")
        with open(f, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        report_count = len(re.findall(r'### \[', content))
        counts[name] = report_count
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H1情报查询")
    parser.add_argument("--type", help="漏洞类型 (idor/ssrf/sqli/xss/rce/jwt/lfi/race/business/ssti)")
    parser.add_argument("--keyword", help="关键词搜索techniques.jsonl")
    parser.add_argument("--top", type=int, default=10, help="返回前N条")
    parser.add_argument("--stats", action="store_true", help="统计漏洞分布")
    args = parser.parse_args()

    if args.stats:
        print("\n📊 H1报告漏洞类型分布（by-weakness）:")
        for vuln, count in list(stats().items())[:20]:
            bar = "█" * min(count * 2, 40)
            print(f"  {count:3d}  {bar}  {vuln}")

    elif args.type:
        print(f"\n🔍 {args.type.upper()} H1报告 (按赏金排序, top {args.top}):")
        reports = query_by_weakness(args.type, args.top)
        if not reports:
            print("  未找到相关报告")
        for r in reports:
            bounty_str = f"${r['bounty']:,}" if r['bounty'] else "N/A"
            print(f"  [{r['severity']:8s}] {bounty_str:>10}  {r['title'][:60]}")
            print(f"             {r['url']}")
            print()

    elif args.keyword:
        print(f"\n🔍 techniques.jsonl 关键词: {args.keyword}")
        techs = query_techniques(args.keyword)
        if not techs:
            print("  未找到")
        for t in techs:
            print(f"  [{t.get('date','')}] {t.get('vuln_type','')} — {t.get('technique','')}")
            print(f"    {t.get('notes','')}")
            print()

    else:
        # 默认显示情报层状态
        print("\n🚀 情报层状态")
        print(f"  H1报告库: {len(glob.glob(os.path.join(H1_BY_WEAKNESS, '*.md')))} 个漏洞类型")
        raw_count = len(glob.glob(os.path.join(H1_RAW, "*.json")))
        print(f"  原始报告: {raw_count} 份")
        techs = query_techniques()
        print(f"  techniques.jsonl: {len(techs)} 条经验")
        print("\n  用法: python intel_query.py --type idor --top 5")
        print("        python intel_query.py --stats")
