#!/usr/bin/env python3
"""逐行对比 4个旧文件 vs 总纲，输出残留差异"""
import re, sys
from pathlib import Path

MEMORY = Path.home() / ".claude" / "projects" / "C--Users-PC" / "memory"

old_files = {
    "asset-collection-tool-matrix.md": MEMORY / "asset-collection-tool-matrix.md",
    "bug-bounty-workflow-full.md": MEMORY / "bug-bounty-workflow-full.md",
    "optimal-hunting-workflow.md": MEMORY / "optimal-hunting-workflow.md",
}
merged_file = MEMORY / "挖洞体系总纲.md"

# 读取所有文件
merged_text = merged_file.read_text(encoding="utf-8")

# 提取总纲中所有非空行（去掉frontmatter）
merged_lines = [l for l in merged_text.split("\n") if l.strip() and not l.strip().startswith("---") and not l.strip().startswith("{")]

found_any = False

for name, path in old_files.items():
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")

    # 跳过 frontmatter
    in_front = False
    content_lines = []
    for l in lines:
        if l.strip() == "---":
            in_front = not in_front
            continue
        if not in_front:
            content_lines.append(l)

    old_body = "\n".join(content_lines)

    print(f"\n{'='*60}")
    print(f">> {name} ({len(content_lines)} lines)")
    print(f"{'='*60}")

    # 方法：提取旧文件中的关键句子/段落，检查是否在总纲中出现
    # 按段落分割（空行分隔）
    paragraphs = re.split(r'\n\s*\n', old_body)

    found_count = 0
    missing_paras = []

    for i, para in enumerate(paragraphs):
        para = para.strip()
        if not para or len(para) < 10:
            continue

        # 提取段落的关键词（去掉标点、空格）
        key = re.sub(r'[\s\-_→❌✅🔴🟠🟡🟢⭐]+', '', para)[:80].lower()

        # 在总纲中搜索（也去掉标点空格比较）
        merged_flat = re.sub(r'[\s\-_→❌✅🔴🟠🟡🟢⭐]+', '', merged_text).lower()

        if key in merged_flat:
            found_count += 1
        else:
            # 可能是跨段落合并了，取前30字符再试
            short_key = key[:40]
            if short_key in merged_flat:
                found_count += 1
            else:
                missing_paras.append(para[:200])

    if missing_paras:
        found_any = True
        print(f"  总段落: {len(paragraphs)} | 匹配: {found_count} | 可能遗漏: {len(missing_paras)}")
        for mp in missing_paras[:15]:
            print(f"  !! NOT FOUND:\n    {mp[:150]}")
    else:
        print(f"  ✅ 全部 {len(paragraphs)} 段匹配")

if not found_any:
    print(f"\n{'='*60}")
    print("ALL PARAGRAPHS MATCHED - no content missing")
    print(f"{'='*60}")
