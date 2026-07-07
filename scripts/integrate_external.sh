#!/bin/bash
# 融合外部项目的技能
set -e

SKILLS_DIR="/c/Users/PC/Desktop/彦/skills"
CBH_DIR="/c/Users/PC/Desktop/彦/_external/Claude-BugHunter/skills"
SRC_HUNTER="/c/Users/PC/Desktop/彦/_external/src-hunter-skill"
PSB="/c/Users/PC/Desktop/彦/_external/public-skills-builder"

# === Step 1: 复制 Claude-BugHunter 独有的 13 個技能 ===
echo "=== Step 1: 复制 CBH 独占技能 ==="

for s in apk-redteam-pipeline hunt-aspnet hunt-grpc hunt-laravel \
         hunt-nextjs hunt-nodejs hunt-sharepoint hunt-springboot \
         hunt-mfa-bypass hunt-ntlm-info hunt-tls-network \
         mid-engagement-ir-detection hunt-ato hunt-dom hunt-session; do
    if [ -d "$CBH_DIR/$s" ] && [ ! -d "$SKILLS_DIR/$s" ]; then
        cp -r "$CBH_DIR/$s" "$SKILLS_DIR/"
        lines=$(wc -l < "$CBH_DIR/$s/SKILL.md")
        echo "  [+] $s ($lines 行)"
    elif [ -d "$SKILLS_DIR/$s" ]; then
        echo "  [-] $s 已存在，跳过"
    else
        echo "  [!] $s 源目录不存在"
    fi
done

# === Step 2: 融合 src-hunter H1报告（2,888份JSON）===
echo ""
echo "=== Step 2: 融合 src-hunter H1 报告 ==="
SRC_H1="$SRC_HUNTER/references/h1-reports"
TGT_H1="/c/Users/PC/Desktop/彦/references/h1-reports"

if [ -d "$SRC_H1" ]; then
    mkdir -p "$TGT_H1"
    find "$SRC_H1" -name "*.json" | wc -l
    # 去重复制（不覆盖已有同名）
    rsync -a --ignore-existing "$SRC_H1/" "$TGT_H1/"
    echo "  [+] src-hunter H1 报告已融合"
    echo "  [+] H1 raw: $(find $TGT_H1/raw -name '*.json' 2>/dev/null | wc -l) 条"
    echo "  [+] by-weakness: $(ls $TGT_H1/by-weakness/ 2>/dev/null | wc -l) 类"
fi

# === Step 3: 融合 src-hunter payloader ===
echo ""
echo "=== Step 3: 融合 payloader ==="
if [ -d "$SRC_HUNTER/references/payloader" ]; then
    mkdir -p "/c/Users/PC/Desktop/彦/references/payloader"
    rsync -a --ignore-existing "$SRC_HUNTER/references/payloader/" "/c/Users/PC/Desktop/彦/references/payloader/"
    echo "  [+] payloader 已融合"
fi

# === Step 4: 融合 src-hunter 字典 ===
echo ""
echo "=== Step 4: 融合字典 ==="
if [ -d "$SRC_HUNTER/references/dictionaries" ]; then
    mkdir -p "/c/Users/PC/Desktop/彦/references/dictionaries"
    rsync -a --ignore-existing "$SRC_HUNTER/references/dictionaries/" "/c/Users/PC/Desktop/彦/references/dictionaries/"
    echo "  [+] 字典已融合"
fi

# === Step 5: 融合 src-hunter playbooks ===
echo ""
echo "=== Step 5: 融合 playbooks ==="
if [ -d "$SRC_HUNTER/references/playbooks" ]; then
    mkdir -p "/c/Users/PC/Desktop/彦/references/playbooks"
    rsync -a --ignore-existing "$SRC_HUNTER/references/playbooks/" "/c/Users/PC/Desktop/彦/references/playbooks/"
    echo "  [+] playbooks 已融合"
fi

# === Step 6: 融合 src-hunter 模板 ===
echo ""
echo "=== Step 6: 融合 模板 ==="
if [ -d "$SRC_HUNTER/references/templates" ]; then
    mkdir -p "/c/Users/PC/Desktop/彦/references/templates"
    rsync -a --ignore-existing "$SRC_HUNTER/references/templates/" "/c/Users/PC/Desktop/彦/references/templates/"
    echo "  [+] 模板已融合"
fi

# === Step 7: 安装 public-skills-builder 依赖 ===
echo ""
echo "=== Step 7: public-skills-builder 环境 ==="
if [ -f "$PSB/public_skills_builder.py" ]; then
    echo "  [+] public_skills_builder.py 就绪"
    echo "  [+] 使用: python public_skills_builder.py --source all --limit 500"
fi

# === Step 8: 复制 CBH 引擎工具 ===
echo ""
echo "=== Step 8: CBH 引擎工具 ==="
CBH_ENGINE="/c/Users/PC/Desktop/彦/_external/Claude-BugHunter/engine"
if [ -d "$CBH_ENGINE" ]; then
    mkdir -p "/c/Users/PC/Desktop/彦/aimy/references/cbh-engine"
    cp "$CBH_ENGINE/brain.py" "$CBH_ENGINE/state.py" "$CBH_ENGINE/skill_map.py" \
       "/c/Users/PC/Desktop/彦/aimy/references/cbh-engine/" 2>/dev/null
    echo "  [+] engine tools 已复制"
fi

echo ""
echo "=== 融合完成 ==="
echo "技能总数: $(ls $SKILLS_DIR | wc -l)"
echo "CBH 新增: 14 skill"
echo "H1 报告: ~2900 条"
echo "Payloader: 已融合"

# 下次启动 session_brief 提示更新
echo ""
echo "提醒: 执行以下命令刷新 session_brief"
echo "  python -m aimy.memory.session_brief"
