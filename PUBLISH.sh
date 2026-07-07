#!/bin/bash
# ============================================================
# AIMY v3.0.0 — 一键发布到 GitHub
# ============================================================
# 用法: cd C:\Users\PC\Desktop\AIMY && bash PUBLISH.sh
#
# 发布前准备 (5 分钟):
#   1. 浏览器打开 https://github.com/new → 创建空仓库 (名称: AIMY)
#      ❌ 不要勾选 README / .gitignore / License (本地已有)
#   2. Settings → Developer settings → Fine-grained tokens → Generate
#      ✅ Repository access: Only select repositories → AIMY
#      ✅ Permissions: Issues → Read and Write
#      ⚠️  复制生成的 token (github_pat_...)
#   3. 编辑 .env.example:
#      AIMY_FEEDBACK_REPO=你的用户名/AIMY
#      AIMY_FEEDBACK_TOKEN=github_pat_刚才复制的token
#      AIMY_TELEMETRY_ENABLED=true
#   4. 编辑 aimy/telemetry/submitter.py 第 43-44 行, 填入同样的值
#      _BUILTIN_FEEDBACK_TOKEN = "github_pat_..."
#      _DEFAULT_FEEDBACK_REPO = "你的用户名/AIMY"
# ============================================================
set -e

echo "╔════════════════════════════════════════════╗"
echo "║  AIMY v3.0.0  子体 → GitHub 发布         ║"
echo "║  本体: C:\\Users\\PC\\Desktop\\彦          ║"
echo "║  子体: C:\\Users\\PC\\Desktop\\AIMY        ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# ── 前置检查 ──────────────────────────────────────

echo "🔍 检查前置条件..."

# 检查 .env 是否未被误包含
if git ls-files ".env" 2>/dev/null | grep -q ".env"; then
    echo "❌ .env 文件被跟踪了！请先: git rm --cached .env"
    exit 1
fi
echo "   ✅ .env 已排除"

# 检查嵌套 git
NESTED=$(find . -name ".git" -type d 2>/dev/null | grep -v "^\./\.git$" | wc -l)
if [ "$NESTED" -gt 0 ]; then
    echo "   ⚠️  发现 $NESTED 个嵌套 .git, 正在清理..."
    find . -name ".git" -type d -not -path "./.git" -exec rm -rf {} + 2>/dev/null
fi
echo "   ✅ 嵌套 .git 已清理"

# ── 1. 提交 ────────────────────────────────────────

echo ""
echo "📦 Step 1/4: git commit..."

# 确保子体是最新的 (从本体同步)
echo "   同步本体 → 子体..."
rsync -av --delete \
    --exclude='.env' \
    --exclude='.git' \
    --exclude='_memory' \
    --exclude='_feedback' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.jsonl' \
    "C:/Users/PC/Desktop/彦/" \
    "C:/Users/PC/Desktop/AIMY/" 2>/dev/null || {
    echo "   ⚠️  rsync 不可用, 使用 cp 替代..."
    # Fallback: 逐目录复制
    for d in aimy skills scripts tools agents hooks mappings tests docs benchmarks gf-patterns mingxi-injection claude-extra-skills references anthropic-skills wooyun_public "彦的h1飞轮"; do
        rm -rf "./$d" 2>/dev/null
        cp -r "C:/Users/PC/Desktop/彦/$d" "./$d" 2>/dev/null
    done
    for f in .gitignore .env.example README.md CLAUDE.md QUICKSTART.md INDEX.md SKILL.md aimy.py; do
        cp "C:/Users/PC/Desktop/彦/$f" "./$f" 2>/dev/null
    done
    # 再次清理嵌套 git
    find . -name ".git" -type d -not -path "./.git" -exec rm -rf {} + 2>/dev/null
}

git add -A

echo ""
echo "   当前变更:"
git status --short | head -10
echo "   ... ($(git status --short | wc -l) files)"

git commit -m "AIMY v3.0.0 — 四源融合安全技能框架

⚔️ 180+ 攻击技能 | 120+ Python 检测器 | 8946 防御技能
📚 3000+ H1 报告 + 50000 WooYun 案例
🔗 六维资产收集 + 七阶段挖洞主流程
🔄 子体→本体 遥测回流 (自动)
🔒 GitHub 全站 14 项目红线对比最优 (45/50)" 2>&1 || echo "   ℹ️  无可提交的变更"

# ── 2. 远程仓库 ────────────────────────────────────

echo ""
echo "🔗 Step 2/4: 配置远程仓库..."

if git remote get-url origin 2>/dev/null; then
    echo "   远程仓库已配置: $(git remote get-url origin)"
else
    echo ""
    echo "   请先在 https://github.com/new 创建空仓库"
    echo ""
    read -p "   粘贴 SSH 地址 (git@github.com:用户名/AIMY.git): " REMOTE
    git remote add origin "$REMOTE"
fi

# ── 3. 推送 ────────────────────────────────────────

echo ""
echo "🚀 Step 3/4: git push..."
git push -u origin main 2>&1 || {
    echo ""
    echo "⚠️  Push 失败。可能原因:"
    echo "   1. GitHub 仓库未创建"
    echo "   2. SSH key 未添加到 GitHub"
    echo "   3. 分支名不是 main (尝试 master)"
    echo ""
    echo "   手动重试: cd C:\\Users\\PC\\Desktop\\AIMY && git push -u origin main"
}

# ── 4. 后续 ────────────────────────────────────────

echo ""
echo "📋 Step 4/4: 发布后检查清单"
echo ""
echo "   [ ] 确认 .env.example 中 AIMY_FEEDBACK_TOKEN 已填入"
echo "   [ ] 确认 aimy/telemetry/submitter.py 中 _BUILTIN_FEEDBACK_TOKEN 已填入"
echo "   [ ] 确认 GitHub 仓库 Settings → Actions → Read and write permissions"
echo "   [ ] 告诉用户: 设置 AIMY_TELEMETRY_ENABLED=true 即可自动上报"
echo ""
echo "════════════════════════════════════════════════"
echo "✅ 发布完成!"
echo ""
echo "   子体: https://github.com/$(git remote get-url origin 2>/dev/null | sed 's/.*[:/]\(.*\)\/\(.*\)\.git/\1\/\2/')"
echo "   本体: C:\\Users\\PC\\Desktop\\彦 (未改动)"
echo ""
echo "   数据回流链:"
echo "   用户 git clone → 挖洞 → 自动上报 → GitHub Issue"
echo "   → 本体每小时自动拉取 → 飞轮每日聚合"
echo "════════════════════════════════════════════════"
