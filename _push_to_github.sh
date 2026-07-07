#!/bin/bash
# ============================================================
# AIMY v3.0.0 子体发布脚本
# 执行前确保已在 GitHub 创建空仓库: https://github.com/new
# 仓库名建议: AIMY
# ============================================================
set -e
cd "C:\Users\PC\Desktop\AIMY"

echo "=== 1. 提交 ==="
git commit -m "AIMY v3.0.0 — 四源融合安全技能框架

180+ 攻击/防御技能 | 120+ Python 工具 | 3000+ H1 报告参考
六维资产管线 | 遥测反馈回流(子体→本体) | 7阶段挖洞主流程"

echo ""
echo "=== 2. 添加远程仓库 ==="
echo "请先确认 GitHub 仓库已创建，然后输入仓库地址:"
echo "  例如: git@github.com:shiyue416/AIMY.git"
echo ""
read -p "GitHub 仓库 SSH 地址: " REMOTE_URL

git remote add origin "$REMOTE_URL"

echo ""
echo "=== 3. 推送 ==="
git push -u origin main

echo ""
echo "=== 完成 ==="
echo "子体已发布: https://github.com/$(echo $REMOTE_URL | sed 's/.*://' | sed 's/\.git//')"
