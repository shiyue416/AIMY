#!/bin/bash
# 一键提交+推送 AIMY 到 GitHub
set -e
TOKEN="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"
REPO="shiyue416/AIMY"
DIR="C:\Users\PC\Desktop\AIMY"

echo "=== git add ==="
git -C "$DIR" add -A

echo "=== git commit ==="
git -C "$DIR" commit -m "AIMY v3.0.0 — 四源融合安全技能框架

180+ 攻击/防御技能 | 120+ Python 检测器 | 3000+ H1 报告参考
六维资产管线 | 七阶段挖洞主流程 | 子体-本体遥测回流
全自动反馈链路: atexit上报→GitHubIssue→本体Cron拉取→飞轮进化" 2>&1 || echo "(nothing new to commit)"

echo "=== git push ==="
git -C "$DIR" -c "http.extraheader=Authorization: Bearer $TOKEN" push -u origin main 2>&1

echo ""
echo "=== DONE ==="
echo "https://github.com/shiyue416/AIMY"
