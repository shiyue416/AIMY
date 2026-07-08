#!/bin/bash
# 完整资产收集入口 — 六维 + 企业扩展
# 用法: bash full_recon.sh <target_domain> [company_name]
# 示例: bash full_recon.sh mi.com "小米"
#
# Phase 2 入口，按顺序执行:
#   ① 子域名被动 (recon_engine.sh)
#   ② 企业扩展 (enscan_recon.sh) — 如有公司名
#   ③ 图标关联 (favicon_hunt.sh)
#   ④ ASN/IP  (asn_discovery.sh)
#   ⑤ CSP 情报 (csp_intel.sh)
#   ⑥ JS 源码 (js_sourcemap.sh)
set -euo pipefail

DOMAIN="${1:?Usage: full_recon.sh <domain> [company_name]}"
COMPANY="${2:-}"
TOOLS_DIR="$HOME/.claude/tools"
OUTDIR="recon/$DOMAIN"
mkdir -p "$OUTDIR"

START_TIME=$(date +%s)

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           AIMY Phase 2: 完整资产收集                         ║"
echo "║           Target: $DOMAIN"
[ -n "$COMPANY" ] && echo "║           Company: $COMPANY"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ① 子域名被动
echo ">>> 维度 1: 子域名被动收集"
bash "$TOOLS_DIR/recon_engine.sh" "$DOMAIN" "$OUTDIR"

# ② 企业扩展 (enscan + OneForAll)
if [ -n "$COMPANY" ]; then
  echo ""
  echo ">>> 维度 2: 企业资产扩展 (enscan + OneForAll)"
  bash "$TOOLS_DIR/enscan_recon.sh" "$COMPANY" "$DOMAIN" "$OUTDIR"
else
  echo ""
  echo ">>> 维度 2: 企业资产扩展 — 跳过 (未提供公司名)"
  echo "    用法: bash full_recon.sh mi.com \"小米\" 启用企业扩展"
fi

# ③ 图标关联
echo ""
echo ">>> 维度 3: 图标关联 (FOFA/Shodan)"
bash "$TOOLS_DIR/favicon_hunt.sh" --url "https://$DOMAIN" 2>/dev/null || \
  echo "    [--] 图标关联跳过 (favicon_hunt.sh 未找到或失败)"

# ④ ASN/IP 反查
echo ""
echo ">>> 维度 4: ASN/IP 反查"
bash "$TOOLS_DIR/asn_discovery.sh" --domain "$DOMAIN" 2>/dev/null || \
  echo "    [--] ASN 反查跳过"

# ⑤ CSP 情报
echo ""
echo ">>> 维度 5: CSP 反向情报"
bash "$TOOLS_DIR/csp_intel.sh" --url "https://$DOMAIN" --probe 2>/dev/null || \
  echo "    [--] CSP 情报跳过"

# ⑥ JS 源码还原
echo ""
echo ">>> 维度 6: JS 源码还原"
bash "$TOOLS_DIR/js_sourcemap.sh" "$OUTDIR" 2>/dev/null || \
  echo "    [--] JS 分析跳过"

# 汇总
ELAPSED=$(($(date +%s) - START_TIME))
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Phase 2 完成 (${ELAPSED}s)                                    ║"
echo "║  总域名:    $(wc -l < "$OUTDIR/subs.txt" 2>/dev/null || echo 0)"
echo "║  解析通过:  $(wc -l < "$OUTDIR/resolved.txt" 2>/dev/null || echo 0)"
echo "║  HTTP 存活: $(wc -l < "$OUTDIR/live.txt" 2>/dev/null || echo 0)"
echo "║  输出目录:  $OUTDIR/"
echo "╚══════════════════════════════════════════════════════════════╝"
