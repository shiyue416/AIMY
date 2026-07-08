#!/bin/bash
# 企业资产扩展 — enscan + OneForAll 集成
# 用法: bash enscan_recon.sh <company_name> <target_domain> [output_dir]
# 示例: bash enscan_recon.sh "小米" mi.com recon/mi.com
#
# 流程:
#   ① enscan 企业信息收集 → 子公司/分支机构/ICP域名
#   ② OneForAll 子域名全量收集 → 补充被动源遗漏
#   ③ 合并去重 → 追加到主 recon 管线
set -euo pipefail

COMPANY="${1:?Usage: enscan_recon.sh <company> <domain> [output_dir]}"
DOMAIN="${2:?}"
OUTDIR="${3:-recon/$DOMAIN}"
mkdir -p "$OUTDIR"

ENSCAN_BIN="$HOME/go/bin/enscan.exe"
ONEFORALL_DIR="$HOME/tools/OneForAll"
SLEEP=1  # 请求间隔

echo "============================================"
echo " 企业资产扩展: $COMPANY ($DOMAIN)"
echo " 输出: $OUTDIR"
echo "============================================"

# ═══════════════════════════════════════════
# ① enscan — 企业信息收集
# ═══════════════════════════════════════════
echo ""
echo "[1/4] enscan 企业信息收集..."

ENSCAN_OUT="$OUTDIR/enscan"
mkdir -p "$ENSCAN_OUT"

# ICP 备案域名
echo "  [*] ICP 备案查询..."
"$ENSCAN_BIN" -n "$COMPANY" -field icp -out-dir "$ENSCAN_OUT" -out-type json 2>/dev/null || true
sleep $SLEEP

# 分支机构
echo "  [*] 分支机构查询..."
"$ENSCAN_BIN" -n "$COMPANY" --branch -is-show=false -out-dir "$ENSCAN_OUT" -out-type json 2>/dev/null || true
sleep $SLEEP

# 控股子公司 (100% 持股)
echo "  [*] 控股子公司查询..."
"$ENSCAN_BIN" -n "$COMPANY" --invest 100 -is-show=false -out-dir "$ENSCAN_OUT" -out-type json 2>/dev/null || true
sleep $SLEEP

# 供应商
echo "  [*] 供应商查询..."
"$ENSCAN_BIN" -n "$COMPANY" --supplier -is-show=false -out-dir "$ENSCAN_OUT" -out-type json 2>/dev/null || true

# 从 enscan 输出中提取域名
echo "  [*] 提取域名..."
ENSACN_DOMAINS="$OUTDIR/enscan_domains.txt"
> "$ENSACN_DOMAINS"

# 从 JSON/文本输出中提取可能的域名
if ls "$ENSCAN_OUT"/*.json 2>/dev/null | head -1 > /dev/null 2>&1; then
  cat "$ENSCAN_OUT"/*.json 2>/dev/null | \
    grep -oP '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}' | \
    sort -u > "$ENSACN_DOMAINS" 2>/dev/null || true
fi

# 从 Excel 转出来的文本也提取一遍
if ls "$ENSCAN_OUT"/*.txt 2>/dev/null | head -1 > /dev/null 2>&1; then
  cat "$ENSCAN_OUT"/*.txt 2>/dev/null | \
    grep -oP '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}' | \
    sort -u >> "$ENSACN_DOMAINS" 2>/dev/null || true
fi

# 过滤噪音域名
if [ -s "$ENSACN_DOMAINS" ]; then
  grep -v -E '\.(gov|edu|mil|example|test|local|internal)$' "$ENSACN_DOMAINS" | \
    sort -u > "${ENSACN_DOMAINS}.tmp" && mv "${ENSACN_DOMAINS}.tmp" "$ENSACN_DOMAINS"
  echo "  [OK] enscan 发现 $(wc -l < "$ENSACN_DOMAINS") 个域名"
else
  echo "  [--] enscan 未发现新域名"
  echo "# enscan: no domains found" > "$ENSACN_DOMAINS"
fi

# ═══════════════════════════════════════════
# ② OneForAll — 子域名全量收集
# ═══════════════════════════════════════════
echo ""
echo "[2/4] OneForAll 子域名收集..."

OFA_OUT="$OUTDIR/oneforall"
mkdir -p "$OFA_OUT"

if [ -f "$ONEFORALL_DIR/oneforall.py" ]; then
  echo "  [*] 运行 OneForAll (被动+爆破+DNS验证)..."
  python "$ONEFORALL_DIR/oneforall.py" \
    --target "$DOMAIN" \
    --alive False \
    --fmt json \
    --path "$OFA_OUT" \
    run 2>&1 | grep -v "^INFO:" || true

  # 合并 OneForAll 结果
  if [ -f "$OFA_OUT"/*.json 2>/dev/null ]; then
    cat "$OFA_OUT"/*.json 2>/dev/null | \
      grep -oP '"subdomain"\s*:\s*"([^"]+)"' | \
      cut -d'"' -f4 | sort -u > "$OUTDIR/oneforall_subs.txt" 2>/dev/null || true
    echo "  [OK] OneForAll: $(wc -l < "$OUTDIR/oneforall_subs.txt" 2>/dev/null || echo 0) 子域名"
  elif [ -f "$OFA_OUT"/*.csv 2>/dev/null ]; then
    cat "$OFA_OUT"/*.csv 2>/dev/null | \
      grep -oP '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}' | \
      sort -u > "$OUTDIR/oneforall_subs.txt" 2>/dev/null || true
    echo "  [OK] OneForAll: $(wc -l < "$OUTDIR/oneforall_subs.txt" 2>/dev/null || echo 0) 子域名"
  else
    echo "  [--] OneForAll 无输出文件"
    touch "$OUTDIR/oneforall_subs.txt"
  fi
else
  echo "  [--] OneForAll 未安装，跳过"
  touch "$OUTDIR/oneforall_subs.txt"
fi

# ═══════════════════════════════════════════
# ③ 合并 — 并入主管线
# ═══════════════════════════════════════════
echo ""
echo "[3/4] 合并结果..."

# 合并 enscan 企业域名 + OneForAll 子域名 + 已有子域名
MERGED="$OUTDIR/merged_all.txt"
{
  cat "$ENSACN_DOMAINS" 2>/dev/null || true
  cat "$OUTDIR/oneforall_subs.txt" 2>/dev/null || true
  cat "$OUTDIR/subs.txt" 2>/dev/null || true
} | sort -u | grep -v '^#' | grep -v '^$' > "$MERGED"

echo "  [OK] 合并后总计: $(wc -l < "$MERGED") 唯一域名"

# 追加到主 subs.txt (去重)
if [ -f "$OUTDIR/subs.txt" ]; then
  cat "$MERGED" | sort -u > "$OUTDIR/subs_all.txt"
  mv "$OUTDIR/subs_all.txt" "$OUTDIR/subs.txt"
else
  cp "$MERGED" "$OUTDIR/subs.txt"
fi

# ═══════════════════════════════════════════
# ④ 验证新域名 — DNS + HTTP
# ═══════════════════════════════════════════
echo ""
echo "[4/4] 验证新发现域名..."

# DNS 验证
"$HOME/go/bin/dnsx" -l "$MERGED" -silent -rate-limit 1 2>/dev/null | sort -u > "$OUTDIR/resolved_new.txt" || true
echo "  DNS 验证通过: $(wc -l < "$OUTDIR/resolved_new.txt" 2>/dev/null || echo 0)"

# 合并到 resolved
if [ -f "$OUTDIR/resolved.txt" ]; then
  cat "$OUTDIR/resolved.txt" "$OUTDIR/resolved_new.txt" 2>/dev/null | sort -u > "$OUTDIR/resolved_all.txt"
  mv "$OUTDIR/resolved_all.txt" "$OUTDIR/resolved.txt"
fi

# HTTP 存活
"$HOME/go/bin/httpx" -l "$OUTDIR/resolved_new.txt" -silent -status-code -title -tech-detect \
  -no-color -rate-limit 1 -t 5 2>/dev/null > "$OUTDIR/live_new.txt" || true
echo "  HTTP 存活: $(wc -l < "$OUTDIR/live_new.txt" 2>/dev/null || echo 0)"

# 合并到 live
if [ -f "$OUTDIR/live.txt" ]; then
  cat "$OUTDIR/live.txt" "$OUTDIR/live_new.txt" 2>/dev/null | sort -u > "$OUTDIR/live_all.txt"
  mv "$OUTDIR/live_all.txt" "$OUTDIR/live.txt"
fi

echo ""
echo "============================================"
echo " 企业资产扩展完成"
echo " enscan 域名:    $(wc -l < "$ENSACN_DOMAINS" 2>/dev/null || echo 0)"
echo " OneForAll 子域: $(wc -l < "$OUTDIR/oneforall_subs.txt" 2>/dev/null || echo 0)"
echo " 合并总域名:     $(wc -l < "$MERGED" 2>/dev/null || echo 0)"
echo " 输出目录:       $OUTDIR/"
echo "============================================"
