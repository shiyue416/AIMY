#!/bin/bash
# CDN 源站溯源 — 辅助维度
# 用法: bash cdn_origin.sh target.com
DOMAIN="${1:?Usage: cdn_origin.sh <target.com>}"
echo "[+] CDN Origin: $DOMAIN"

IP=$(dig +short "$DOMAIN" @8.8.8.8 2>/dev/null | head -1)
echo "    IP: $IP"

CNAME=$(dig +short CNAME "$DOMAIN" 2>/dev/null || echo "")
[ -n "$CNAME" ] && echo "    CNAME: $CNAME"

for r in "1.1.1.1" "8.8.8.8" "208.67.222.222"; do
  ip=$(dig +short "$DOMAIN" @"$r" 2>/dev/null | head -1)
  echo "    $r → $ip"
done

for pat in "origin.$DOMAIN" "direct.$DOMAIN" "origin-www.$DOMAIN"; do
  ip=$(dig +short "$pat" 2>/dev/null | head -1)
  [ -n "$ip" ] && echo "    💥 $pat → $ip"
done
