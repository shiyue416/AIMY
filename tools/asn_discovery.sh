#!/bin/bash
# ASN/IP 反向发现 — 六维 ④
# 用法: bash asn_discovery.sh --org "Target Corp" --domain target.com
set -euo pipefail

ORG=""; DOMAIN=""
while [[ $# -gt 0 ]]; do case $1 in
  --org) ORG="$2"; shift 2 ;;
  --domain) DOMAIN="$2"; shift 2 ;;
  *) shift ;;
esac; done

echo "[+] ASN Discovery"

if [ -n "$DOMAIN" ]; then
  IP=$(dig +short "$DOMAIN" @8.8.8.8 2>/dev/null | head -1)
  [ -n "$IP" ] && echo "    IP: $IP → https://bgp.he.net/ip/$IP"
fi

if [ -n "$ORG" ] && command -v amass &>/dev/null; then
  echo "[*] amass intel..."
  amass intel -org "$ORG" -timeout 60 2>/dev/null | head -50
fi

echo "[+] Done"
