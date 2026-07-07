#!/bin/bash
# CSP 反向情报 — 六维 ⑤
# 用法: bash csp_intel.sh --url https://target.com [--probe]
set -euo pipefail

URL=""
PROBE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --url) URL="$2"; shift 2 ;;
    --probe) PROBE=true; shift ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

URL="${URL:?Usage: csp_intel.sh --url https://target.com [--probe]}"

echo "[+] CSP Intel: $URL"

# Step 1: Fetch headers
echo "[*] Fetching CSP headers..."
HEADERS=$(curl -sI --max-time 10 "$URL" 2>/dev/null)
CSP=$(echo "$HEADERS" | grep -i "content-security-policy" || echo "")

if [ -z "$CSP" ]; then
  echo "[-] No CSP header found"
  # Also check meta tag
  META_CSP=$(curl -sL --max-time 10 "$URL" 2>/dev/null \
    | grep -oP 'http-equiv="?Content-Security-Policy"?[^>]*content="?([^"]+)"?' || echo "")
  if [ -z "$META_CSP" ]; then
    echo "[-] No CSP meta tag found either"
    exit 1
  fi
  echo "    Found CSP in meta tag"
else
  echo "    CSP header: ${CSP:0:200}..."
fi

# Step 2: Extract domains from CSP
echo "[*] Extracting domains..."
echo "$CSP" | grep -oP "https?://[^/\s'\"]+" | sort -u | while read domain; do
  echo "    $domain"
done > /tmp/csp_domains.txt
echo "    Found $(wc -l < /tmp/csp_domains.txt) domains"

# Step 3: Probe if requested
if $PROBE && command -v httpx &>/dev/null; then
  echo "[*] Probing CSP domains..."
  cat /tmp/csp_domains.txt | httpx -silent -status-code -title 2>/dev/null
fi

echo "[+] Done"
