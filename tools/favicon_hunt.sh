#!/bin/bash
# 图标关联 — 六维 ③
# 用法: bash favicon_hunt.sh https://target.com
set -euo pipefail

URL="${1:?Usage: favicon_hunt.sh <https://target.com>}"

echo "[+] Target: $URL"

# Step 1: Get favicon and compute mmh3 hash
echo "[*] Computing mmh3 hash..."
FAVICON_URL="${URL%/}/favicon.ico"
HASH=$(curl -sL --max-time 10 "$FAVICON_URL" 2>/dev/null \
  | python -c "
import sys, mmh3, codecs
data = sys.stdin.buffer.read()
# mmh3 requires base64-encoded favicon in a specific format
import base64
b64 = base64.b64encode(data).decode()
print(mmh3.hash(b64))
" 2>/dev/null)

if [ -z "$HASH" ]; then
  echo "[-] Could not fetch favicon or compute hash"
  exit 1
fi

echo "    mmh3 hash: $HASH"

# Step 2: FOFA search
echo "[*] FOFA search..."
echo "    FOFA: https://fofa.info/result?qbase64=$(echo -n "icon_hash=\"$HASH\"" | base64 -w0)"

# Step 3: Shodan search
echo "[*] Shodan search..."
echo "    Shodan: https://www.shodan.io/search?query=http.favicon.hash%3A$HASH"

echo "[+] Done"
