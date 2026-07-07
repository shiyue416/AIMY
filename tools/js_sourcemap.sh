#!/bin/bash
# JS 源码还原 — 六维 ⑥
# 用法: bash js_sourcemap.sh --recon-dir recon/target.com
set -euo pipefail

RECON_DIR="${1:?Usage: js_sourcemap.sh <recon_dir>}"
URLS_FILE="$RECON_DIR/urls.txt"
[ ! -f "$URLS_FILE" ] && { echo "[-] urls.txt not found. Run katana/gau first."; exit 1; }

OUT="$RECON_DIR/js-analysis"
mkdir -p "$OUT" "$OUT/endpoints" "$OUT/secrets"

echo "[+] JS Analysis: $RECON_DIR"

# 1. Find .js.map files
echo "[*] .js.map files..."
grep -E "\.js\.map$" "$URLS_FILE" | anew "$OUT/jsmap-urls.txt" 2>/dev/null || true
echo "    $(wc -l < "$OUT/jsmap-urls.txt") found"

# 2. Source map unpack
if command -v source-map-unpack &>/dev/null; then
  echo "[*] Unpacking source maps..."
  mkdir -p "$OUT/source"
  cat "$OUT/jsmap-urls.txt" | while read url; do
    source-map-unpack "$url" "$OUT/source/" 2>/dev/null || true
  done
  echo "    extracted: $(find "$OUT/source" -type f 2>/dev/null | wc -l) files"
else
  echo "    [-] source-map-unpack not installed (npm i -g source-map-unpack)"
fi

# 3. Extract endpoints from JS files
echo "[*] Extracting endpoints..."
cat "$URLS_FILE" | grep "\.js$" | head -30 | while read url; do
  curl -sL --max-time 8 "$url" 2>/dev/null \
    | grep -oP '"(/[^"]{2,})"' \
    | sed 's/"//g' \
    | sort -u >> "$OUT/endpoints/paths.txt" 2>/dev/null || true
done
[ -f "$OUT/endpoints/paths.txt" ] && echo "    $(wc -l < "$OUT/endpoints/paths.txt") paths" || echo "    0 paths"

# 4. Classify endpoints
[ -f "$OUT/endpoints/paths.txt" ] && {
  grep -iE "api"       "$OUT/endpoints/paths.txt" | anew "$OUT/endpoints/api.txt"       || true
  grep -iE "admin|debug|internal|console" "$OUT/endpoints/paths.txt" | anew "$OUT/endpoints/admin.txt" || true
  grep -iE "upload|file|image|avatar"     "$OUT/endpoints/paths.txt" | anew "$OUT/endpoints/upload.txt"  || true
  grep -iE "login|auth|token|oauth|sso"   "$OUT/endpoints/paths.txt" | anew "$OUT/endpoints/auth.txt"    || true
  grep -iE "[?&](id|user|order|uuid)="    "$OUT/endpoints/paths.txt" | anew "$OUT/endpoints/idor.txt"    || true
  echo "    api:$(wc -l < "$OUT/endpoints/api.txt") admin:$(wc -l < "$OUT/endpoints/admin.txt") upload:$(wc -l < "$OUT/endpoints/upload.txt") auth:$(wc -l < "$OUT/endpoints/auth.txt") idor:$(wc -l < "$OUT/endpoints/idor.txt")"
}

# 5. Quick secret scan
echo "[*] Secret scan..."
cat "$URLS_FILE" | grep "\.js$" | head -30 | while read url; do
  curl -sL --max-time 8 "$url" 2>/dev/null \
    | grep -oP '(api[Kk]ey|api_key|token|secret|password|AKIA|private.key|client.secret)["\s:=]+[A-Za-z0-9_\-\.]{12,}' \
    >> "$OUT/secrets/raw.txt" 2>/dev/null || true
done
[ -f "$OUT/secrets/raw.txt" ] && echo "    $(wc -l < "$OUT/secrets/raw.txt") potential secrets" || echo "    0 potential secrets"

echo "[+] Done: $OUT/"
ls -la "$OUT/"
