#!/bin/bash
# 子域名被动收集 — 六维 ①
# 用法: bash recon_engine.sh target.com [output_dir]
set -euo pipefail

TARGET="${1:?Usage: recon_engine.sh <target.com> [output_dir]}"
OUTDIR="${2:-recon/$TARGET}"
mkdir -p "$OUTDIR"

echo "[+] Target: $TARGET"
echo "[+] Output: $OUTDIR"

# Step 0: crt.sh (零发包)
echo "[*] crt.sh..."
curl -s --max-time 30 "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null \
  | python -c "import json,sys; data=json.load(sys.stdin); [print(n.strip().lower()) for e in data for n in e.get('name_value','').split('\n') if n.strip()]" \
  | sed 's/^\*\.//g' | sort -u > "$OUTDIR/crtsh.txt"
echo "    crt.sh: $(wc -l < "$OUTDIR/crtsh.txt")"

# Step 1: subfinder
echo "[*] subfinder..."
subfinder -d "$TARGET" -silent -all 2>/dev/null | sort -u > "$OUTDIR/subfinder.txt"
echo "    subfinder: $(wc -l < "$OUTDIR/subfinder.txt")"

# Step 2: assetfinder
echo "[*] assetfinder..."
assetfinder --subs-only "$TARGET" 2>/dev/null | sort -u > "$OUTDIR/assetfinder.txt"
echo "    assetfinder: $(wc -l < "$OUTDIR/assetfinder.txt")"

# Step 3: Chaos (ProjectDiscovery)
echo "[*] Chaos..."
if [ -n "${CHAOS_API_KEY:-}" ]; then
  curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
    -H "Authorization: $CHAOS_API_KEY" 2>/dev/null \
    | python -c "import json,sys; [print(d) for d in json.load(sys.stdin)]" \
    | sort -u > "$OUTDIR/chaos.txt" 2>/dev/null || touch "$OUTDIR/chaos.txt"
  echo "    Chaos: $(wc -l < "$OUTDIR/chaos.txt")"
else
  echo "    Chaos: skipped (set CHAOS_API_KEY)"
  touch "$OUTDIR/chaos.txt"
fi

# Step 4: Merge & dedup
cat "$OUTDIR"/crtsh.txt "$OUTDIR"/subfinder.txt "$OUTDIR"/assetfinder.txt "$OUTDIR"/chaos.txt \
  | sort -u > "$OUTDIR/subs.txt"
echo "[+] Total unique: $(wc -l < "$OUTDIR/subs.txt")"

# Step 5: DNS resolve
echo "[*] dnsx..."
cat "$OUTDIR/subs.txt" | dnsx -silent 2>/dev/null | sort -u > "$OUTDIR/resolved.txt"
echo "    Resolved: $(wc -l < "$OUTDIR/resolved.txt")"

# Step 6: Live check
echo "[*] httpx..."
cat "$OUTDIR/resolved.txt" | httpx -silent -status-code -title -tech-detect -no-color 2>/dev/null > "$OUTDIR/live.txt"
echo "    Live: $(wc -l < "$OUTDIR/live.txt")"

echo "[+] Done: $OUTDIR/"
ls -la "$OUTDIR/"
