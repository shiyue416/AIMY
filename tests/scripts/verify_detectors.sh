#!/bin/bash
# Quick detector verification - one at a time
BENCH="/c/Users/PC/Desktop/validation-benchmarks/benchmarks"
PYTHONPATH="/c/Users/PC/Desktop/彦"

verify() {
    local VULN=$1 TARGET=$2 DETECTOR=$3 ENDPOINT=$4 PARAM=$5
    local CWD="$BENCH/$TARGET"

    echo "--- $VULN ($TARGET) ---"
    docker compose -f "$CWD/docker-compose.yml" down -v 2>&1 > /dev/null
    docker compose -f "$CWD/docker-compose.yml" up -d --wait 2>&1 > /dev/null
    sleep 5

    local PORT=$(docker ps --format '{{.Names}} {{.Ports}}' | grep "$(echo $TARGET | cut -c1-10 | tr '[:upper:]' '[:lower:]')" | grep -oP '\d+(?=->)' | head -1)

    if [ -z "$PORT" ]; then
        echo "  NO_PORT"
        docker compose -f "$CWD/docker-compose.yml" down -v 2>&1 > /dev/null
        return
    fi

    local URL="http://localhost:$PORT$ENDPOINT"

    PYTHONPATH=$PYTHONPATH python -c "
from aimy.tools.$DETECTOR import check
import requests, json
sess = requests.Session()
r = check('$URL', '$PARAM', sess=sess, timeout=10.0)
print('vulnerable:', r.get('vulnerable'))
if r.get('vulnerable'):
    ev = r.get('evidence', [])
    if ev: print('evidence:', str(ev[0])[:120])
print('type:', r.get('type', ''))
if r.get('default_creds'):
    for d in r['default_creds'][:2]:
        print('creds:', d.get('username'), d.get('password'), d.get('status'))
if r.get('findings'):
    print('findings:', len(r['findings']))
" 2>&1 | grep -v "SAFETY\|WARNING\|safety_gate"

    docker compose -f "$CWD/docker-compose.yml" down -v 2>&1 > /dev/null
    echo ""
}

# Run verification
verify "idor"        "XBEN-001-24" "auth_bypass"       "/"           "id"
verify "xss"         "XBEN-008-24" "xss_detector"      "/"           "q"
verify "ssti"        "XBEN-009-24" "ssti_detector"     "/greet/"     "name"
verify "sqli"        "XBEN-006-24" "sql_injection"     "/"           "id"
verify "ssrf"        "XBEN-020-24" "ssrf_detector"     "/redirect.php" "url"
verify "lfi"         "XBEN-019-24" "lfi_scanner"       "/"           "file"
verify "jwt"         "XBEN-005-24" "jwt_detector"      "/"           "token"
verify "deser"       "XBEN-014-24" "deserialization_detector" "/"    "data"
verify "nosqli"      "XBEN-100-24" "nosqli_detector"   "/"           "id"
verify "cmdi"        "XBEN-030-24" "cmdi_detector"     "/"           "cmd"

echo "Done."
