"""Full detector verification against benchmark targets."""
import subprocess, re, time, json, os, sys
from pathlib import Path

BENCH = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")
PYTHONPATH = r"C:\Users\PC\Desktop\彦"

# Target selection: pick known-working target per vuln type
PLAN = [
    ("idor",                "XBEN-001-24", "auth_bypass",       "/", "id"),
    ("xss",                 "XBEN-008-24", "xss_detector",      "/", "q"),
    ("ssti",                "XBEN-009-24", "ssti_detector",     "/greet/", "name"),
    ("command_injection",   "XBEN-030-24", "cmdi_detector",     "/", "cmd"),
    ("sqli",                "XBEN-006-24", "sql_injection",     "/", "id"),
    ("ssrf",                "XBEN-020-24", "ssrf_detector",     "/redirect.php", "url"),
    ("lfi",                 "XBEN-019-24", "lfi_scanner",       "/", "file"),
    ("jwt",                 "XBEN-005-24", "jwt_detector",      "/", "token"),
    ("insecure_deserialization", "XBEN-014-24", "deserialization_detector", "/", "data"),
    ("nosqli",              "XBEN-100-24", "nosqli_detector",   "/", "id"),
    ("graphql",             "XBEN-007-24", "graphql_scanner",   "/graphql", "query"),
    ("xxe",                 "XBEN-032-24", "deserialization_detector", "/", "xml"),
    ("path_traversal",      "XBEN-022-24", "lfi_scanner",       "/", "file"),
    ("race_condition",      "XBEN-088-24", "race_condition",    "/", "id"),
]

def start_and_get_port(target):
    cwd = BENCH / target
    subprocess.run("docker compose down -v 2>&1", shell=True,
                   capture_output=True, text=True, timeout=30, cwd=str(cwd))
    subprocess.run("docker compose up -d --wait 2>&1", shell=True,
                   capture_output=True, text=True, timeout=120, cwd=str(cwd))
    time.sleep(3)

    # Get port
    r = subprocess.run("docker compose port app 80 2>&1 || "
                       "docker compose port web 80 2>&1 || "
                       "docker compose port web 5000 2>&1 || "
                       "docker compose port app 5000 2>&1 || "
                       "docker compose port wordpress 80 2>&1",
                       shell=True, capture_output=True, text=True, timeout=5, cwd=str(cwd))
    m = re.search(r":(\d+)", r.stdout)
    if m:
        return int(m.group(1)), cwd

    # Fallback: docker ps
    ps = subprocess.run(
        f'docker ps --format "{{{{.Ports}}}}" --filter "name={target.lower().replace("-","_")[:20]}"',
        shell=True, capture_output=True, text=True, timeout=5)
    m = re.search(r"(\d+)->(\d+)/tcp", ps.stdout)
    return int(m.group(1)) if m else None, cwd

def run_detector(vuln_type, detector_name, url, param):
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH

    script = '''
import sys, json, traceback
sys.path.insert(0, PYTHONPATH_PLACEHOLDER)
try:
    import requests
    sess = requests.Session()
    url = "URL_PLACEHOLDER"
    param = "PARAM_PLACEHOLDER"
    vuln_type = "VULN_PLACEHOLDER"
    detector = "DETECTOR_PLACEHOLDER"
    r = {"vulnerable": False}

    if detector == "auth_bypass":
        from aimy.tools.auth_bypass import check
        r = check(url, sess=sess, timeout=12.0)
    elif detector == "xss_detector":
        from aimy.tools.xss_detector import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "ssti_detector":
        from aimy.tools.ssti_detector import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "cmdi_detector":
        from aimy.tools.cmdi_detector import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "sql_injection":
        from aimy.tools.sql_injection import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "ssrf_detector":
        from aimy.tools.ssrf_detector import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "lfi_scanner":
        from aimy.tools.lfi_scanner import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "jwt_detector":
        from aimy.tools.jwt_detector import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "deserialization_detector":
        from aimy.tools.deserialization_detector import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "nosqli_detector":
        from aimy.tools.nosqli_detector import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "graphql_scanner":
        from aimy.tools.graphql_scanner import check
        r = check(url, param, sess=sess, timeout=12.0)
    elif detector == "race_condition":
        from aimy.tools.race_condition import check
        r = check(url, param, sess=sess, timeout=12.0)

    evidence = []
    for e in r.get("evidence", [])[:3]:
        evidence.append(str(e)[:200])

    print("JSON:" + json.dumps({
        "vulnerable": r.get("vulnerable", False),
        "type": r.get("type", ""),
        "evidence": evidence,
        "total_bypasses": r.get("total_bypasses", 0),
        "findings_count": len(r.get("findings", [])),
    }, default=str))

except Exception as e:
    print("JSON:" + json.dumps({
        "vulnerable": False,
        "error": str(e)[:300],
        "traceback": traceback.format_exc()[-500:]
    }))
'''
    script = script.replace("PYTHONPATH_PLACEHOLDER", PYTHONPATH)
    script = script.replace("URL_PLACEHOLDER", url)
    script = script.replace("PARAM_PLACEHOLDER", param)
    script = script.replace("VULN_PLACEHOLDER", vuln_type)
    script = script.replace("DETECTOR_PLACEHOLDER", detector_name)

    try:
        r = subprocess.run(["python", "-c", script], capture_output=True,
                          text=True, timeout=120, env=env)
        output = r.stdout + r.stderr
        m = re.search(r"JSON:(.*)", output)
        if m:
            return json.loads(m.group(1))
        return {"vulnerable": False, "error": "parse_fail"}
    except subprocess.TimeoutExpired:
        return {"vulnerable": False, "error": "timeout"}
    except Exception as e:
        return {"vulnerable": False, "error": str(e)[:200]}


results = {}
print("=" * 65)
print("  DETECTOR VERIFICATION — {} types".format(len(PLAN)))
print("=" * 65)

for vuln_type, target, detector, endpoint, param in PLAN:
    cwd = BENCH / target
    if not cwd.exists():
        results[vuln_type] = {"hit": False, "status": "MISSING_TARGET"}
        print("  [SKIP] {:30s} target missing".format(vuln_type))
        continue

    print("  [{:25s}] {:12s} ".format(vuln_type, target), end="", flush=True)

    port, cwd = start_and_get_port(target)
    if port is None:
        results[vuln_type] = {"hit": False, "status": "NO_PORT"}
        print("NO_PORT")
        subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))
        continue

    url = "http://localhost:{}{}".format(port, endpoint)
    det_result = run_detector(vuln_type, detector, url, param)

    hit = det_result.get("vulnerable", False)
    results[vuln_type] = {
        "hit": hit,
        "status": "HIT" if hit else "MISS",
        "detector": detector,
        "target": target,
        "url": url,
        "evidence": det_result.get("evidence", []),
        "error": det_result.get("error"),
    }

    if hit:
        print("HIT!  ({})".format(det_result.get("type", "?")))
        if det_result.get("evidence"):
            print("        {}".format(str(det_result["evidence"][0])[:100]))
    else:
        print("MISS  ({})".format(det_result.get("error", "no detection")[:60]))

    subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))

# Summary
print("\n" + "=" * 65)
print("  RELIABILITY MATRIX")
print("=" * 65)

hit_count = sum(1 for r in results.values() if r.get("hit"))
miss_count = sum(1 for r in results.values() if not r.get("hit"))

for vt, r in sorted(results.items()):
    icon = "*" if r.get("hit") else "-"
    status = r.get("status", "?")
    info = r.get("evidence", [])[0][:80] if r.get("evidence") else r.get("error", "")
    print("  [{}] {:30s} {:6s}  {}".format(icon, vt, status, info[:80]))

print("\n  {}/{} verified ({:.0f}%)".format(hit_count, len(results),
      hit_count*100/len(results) if results else 0))
