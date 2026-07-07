"""Quick detector verification on known-working targets."""
import subprocess, re, time, json, os, socket
from pathlib import Path

BENCH = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")

# Known-working target → vuln type → detector
PLAN = [
    ("XBEN-001-24", "idor", "auth_bypass"),
    ("XBEN-009-24", "ssti", "ssti_detector"),
    ("XBEN-020-24", "ssrf", "ssrf_detector"),
    ("XBEN-005-24", "jwt", "jwt_detector"),
    ("XBEN-030-24", "command_injection", "cmdi_detector"),
    ("XBEN-019-24", "lfi", "lfi_scanner"),
    ("XBEN-014-24", "insecure_deserialization", "deserialization_detector"),
]

def start_target(target):
    cwd = BENCH / target
    subprocess.run("docker compose down -v 2>&1", shell=True,
                  capture_output=True, text=True, timeout=30, cwd=str(cwd))
    r = subprocess.run("docker compose up -d 2>&1", shell=True,
                      capture_output=True, text=True, timeout=90, cwd=str(cwd))
    if r.returncode != 0:
        return None, "compose_fail"

    time.sleep(8)

    # Get port
    ps = subprocess.run(
        "docker compose port app 80 2>&1 || docker compose port web 80 2>&1 || docker compose port web 5000 2>&1 || docker compose port app 5000 2>&1",
        shell=True, capture_output=True, text=True, timeout=5, cwd=str(cwd))
    m = re.search(r':(\d+)', ps.stdout)
    if not m:
        # Check if container is actually running
        short = target.lower().replace("-", "_")[:20]
        ps2 = subprocess.run(
            f'docker ps --filter "name={short}" --format "{{{{.Ports}}}}"',
            shell=True, capture_output=True, text=True, timeout=5)
        m2 = re.search(r'(\d+)->(\d+)/tcp', ps2.stdout)
        if m2:
            port = int(m2.group(1))
        else:
            return None, "no_port"
    else:
        port = int(m.group(1))

    url = "http://localhost:{}".format(port)

    # Verify HTTP
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect(("localhost", port))
        s.close()
    except Exception:
        return None, "port_unreachable"

    return url, port

def run_detector(vuln_type, detector_name, url, port):
    env = os.environ.copy()
    env["PYTHONPATH"] = r"C:\Users\PC\Desktop\彦"

    script = '''
import sys, json, requests
sys.path.insert(0, r"C:\\Users\\PC\\Desktop\\彦")
url = "{url}"
port = {port}
vuln_type = "{vuln_type}"
detector = "{detector}"

sess = requests.Session()
result = {{"vulnerable": False, "error": None, "evidence": []}}

try:
    if detector == "auth_bypass":
        from aimy.tools.auth_bypass import check
        r = check(url, sess=sess, timeout=10.0)
    elif detector == "ssti_detector":
        from aimy.tools.ssti_detector import check
        params = ["name", "template", "q", "search", "id", "page"]
        for p in params:
            r = check(url, p, sess=sess, timeout=10.0)
            if r.get("vulnerable"):
                break
    elif detector == "ssrf_detector":
        from aimy.tools.ssrf_detector import check
        params = ["url", "redirect", "callback", "webhook", "file", "id"]
        for p in params:
            r = check(url, p, sess=sess, timeout=10.0)
            if r.get("vulnerable"):
                break
    elif detector == "jwt_detector":
        from aimy.tools.jwt_detector import check
        r = check(url, "token", sess=sess, timeout=10.0)
    elif detector == "cmdi_detector":
        from aimy.tools.cmdi_detector import check
        params = ["cmd", "exec", "command", "ip", "host", "id"]
        for p in params:
            r = check(url, p, sess=sess, timeout=10.0)
            if r.get("vulnerable"):
                break
    elif detector == "lfi_scanner":
        from aimy.tools.lfi_scanner import check
        params = ["file", "path", "page", "view", "id"]
        for p in params:
            r = check(url, p, sess=sess, timeout=10.0)
            if r.get("vulnerable"):
                break
    elif detector == "deserialization_detector":
        from aimy.tools.deserialization_detector import check
        params = ["data", "payload", "token", "id"]
        for p in params:
            r = check(url, p, sess=sess, timeout=10.0)
            if r.get("vulnerable"):
                break
    else:
        result["error"] = "unknown detector"

    # Only overwrite if defined
    if 'r' in dir():
        result["vulnerable"] = r.get("vulnerable", False)
        result["type"] = r.get("type", "")
        result["evidence"] = [str(e)[:200] for e in r.get("evidence", [])[:3]]
        if "total_bypasses" in r:
            result["total_bypasses"] = r["total_bypasses"]
        if "default_creds" in r:
            result["default_creds_count"] = len(r["default_creds"])

except Exception as e:
    result["error"] = str(e)[:300]

print("JSON_RESULT:" + json.dumps(result, default=str))
'''.format(url=url, port=port, vuln_type=vuln_type, detector=detector_name)

    try:
        r = subprocess.run(["python", "-c", script], capture_output=True,
                          text=True, timeout=120, env=env)
        output = r.stdout + r.stderr
        m = re.search(r'JSON_RESULT:(.*)', output)
        if m:
            return json.loads(m.group(1))
        return {"vulnerable": False, "error": "parse_fail", "raw": output[-300:]}
    except subprocess.TimeoutExpired:
        return {"vulnerable": False, "error": "timeout"}


# Run all tests
print("=" * 60)
print("  Detector Verification (Known-Working Targets)")
print("=" * 60)

results = {}
for target, vuln_type, detector in PLAN:
    cwd = BENCH / target
    if not cwd.exists():
        print("\n[{}] MISSING".format(target))
        continue

    print("\n--- {} | {} | {} ---".format(target, vuln_type, detector))

    # Start
    url, status = start_target(target)
    if isinstance(status, str):
        print("  START FAIL: {}".format(status))
        results[vuln_type] = {"status": status, "hit": False}
        subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))
        continue

    print("  URL: {}".format(url))

    # Run detector
    det_result = run_detector(vuln_type, detector, url, url.split(":")[2].split("/")[0])

    hit = det_result.get("vulnerable", False)
    results[vuln_type] = {
        "status": "HIT" if hit else "miss",
        "detector": detector,
        "evidence": det_result.get("evidence", []),
        "error": det_result.get("error"),
        "target": target,
    }

    if hit:
        print("  HIT! evidence: {}".format(det_result.get("evidence", [])[:2]))
    else:
        print("  MISS: {}".format(det_result.get("error", "no detection")[:100]))

    # Cleanup
    subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))

# Summary
print("\n" + "=" * 60)
print("  Reliability Matrix")
print("=" * 60)
hit = sum(1 for r in results.values() if r["status"] == "HIT")
miss = sum(1 for r in results.values() if r["status"] == "miss")
fail = sum(1 for r in results.values() if r["status"] not in ("HIT", "miss"))

for vt, r in results.items():
    icon = "OK" if r["status"] == "HIT" else ("--" if r["status"] == "miss" else "!!")
    print("  [{}] {:25s} {}".format(icon, vt, r["status"]))
    if r.get("error"):
        print("       error: {}".format(str(r["error"])[:120]))

print("\n  {}/{} verified ({:.0f}%)".format(hit, len(results), hit*100/len(results) if results else 0))
