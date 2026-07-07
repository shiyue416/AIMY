"""
Detector Reliability Verifier — 逐类型验证检测器可信度。

对每种漏洞类型选 1 个 benchmark 靶机：
  build → start → 探测参数 → 跑检测器 → 记录命中 → teardown

输出: 检测器可信度矩阵 + 失败原因
"""
import subprocess, re, time, socket, json, sys, os
from pathlib import Path
from collections import defaultdict

BENCH_DIR = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")

# Vuln type → targets (ordered by simplicity, pick first)
TYPE_TARGETS = {
    "idor": "XBEN-001-24",
    "xss": None,  # find dynamically
    "ssti": None,
    "command_injection": None,
    "sqli": None,
    "ssrf": None,
    "lfi": None,
    "insecure_deserialization": None,
    "nosqli": None,
    "graphql": None,
    "xxe": None,
    "race_condition": None,
    "jwt": None,
    "path_traversal": None,
}

# Find one target per type
print("=== Finding targets ===")
for d in sorted(BENCH_DIR.glob("XBEN-*")):
    cfg_path = d / "benchmark.json"
    if not cfg_path.exists():
        continue
    with open(cfg_path) as f:
        cfg = json.load(f)
    tags = cfg.get("tags", [])
    for tag in tags:
        if tag in TYPE_TARGETS and TYPE_TARGETS[tag] is None:
            TYPE_TARGETS[tag] = d.name
            print("  {} -> {}".format(tag, d.name))

# Only test types we found
test_plan = {k: v for k, v in TYPE_TARGETS.items() if v is not None}
print("\n{} vulnerability types to test\n".format(len(test_plan)))


def run_cmd(cmd, timeout=120, cwd=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return (r.stdout + r.stderr), r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return str(e), -1


def get_port(name_prefix):
    out = subprocess.run(
        f'docker ps --filter "name={name_prefix}" --format "{{{{.Ports}}}}"',
        shell=True, capture_output=True, text=True, timeout=5).stdout
    m = re.search(r'(\d+)->(\d+)/tcp', out)
    return int(m.group(1)) if m else None


def find_params(html):
    """Extract testable params from HTML."""
    params = set()
    for m in re.finditer(r'name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))
    for m in re.finditer(r'/(?:api/)?\w+\?(\w+)=', html, re.I):
        params.add(m.group(1))
    for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I):
        params.add(m.group(1))
    return list(params) if params else ["id"]


def test_one(vuln_type, target_name):
    """Build, start, and test one target."""
    cwd = BENCH_DIR / target_name
    result = {"vuln_type": vuln_type, "target": target_name,
              "status": "unknown", "hit": False, "error": None, "evidence": []}

    print("  [{}] {}...".format(vuln_type, target_name), end=" ", flush=True)

    # Start
    run_cmd("docker compose down -v 2>&1", timeout=30, cwd=str(cwd))
    out, code = run_cmd("docker compose up -d 2>&1", timeout=120, cwd=str(cwd))
    if code != 0:
        result["status"] = "start_fail"
        result["error"] = out[-200:]
        print("START FAIL")
        return result

    time.sleep(5)

    # Get port
    short = target_name.lower().replace("-", "_")[:20]
    port = get_port(short)
    if not port:
        result["status"] = "no_port"
        print("NO PORT")
        run_cmd("docker compose down -v 2>&1", timeout=30, cwd=str(cwd))
        return result

    url = "http://localhost:{}".format(port)
    result["url"] = url
    result["port"] = port

    # Fetch homepage
    try:
        r = subprocess.run('curl -s --max-time 5 "{}"'.format(url),
                          shell=True, capture_output=True, text=True, timeout=10)
        html = r.stdout
    except Exception:
        html = ""

    params = find_params(html)
    param = params[0] if params else "id"
    result["param"] = param

    # Run detector (PYTHONPATH needed for aimy imports)
    env = os.environ.copy()
    env["PYTHONPATH"] = r"C:\Users\PC\Desktop\彦"

    detector_script = '''
import sys, json
sys.path.insert(0, r"C:\\Users\\PC\\Desktop\\彦")

try:
    import requests
    sess = requests.Session()
    url = "{url}"
    param = "{param}"
    vuln_type = "{vuln_type}"

    if vuln_type == "idor":
        from aimy.tools.auth_bypass import check
        r = check(url, sess=sess, timeout=10.0)
    elif vuln_type == "xss":
        from aimy.tools.xss_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "ssti":
        from aimy.tools.ssti_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "command_injection":
        from aimy.tools.cmdi_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "sqli":
        from aimy.tools.sql_injection import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "ssrf":
        from aimy.tools.ssrf_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "lfi" or vuln_type == "path_traversal":
        from aimy.tools.lfi_scanner import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "insecure_deserialization":
        from aimy.tools.deserialization_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "nosqli":
        from aimy.tools.nosqli_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "graphql":
        from aimy.tools.graphql_scanner import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "jwt":
        from aimy.tools.jwt_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "xxe":
        from aimy.tools.deserialization_detector import check
        r = check(url, param, sess=sess, timeout=10.0)
    elif vuln_type == "race_condition":
        from aimy.tools.race_condition import check
        r = check(url, param, sess=sess, timeout=10.0)
    else:
        r = {{"vulnerable": False, "error": "unknown type"}}

    # Clean evidence for JSON serialization
    if isinstance(r, dict):
        evidence = []
        for e in r.get("evidence", [])[:3]:
            evidence.append(str(e)[:200])
        print("JSON_RESULT:" + json.dumps({{
            "vulnerable": r.get("vulnerable", False),
            "type": r.get("type", ""),
            "evidence": evidence,
            "total_bypasses": r.get("total_bypasses", 0),
            "default_creds_count": len(r.get("default_creds", [])),
        }}, default=str))
    else:
        print("JSON_RESULT:" + json.dumps({{"vulnerable": False, "error": "non-dict result"}}))

except Exception as e:
    print("JSON_RESULT:" + json.dumps({{"vulnerable": False, "error": str(e)[:300]}}))
'''.format(url=url, param=param, vuln_type=vuln_type)

    try:
        r = subprocess.run(
            ["python", "-c", detector_script],
            capture_output=True, text=True, timeout=120, env=env)
        output = r.stdout + r.stderr

        # Extract JSON result
        m = re.search(r'JSON_RESULT:(.*)', output)
        if m:
            det_result = json.loads(m.group(1))
            result["hit"] = det_result.get("vulnerable", False)
            result["evidence"] = det_result.get("evidence", [])
            result["detector_output"] = det_result
            if result["hit"]:
                result["status"] = "HIT"
                print("HIT!")
            else:
                result["status"] = "miss"
                result["error"] = det_result.get("error", "no vulnerability detected")
                print("miss: {}".format(result["error"][:80]))
        else:
            result["status"] = "parse_error"
            result["error"] = output[-300:]
            print("PARSE ERR")

    except Exception as e:
        result["status"] = "exec_error"
        result["error"] = str(e)[:200]
        print("EXEC ERR")

    # Cleanup
    run_cmd("docker compose down -v 2>&1", timeout=30, cwd=str(cwd))
    return result


# Test types with existing images only (build already done)
test_order = ["idor", "xss", "ssti", "command_injection", "sqli",
              "ssrf", "lfi", "insecure_deserialization",
              "nosqli", "graphql", "xxe", "race_condition", "jwt", "path_traversal"]

print("=== Running detector verification ===\n")
results = {}

for vt in test_order:
    target = TYPE_TARGETS.get(vt)
    if not target:
        print("  [{}] NO TARGET".format(vt))
        results[vt] = {"status": "no_target"}
        continue

    # Skip if not in test_plan
    if vt not in test_plan:
        continue

    results[vt] = test_one(vt, target)

# Summary
print("\n" + "=" * 60)
print("  Detector Reliability Matrix")
print("=" * 60)
hit = 0
miss = 0
fail = 0
for vt in test_order:
    r = results.get(vt, {})
    status = r.get("status", "skipped")
    if status == "HIT":
        hit += 1
        icon = "✅"
    elif status == "miss":
        miss += 1
        icon = "❌"
    else:
        fail += 1
        icon = "⚠️"
    print("  {} {:25s} {}".format(icon, vt, status))
    if r.get("error"):
        print("     Error: {}".format(str(r["error"])[:100]))

total = hit + miss + fail
print("\n  {}/{} detectors verified working".format(hit, total))
if miss:
    print("  {} missed — need investigation".format(miss))
if fail:
    print("  {} failed to run — infrastructure issue".format(fail))
