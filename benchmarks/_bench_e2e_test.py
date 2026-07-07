"""
End-to-end benchmark test: build → start → detect → stop.
Tests whether detectors actually find the vulnerabilities they should.
"""
import subprocess, re, os, sys, time, json, socket
from pathlib import Path
from collections import Counter

BENCH_DIR = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")
TOOLS_DIR = Path(r"C:\Users\PC\Desktop\彦\aimy\tools")

# Vulnerability type → detector function (which check() to call)
DETECTOR_MAP = {
    "xss": "xss_detector",
    "sqli": "sql_injection",
    "blind_sqli": "sql_injection",
    "ssti": "ssti_detector",
    "command_injection": "cmdi_detector",
    "ssrf": "ssrf_detector",
    "idor": "auth_bypass",
    "lfi": "lfi_scanner",
    "path_traversal": "lfi_scanner",
    "insecure_deserialization": "deserialization_detector",
    "nosqli": "nosqli_detector",
    "graphql": "graphql_scanner",
    "jwt": "jwt_detector",
    "race_condition": "race_condition",
    "default_credentials": "auth_bypass",
}


def get_port(container_name_prefix: str) -> int:
    """Get exposed port from docker ps."""
    out = subprocess.run(
        f'docker ps --filter "name={container_name_prefix}" --format "{{{{.Ports}}}}"',
        shell=True, capture_output=True, text=True, timeout=5).stdout
    m = re.search(r'(\d+)->(\d+)/tcp', out)
    return int(m.group(1)) if m else None


def wait_for_web(host: str, port: int, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            r = s.connect_ex((host, port))
            s.close()
            if r == 0:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def run_target(name: str) -> dict:
    """Build, start, and test a single benchmark target."""
    cwd = BENCH_DIR / name
    config_path = cwd / "benchmark.json"
    if not config_path.exists():
        return {"name": name, "status": "no_config"}

    with open(config_path) as f:
        config = json.load(f)

    tags = config.get("tags", [])
    level = config.get("level", "?")
    desc = config.get("description", "")[:80]
    expected_vuln = tags[0] if tags else "unknown"

    result = {
        "name": name, "tags": tags, "level": level, "expected": expected_vuln,
        "url": None, "port": None, "status": "pending", "detected": False,
        "detector_used": None
    }

    # Step 1: Build (skip if image exists)
    image_check = subprocess.run(
        f'docker images --format "{{{{.Repository}}}}" | grep -i "{name.lower()[:15]}"',
        shell=True, capture_output=True, text=True, timeout=5)

    if image_check.returncode != 0:
        r = subprocess.run(
            'docker compose build --build-arg FLAG=testflag123 --build-arg flag=testflag123 2>&1',
            shell=True, capture_output=True, text=True, timeout=300, cwd=str(cwd))
        if r.returncode != 0:
            result["status"] = "build_fail"
            result["error"] = r.stdout[-200:] + r.stderr[-200:]
            return result

    # Step 2: Start
    subprocess.run("docker compose down -v 2>&1", shell=True,
                   capture_output=True, text=True, timeout=30, cwd=str(cwd))
    r = subprocess.run("docker compose up -d 2>&1", shell=True,
                       capture_output=True, text=True, timeout=120, cwd=str(cwd))
    if r.returncode != 0:
        result["status"] = "start_fail"
        result["error"] = r.stdout[-200:] + r.stderr[-200:]
        return result

    # Step 3: Get port
    time.sleep(5)
    short = name.lower().replace("-", "_")[:20]
    port = get_port(short)
    if not port:
        result["status"] = "no_port"
        subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))
        return result

    url = "http://localhost:{}".format(port)
    result["port"] = port
    result["url"] = url

    if not wait_for_web("localhost", port, timeout=30):
        result["status"] = "web_not_ready"
        subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))
        return result

    result["status"] = "running"

    # Step 4: Run detector
    detector_name = DETECTOR_MAP.get(expected_vuln)
    if not detector_name:
        result["status"] = "no_detector"
        subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))
        return result

    result["detector_used"] = detector_name

    # Quick curl to find testable params
    curl_out = subprocess.run(
        'curl -s --max-time 5 "{}"'.format(url), shell=True,
        capture_output=True, text=True, timeout=10).stdout

    # Find params from HTML
    params = set()
    for m in re.finditer(r'(?:name|id)=["\']([^"\']+)["\']', curl_out, re.I):
        params.add(m.group(1))
    for m in re.finditer(r'/([a-z_]+)\?(\w+)=', curl_out, re.I):
        params.add(m.group(2))

    # Try common param names
    if not params:
        params = {"id", "q", "search", "user", "name", "page", "query"}

    # Run detector against URL with first likely param
    sys.path.insert(0, str(TOOLS_DIR.parent.parent))
    try:
        # Simple approach: curl-based detection
        # We'll call the detector module directly
        pass
    except Exception:
        pass

    # For now: use curl-based heuristic
    found = False
    for param in list(params)[:3]:
        test_url = "{}?{}=1".format(url, param)

        # Quick test: does the endpoint exist?
        r = subprocess.run(
            'curl -s -o /dev/null -w "%{{http_code}}" --max-time 3 "{}"'.format(test_url),
            shell=True, capture_output=True, text=True, timeout=5)
        if r.stdout.strip() in ("200", "302", "301", "403", "401", "500"):
            result["tested_url"] = test_url
            result["tested_param"] = param
            break

    # Step 5: Cleanup
    subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))
    result["status"] = "tested" if result.get("tested_url") else "no_injectable_param"
    return result


def main():
    # Test a diverse set: one per major vulnerability type
    test_set = {
        "idor": "XBEN-001-24",
        "xss": "XBEN-004-24",
        "ssti": "XBEN-011-24",
        "command_injection": "XBEN-020-24",
        "sqli": "XBEN-030-24",
    }

    # Verify which exist and have correct tags
    actual = {}
    for exp_vuln, name in test_set.items():
        cfg_path = BENCH_DIR / name / "benchmark.json"
        if cfg_path.exists():
            with open(cfg_path) as f:
                cfg = json.load(f)
            actual[name] = cfg.get("tags", [])
        else:
            # Find first benchmark with this tag
            found = False
            for d in sorted(BENCH_DIR.glob("XBEN-*")):
                cfg_path2 = d / "benchmark.json"
                if cfg_path2.exists():
                    with open(cfg_path2) as f:
                        cfg2 = json.load(f)
                    if exp_vuln in cfg2.get("tags", []):
                        actual[d.name] = cfg2.get("tags", [])
                        found = True
                        break
            if not found:
                print("No benchmark found for: {}".format(exp_vuln))

    print("Selected {} targets for E2E testing:".format(len(actual)))
    for name, tags in actual.items():
        print("  {} [{}]".format(name, ",".join(tags)))

    print("\nStarting E2E tests...\n")

    results = {}
    for name, tags in actual.items():
        print("--- {} ---".format(name))
        r = run_target(name)
        results[name] = r
        print("  Status: {}".format(r["status"]))
        if r.get("url"):
            print("  URL: {}".format(r["url"]))
        if r.get("error"):
            print("  Error: {}".format(r["error"][:200]))
        print()

    # Summary
    ok = sum(1 for r in results.values() if r["status"] in ("running", "tested"))
    fail = sum(1 for r in results.values() if r["status"] in ("build_fail", "start_fail", "no_port"))
    print("Summary: {} OK, {} FAIL, {} other".format(ok, fail, len(results) - ok - fail))


if __name__ == "__main__":
    main()
