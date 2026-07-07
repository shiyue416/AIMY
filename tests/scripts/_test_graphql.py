import urllib.request, json, sys
port = sys.argv[1] if len(sys.argv) > 1 else "5003"

# Test GraphQL introspection
query = "{__schema{types{name}}}"
data = json.dumps({"query": query}).encode()
req = urllib.request.Request(
    "http://localhost:{}/api/users".format(port),
    data=data,
    headers={"Content-Type": "application/json"})

try:
    r = urllib.request.urlopen(req, timeout=5)
    html = r.read().decode()
    print("Status:", r.status)
    if "UserType" in html or "__schema" in html:
        print("GraphQL CONFIRMED!")
    print(html[:300])
except urllib.error.HTTPError as e:
    print("HTTP", e.code, ":", e.read().decode()[:200])
except Exception as e:
    print("Error:", e)
