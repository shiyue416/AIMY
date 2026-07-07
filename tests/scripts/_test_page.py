import urllib.request, sys
port = sys.argv[1] if len(sys.argv) > 1 else "55541"
r = urllib.request.urlopen("http://localhost:{}/page?name=test123".format(port))
print(r.read().decode()[:500])
