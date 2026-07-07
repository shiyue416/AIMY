import os, sys
os.environ['HTTP_PROXY'] = ''
os.environ['http_proxy'] = ''
sys.path.insert(0, r'C:\Users\PC\Desktop\彦')

from aimy.tools.xss_detector import check
import requests

port = sys.argv[1] if len(sys.argv) > 1 else '60625'
r = check('http://localhost:{}/page'.format(port), 'name', sess=requests.Session(), timeout=8.0)
print('vuln:', r.get('vulnerable'))
print('type:', r.get('type'))
print('evidence:', r.get('evidence')[:3])
print('vector:', r.get('vector', '')[:80] if r.get('vector') else '')
