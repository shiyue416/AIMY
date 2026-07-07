"""逐个验证 14 个检测器 — 需要先手动启动靶机"""
import os, sys, time
os.environ['HTTP_PROXY'] = ''
os.environ['http_proxy'] = ''
sys.path.insert(0, r'C:\Users\PC\Desktop\彦')

from aimy.tools.auth_bypass import check as check_auth
from aimy.tools.ssti_detector import check as check_ssti
from aimy.tools.ssrf_detector import check as check_ssrf
from aimy.tools.lfi_scanner import check as check_lfi
from aimy.tools.jwt_detector import check as check_jwt
from aimy.tools.xss_detector import check as check_xss
from aimy.tools.sql_injection import check as check_sqli
from aimy.tools.cmdi_detector import check as check_cmdi
from aimy.tools.nosqli_detector import check as check_nosqli
from aimy.tools.deserialization_detector import check as check_deser
from aimy.tools.graphql_scanner import check as check_gql
import requests

print("=" * 50)
print("  检测器验证 — 输入靶机端口")
print("=" * 50)
print()
print("用法:")
print("  1. 先启动靶机: docker compose up -d --wait")
print("  2. docker ps 看端口")
print("  3. 在这里输入端口号")
print()

port = input("端口: ").strip()
sess = requests.Session()

# 已验证通过的
print("\n--- 已验证 (5/5) ---")
r = check_auth(f'http://localhost:{port}/', sess=sess, timeout=10.0, max_time=15.0)
print(f"auth_bypass:     {'HIT' if r['vulnerable'] else 'MISS'}")

r = check_ssti(f'http://localhost:{port}/greet/', 'name', sess=sess, timeout=8.0)
print(f"ssti_detector:   {'HIT' if r['vulnerable'] else 'MISS'}")

r = check_ssrf(f'http://localhost:{port}/redirect.php', 'url', sess=sess, timeout=8.0)
print(f"ssrf_detector:   {'HIT' if r['vulnerable'] else 'MISS'}")

r = check_lfi(f'http://localhost:{port}/', 'file', sess=sess, timeout=8.0)
print(f"lfi_scanner:     {'HIT' if r.get('vulnerable') else 'MISS'}")

r = check_jwt(f'http://localhost:{port}/', 'token', sess=sess, timeout=8.0)
print(f"jwt_detector:    {'HIT' if r.get('vulnerable') else 'MISS'}")

# 待验证
print("\n--- 待验证 (9) ---")
r = check_xss(f'http://localhost:{port}/page', 'name', sess=sess, timeout=8.0)
print(f"xss_detector:    {'HIT' if r['vulnerable'] else 'MISS'} | {r.get('type','')}")

r = check_sqli(f'http://localhost:{port}/jobs', 'job_type', sess=sess, timeout=8.0)
print(f"sql_injection:   {'HIT' if r['vulnerable'] else 'MISS'} | {r.get('type','')}")

r = check_cmdi(f'http://localhost:{port}/', 'cmd', sess=sess, timeout=8.0)
print(f"cmdi_detector:   {'HIT' if r['vulnerable'] else 'MISS'} | {r.get('type','')}")

r = check_nosqli(f'http://localhost:{port}/api/users', 'query', sess=sess, timeout=8.0)
print(f"nosqli_detector: {'HIT' if r['vulnerable'] else 'MISS'} | {r.get('type','')}")

r = check_deser(f'http://localhost:{port}/', 'data', sess=sess, timeout=8.0)
print(f"deserialization: {'HIT' if r['vulnerable'] else 'MISS'} | {r.get('type','')}")

r = check_gql(f'http://localhost:{port}/graphql', 'query', sess=sess, timeout=8.0)
print(f"graphql_scanner: {'HIT' if r['vulnerable'] else 'MISS'} | {r.get('type','')}")

print("\n完成。每个靶机需要对应的端口，重复运行即可。")
