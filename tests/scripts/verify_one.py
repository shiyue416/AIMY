"""单靶机验证 — 自动识别类型、选检测器、找端点"""
import os, sys, json, subprocess, re, time
os.environ['HTTP_PROXY'] = ''
os.environ['http_proxy'] = ''
os.environ['HTTPS_PROXY'] = ''
os.environ['https_proxy'] = ''
os.environ['NO_PROXY'] = 'localhost,127.0.0.1,::1'
os.environ['PYTHONIOENCODING'] = 'utf-8'

BENCH = r'C:\Users\PC\Desktop\validation-benchmarks\benchmarks'

# 靶机 → 检测器 + 端点映射（从源码分析得出）
TARGET_MAP = {
    # IDOR
    "XBEN-001-24": ("auth_bypass", "/", "id"),
    "XBEN-002-24": ("auth_bypass", "/", "id"),
    "XBEN-003-24": ("auth_bypass", "/", "id"),
    # XSS
    "XBEN-004-24": ("xss_detector", "/xss25", "solution"),
    "XBEN-008-24": ("xss_detector", "/page", "name"),
    "XBEN-010-24": ("xss_detector", "/xss25", "solution"),
    "XBEN-011-24": ("xss_detector", "/page", "name"),
    "XBEN-012-24": ("xss_detector", "/page", "name"),
    "XBEN-013-24": ("xss_detector", "/page", "name"),
    # SSTI
    "XBEN-009-24": ("ssti_detector", "/greet/", "name"),
    "XBEN-022-24": ("ssti_detector", "/", "name"),
    "XBEN-023-24": ("ssti_detector", "/", "name"),
    # SSRF
    "XBEN-020-24": ("ssrf_detector", "/redirect.php", "url"),
    # LFI
    "XBEN-019-24": ("lfi_scanner", "/", "file"),
    # JWT
    "XBEN-005-24": ("jwt_detector", "/", "token"),
    # SQLi (POST JSON body)
    "XBEN-006-24": ("sql_injection", "/jobs", "job_type"),
    # CMDi
    "XBEN-030-24": ("cmdi_detector", "/", "cmd"),
    # GraphQL (靶机虽是nosqli标签，实际是Graphene-Python)
    "XBEN-100-24": ("graphql_scanner", "/api/users", "query"),
    # GraphQL
    "XBEN-007-24": ("graphql_scanner", "/graphql", "query"),
    # Deserialization
    "XBEN-014-24": ("deserialization_detector", "/", "data"),
    # Race
    "XBEN-088-24": ("race_condition", "/login", "username"),
}

print("=" * 55)
print("  靶机验证器 — 一次验证一个")
print("=" * 55)
print()
print("已支持的靶机:")
for t in sorted(TARGET_MAP):
    det, ep, param = TARGET_MAP[t]
    print(f"  {t}  →  {det}  @ {ep}?{param}=")
print()

target = input("输入靶机名 (如 XBEN-001-24): ").strip()

if target not in TARGET_MAP:
    print(f"未找到 {target}，请手动添加到 TARGET_MAP")
    sys.exit(1)

detector, endpoint, param = TARGET_MAP[target]
cwd = f"{BENCH}\\{target}"

# 启动
print(f"\n启动 {target}...")
subprocess.run(f'docker compose -f "{cwd}\\docker-compose.yml" down -v',
              shell=True, capture_output=True, encoding='utf-8', errors='replace')
r = subprocess.run(
    f'docker compose -f "{cwd}\\docker-compose.yml" up -d --wait',
    shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
if r.returncode != 0:
    print(f"启动失败: {r.stderr[-200:]}")
    sys.exit(1)

# 获取端口 — 直接用 docker ps 默认输出
time.sleep(3)
port = None
name_prefix = target[:10].lower().replace('-', '')
r = subprocess.run('docker ps', shell=True, capture_output=True, text=True,
                   encoding='utf-8', errors='replace')
if r.stdout:
    for line in r.stdout.split('\n'):
        if name_prefix in line.lower():
            m = re.search(r'(\d+)->\d+/tcp', line)
            if m:
                port = m.group(1)
                break

if not port:
    print("\n自动检测端口失败。请在另一个终端运行 docker ps 查看端口。")
    manual = input("手动输入端口号: ").strip()
    if manual.isdigit():
        port = manual

if not port:
    print("找不到端口，容器可能崩溃了")
    subprocess.run(f'docker compose -f "{cwd}\\docker-compose.yml" logs --tail=10',
                  shell=True, encoding='utf-8', errors='replace')
    sys.exit(1)

url = f"http://localhost:{port}{endpoint}"
print(f"端口: {port} → {url}")

# 导入
sys.path.insert(0, r'C:\Users\PC\Desktop\彦')
import requests

# 验证 HTTP 可达
try:
    check_sess = requests.Session()
    check_sess.trust_env = False
    r = check_sess.get(url.replace(endpoint, '/'), timeout=5)
    print(f"HTTP: {r.status_code}")
except Exception as e:
    print(f"HTTP 不可达: {e}")

# 跑检测器
print(f"\n跑 {detector} 检测...")
module = __import__(f"aimy.tools.{detector}", fromlist=['check'])
sess = requests.Session()
sess.trust_env = False  # 绕过系统代理
t0 = time.time()

# 不同检测器签名不同
no_param_detectors = {"auth_bypass"}
json_detectors = {"sql_injection", "nosqli_detector"}
if detector in no_param_detectors:
    result = module.check(url, sess=sess, timeout=10.0, max_time=20.0)
elif detector in json_detectors:
    result = module.check(url, param, sess=sess, timeout=10.0, post_body=True,
                         post_data={param: "1"}, json_body=True)
else:
    result = module.check(url, param, sess=sess, timeout=10.0)
elapsed = time.time() - t0

# 结果
vuln = result.get('vulnerable', False)
print(f"\n{'='*55}")
print(f"  {target}")
print(f"  {'HIT!' if vuln else 'MISS'}")
print(f"  时间: {elapsed:.1f}s")
if result.get('type'):
    print(f"  类型: {result['type']}")
if result.get('evidence'):
    for e in result['evidence'][:3]:
        print(f"  证据: {str(e)[:120]}")
if result.get('findings'):
    print(f"  发现数: {len(result['findings'])}")
if result.get('default_creds'):
    print(f"  凭据: {len(result['default_creds'])} 个")
print(f"{'='*55}")

# 清理
clean = input("\n停止容器? (y/n): ").strip().lower()
if clean == 'y':
    subprocess.run(f'docker compose -f "{cwd}\\docker-compose.yml" down -v',
                  shell=True, capture_output=True, encoding='utf-8', errors='replace')
    print("已停止")
