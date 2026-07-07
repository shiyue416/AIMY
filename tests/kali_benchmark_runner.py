#!/usr/bin/env python3
"""
XBOW Benchmark Auto-Runner — Kali 版
=====================================
在 Kali 上运行，通过局域网打 Windows 上的 Docker 容器。

架构:
  Windows (Docker) ←→ Kali (AIMY 攻击端)
  192.168.x.x:xxxx      对每个 benchmark 自动探测

用法:
  # 先在 Windows 上启动所有 benchmark（一次性批量启动）
  python kali_benchmark_runner.py --mode remote --host 192.168.1.100 --start-port 10080

  # 或者在 Kali 本地跑（需要 Kali 有 Docker）
  python kali_benchmark_runner.py --mode local

  # 单靶机测试
  python kali_benchmark_runner.py --mode local --single XBEN-001-24
"""

import json, os, sys, re, time, subprocess, socket, argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

# === CONFIG ============================================================
BENCH_DIR = Path("C:/Users/PC/Desktop/validation-benchmarks/benchmarks")  # Windows 路径
AIMY_MAIN = Path("C:/Users/PC/Desktop/四月-skill-main/main.py")
RESULTS_FILE = Path.home() / ".aimy" / "kali_bench_results.jsonl"
PARALLEL = 3          # 并发跑 benchmark 数（受 Docker 资源限制）
TIMEOUT_PER_BENCH = 600  # 每个靶机 10 分钟
FLAG_RE = re.compile(r'flag\{[^}]+\}|FLAG\{[^}]+\}', re.IGNORECASE)
# =======================================================================


def get_benchmarks():
    """获取所有 benchmark 列表。"""
    dirs = sorted(BENCH_DIR.glob("XBEN-*"))
    return [d.name for d in dirs]


def read_config(name: str) -> dict:
    """读取 benchmark 配置。"""
    for fname in ["benchmark.json", "benchmark/benchmark-config.json"]:
        path = BENCH_DIR / name / fname
        if path.exists():
            with open(path) as f:
                return json.load(f)
    return {}


def run_cmd(cmd: str, timeout: int = 120, cwd=None) -> tuple:
    """运行命令，返回 (output, returncode)。"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout, cwd=cwd)
        return (r.stdout + r.stderr), r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return str(e), -1


def find_flag(text: str) -> str | None:
    """从文本中提取 flag。"""
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def wait_for_port(host: str, port: int, timeout: int = 30) -> bool:
    """等待端口可连通。"""
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


def port_from_docker_ps(name: str) -> int | None:
    """从 docker ps 获取 benchmark 的暴露端口。"""
    short = name.lower().replace("-", "_").replace("_24", "")[:20]
    out, _ = run_cmd(f'docker ps --filter "name={short}" --format "{{{{.Ports}}}}"', timeout=5)
    m = re.search(r'(\d+)->\d+/tcp', out)
    return int(m.group(1)) if m else None


# ======================================================================
# Phase 2: Recon（被动）
# ======================================================================

def phase_recon(url: str) -> dict:
    """被动侦察——快速获取端点清单。"""
    endpoints = set()

    # 首页
    out, _ = run_cmd(f'curl -s --max-time 5 "{url}"', timeout=10)
    if out:
        # 提取 href/src/action
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', out, re.I):
            endpoints.add(m.group(1))

    # 常见路径探测（只读、低频）
    common = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
              "/api/", "/swagger.json", "/openapi.json", "/graphql?query={__schema{types{name}}}"]
    for p in common:
        out, code = run_cmd(f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 3 "{url.rstrip("/")}{p}"', timeout=5)
        if out.strip() and out.strip() != "404":
            endpoints.add(p)

    return {"url": url, "endpoints": list(endpoints), "count": len(endpoints)}


# ======================================================================
# Phase 3-4: Hunt（主动探测）
# ======================================================================

def phase_hunt_aimy(url: str, tags: list) -> dict:
    """调用 AIMY main.py auto 全自动管线。"""
    mode = "veteran"
    cmd = f'python "{AIMY_MAIN}" auto -u "{url}" --mode {mode} --timeout 300'
    out, code = run_cmd(cmd, timeout=TIMEOUT_PER_BENCH)
    flag = find_flag(out)
    return {"output": out[-2000:], "flag": flag, "returncode": code}


def phase_hunt_quick(url: str, tags: list) -> dict:
    """
    快速针对性探测——根据 tags 选对应的 main.py 子命令。
    避免全量 auto 太慢，老鸟模式下精准打击。
    """
    flag = None
    results = []

    # tag → main.py 命令映射
    TAG_CMD_MAP = {
        "idor": f'python "{AIMY_MAIN}" auth-bypass "{url}"',
        "sqli": f'python "{AIMY_MAIN}" sqlcheck "{url}"',
        "xss": f'python "{AIMY_MAIN}" xsscheck "{url}"',
        "ssrf": f'python "{AIMY_MAIN}" ssrf "{url}"',
        "cmdi": f'python "{AIMY_MAIN}" cmdi "{url}"',
        "ssti": f'python "{AIMY_MAIN}" ssti "{url}"',
        "jwt": f'python "{AIMY_MAIN}" jwt "{url}"',
        "lfi": f'python "{AIMY_MAIN}" lfi "{url}"',
        "graphql": f'python "{AIMY_MAIN}" graphql "{url}"',
        "deserialization": f'python "{AIMY_MAIN}" deser "{url}"',
        "race_condition": f'python "{AIMY_MAIN}" race-condition "{url}"',
    }

    for tag in tags:
        tag_lower = tag.lower().replace("-", "_").replace(" ", "_")
        cmd = TAG_CMD_MAP.get(tag_lower)
        if not cmd:
            continue
        out, code = run_cmd(cmd, timeout=120)
        f = find_flag(out)
        results.append({"tag": tag, "cmd": cmd, "flag": f, "code": code})
        if f:
            flag = f
            break

    return {"flag": flag, "results": results}


def phase_hunt_burp(url: str) -> dict:
    """
    Burp MCP 快速验证——仅限本机有 Burp 时使用。
    检测是否能通过 Burp 的被动扫描/主动扫描发现 flag。
    """
    # 尝试通过 Burp 的 proxy_history 和 passive_intel 检测
    # 这是可选通道，不影响主流程
    return {"burp_available": False, "flag": None}


# ======================================================================
# Single benchmark runner
# ======================================================================

def run_single_benchmark(name: str, mode: str = "local", host: str = "localhost",
                         base_port: int = None) -> dict:
    """
    跑单个 benchmark 的完整流程:
      mode=local: 在本机 build+up → localhost 探测
      mode=remote: 假设容器已在远程 Windows 上跑好，直接打 host:port
    """
    config = read_config(name)
    tags = config.get("tags", [])
    level = config.get("level", "?")
    desc = config.get("description", "")[:100]
    win = config.get("win_condition", "flag")

    result = {
        "name": name, "tags": tags, "level": level, "win_condition": win,
        "flag": None, "status": "pending", "port": None, "url": None,
        "ts_start": datetime.now().isoformat()
    }

    print(f"\n{'='*60}")
    print(f"  [{name}] L{level} | {','.join(tags)}")
    print(f"  [{name}] {desc}")
    print(f"{'='*60}")

    cwd = BENCH_DIR / name
    port = None

    if mode == "local":
        # Step 1: Build
        print(f"  [{name}] Building Docker image...")
        out, code = run_cmd(
            'docker compose build --build-arg FLAG="XBOW_FLAG_TEST_2026" '
            '--build-arg flag="XBOW_FLAG_TEST_2026"',
            timeout=300, cwd=str(cwd))
        if code != 0:
            result["status"] = "build_fail"
            result["error"] = out[-300:]
            print(f"  [{name}] ❌ BUILD FAILED")
            return result
        print(f"  [{name}] Build OK")

        # Step 2: Start
        print(f"  [{name}] Starting container...")
        out, code = run_cmd("docker compose up -d --wait", timeout=120, cwd=str(cwd))
        if code != 0:
            # try without --wait for older docker compose
            out, code = run_cmd("docker compose up -d", timeout=60, cwd=str(cwd))
        if code != 0:
            result["status"] = "start_fail"
            result["error"] = out[-300:]
            print(f"  [{name}] ❌ START FAILED")
            return result

        # Step 3: Get port
        time.sleep(3)
        for _ in range(15):
            port = port_from_docker_ps(name)
            if port:
                break
            time.sleep(2)

        if not port:
            result["status"] = "no_port"
            result["error"] = "Port not found in docker ps"
            print(f"  [{name}] ❌ NO PORT")
            run_cmd("docker compose down -v", timeout=30, cwd=str(cwd))
            return result

    elif mode == "remote":
        # Remote mode: 端口是 base_port + index
        port = base_port
        if not wait_for_port(host, port, timeout=10):
            result["status"] = "port_unreachable"
            result["error"] = f"{host}:{port} not reachable"
            print(f"  [{name}] ❌ {host}:{port} UNREACHABLE")
            return result

    result["port"] = port
    url = f"http://{host}:{port}/"
    result["url"] = url
    print(f"  [{name}] 🌐 {url}")

    # ================================================================
    # Phase 2: Recon
    # ================================================================
    print(f"  [{name}] Phase 2: Recon...")
    recon = phase_recon(url)
    print(f"  [{name}]   Found {recon['count']} endpoints")

    # ================================================================
    # Phase 3-4: Hunt
    # ================================================================
    print(f"  [{name}] Phase 4: Hunt ({','.join(tags) if tags else 'generic'})...")

    # 先用针对性快速扫描
    quick = phase_hunt_quick(url, tags)
    flag = quick.get("flag")

    # 如果没找到，用全量 auto 管线
    if not flag:
        print(f"  [{name}]   Quick scan miss, running full auto pipeline...")
        aimy_result = phase_hunt_aimy(url, tags)
        flag = aimy_result.get("flag")

    # Fallback: 直接 curl 常见 flag 路径
    if not flag:
        for p in ["/flag", "/api/flag", "/admin/flag", "/.flag", "/flag.txt"]:
            out, _ = run_cmd(f'curl -s --max-time 3 "{url.rstrip("/")}{p}"', timeout=5)
            flag = find_flag(out)
            if flag:
                print(f"  [{name}]   Flag found at {p}")
                break

    # ================================================================
    # Result
    # ================================================================
    result["flag"] = flag
    result["status"] = "found" if flag else "not_found"
    result["ts_end"] = datetime.now().isoformat()

    if flag:
        print(f"  [{name}] 🔥 FLAG: {flag}")
    else:
        print(f"  [{name}] ❌ NO FLAG")

    # Cleanup (local mode)
    if mode == "local":
        print(f"  [{name}] Cleaning up...")
        run_cmd("docker compose down -v", timeout=60, cwd=str(cwd))

    return result


def save_result(result: dict):
    """追加结果到 JSONL。"""
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")


def load_history() -> list:
    """加载已有结果。"""
    if not RESULTS_FILE.exists():
        return []
    results = []
    with open(RESULTS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return results


def print_summary():
    """打印汇总统计。"""
    history = load_history()
    if not history:
        print("\nNo results yet.")
        return

    total = len(history)
    found = sum(1 for h in history if h.get("flag"))
    fail = sum(1 for h in history if h["status"] in ("build_fail", "start_fail", "no_port"))

    print(f"\n{'='*60}")
    print(f"  XBOW Benchmark Summary")
    print(f"  {'='*60}")
    print(f"  Total:    {total}")
    print(f"  Flags:    {found} ({found*100//total if total else 0}%)")
    print(f"  Failed:   {fail}")
    print(f"  Missed:   {total - found - fail}")

    # 按漏洞类型
    tag_total = Counter()
    tag_found = Counter()
    for h in history:
        for t in h.get("tags", []):
            tag_total[t] += 1
            if h.get("flag"):
                tag_found[t] += 1

    if tag_total:
        print(f"\n  By vulnerability type:")
        for tag, cnt in tag_total.most_common():
            fcnt = tag_found.get(tag, 0)
            pct = fcnt * 100 // cnt if cnt else 0
            bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
            print(f"    {tag:25s} {fcnt:3d}/{cnt:<3d} {bar} {pct}%")

    # 按难度
    level_total = Counter()
    level_found = Counter()
    for h in history:
        lv = str(h.get("level", "?"))
        level_total[lv] += 1
        if h.get("flag"):
            level_found[lv] += 1

    print(f"\n  By difficulty:")
    for lv in sorted(level_total):
        print(f"    Level {lv}: {level_found.get(lv,0)}/{level_total[lv]}")


# ======================================================================
# Batch mode: 在 Windows 上启动所有 benchmark，输出端口映射表
# ======================================================================

def batch_start_all(start_idx: int = 0, count: int = None, base_port: int = 10080):
    """
    批量启动 benchmark，返回端口映射表。
    供 Kali 远程连接使用。
    """
    all_benches = get_benchmarks()
    if count:
        all_benches = all_benches[start_idx:start_idx + count]

    mapping = {}
    for i, name in enumerate(all_benches):
        port = base_port + i
        cwd = BENCH_DIR / name
        print(f"[{i+1}/{len(all_benches)}] {name} → port {port}")

        # Build
        out, code = run_cmd(
            f'docker compose build --build-arg FLAG="XBOW_FLAG_2026" '
            f'--build-arg flag="XBOW_FLAG_2026"',
            timeout=300, cwd=str(cwd))
        if code != 0:
            print(f"  ❌ Build failed")
            continue

        # Start with mapped port
        out, code = run_cmd(
            f'docker compose up -d', timeout=60, cwd=str(cwd))
        if code != 0:
            print(f"  ❌ Start failed")
            continue

        mapping[name] = port
        time.sleep(1)  # stagger startups

    # Save mapping
    map_file = BENCH_DIR.parent / "port_mapping.json"
    with open(map_file, "w") as f:
        json.dump(mapping, f, indent=2)
    print(f"\nPort mapping saved to {map_file}")
    print(f"On Kali, run: python kali_benchmark_runner.py --mode remote --host <WINDOWS_IP> --map {map_file}")

    return mapping


# ======================================================================
# Main
# ======================================================================

def main():
    ap = argparse.ArgumentParser(description="XBOW Benchmark Auto-Runner (Kali Edition)")
    ap.add_argument("--mode", choices=["local", "remote", "batch-start"], default="local",
                   help="local=Kali有Docker / remote=打远程Windows / batch-start=Windows批量启动")
    ap.add_argument("--single", type=str, help="只跑单个 benchmark")
    ap.add_argument("--batch", type=int, default=0, help="跑前 N 个")
    ap.add_argument("--resume", action="store_true", help="跳过已完成")
    ap.add_argument("--host", type=str, default="localhost", help="远程 Docker 主机 IP（remote 模式）")
    ap.add_argument("--start-port", type=int, default=10080, help="起始端口（batch-start/remote 模式）")
    ap.add_argument("--map", type=str, help="端口映射文件（remote 模式）")
    ap.add_argument("--list", action="store_true", help="列出所有靶机")
    ap.add_argument("--summary", action="store_true", help="打印汇总统计")
    args = ap.parse_args()

    if args.summary:
        print_summary()
        return

    all_benches = get_benchmarks()

    if args.list:
        print(f"Total: {len(all_benches)} benchmarks\n")
        for b in all_benches[:20]:
            cfg = read_config(b)
            print(f"  {b:15s} L{cfg.get('level','?')} [{','.join(cfg.get('tags',[])):30s}] {cfg.get('description','')[:60]}")
        if len(all_benches) > 20:
            print(f"  ... and {len(all_benches)-20} more")
        return

    # Batch start mode (runs on Windows)
    if args.mode == "batch-start":
        batch_start_all(base_port=args.start_port)
        return

    # Select benchmarks
    done_names = set()
    if args.resume:
        for h in load_history():
            if h.get("flag") or h["status"] in ("build_fail", "start_fail"):
                done_names.add(h["name"])
        print(f"Resume: {len(done_names)} already done, {len(all_benches) - len(done_names)} remaining")

    if args.single:
        targets = [args.single]
    elif args.batch:
        targets = [b for b in all_benches if b not in done_names][:args.batch]
    else:
        targets = [b for b in all_benches if b not in done_names]

    if not targets:
        print("Nothing to run.")
        print_summary()
        return

    print(f"\n{'#'*60}")
    print(f"  Mode: {args.mode} | Targets: {len(targets)}")
    print(f"  Host: {args.host} | Start Port: {args.start_port}")
    print(f"{'#'*60}")

    if args.mode == "remote":
        # Load port mapping
        map_file = args.map or (BENCH_DIR.parent / "port_mapping.json")
        if Path(map_file).exists():
            with open(map_file) as f:
                port_map = json.load(f)
            print(f"Loaded port mapping: {len(port_map)} entries")
        else:
            print("No port mapping file, using --start-port offset")
            port_map = {}

        for i, name in enumerate(targets):
            port = port_map.get(name, args.start_port + i)
            result = run_single_benchmark(name, mode="remote", host=args.host, base_port=port)
            save_result(result)

    else:
        # Local mode: sequential
        for i, name in enumerate(targets):
            print(f"\n[{i+1}/{len(targets)}]")
            result = run_single_benchmark(name, mode="local")
            save_result(result)

    print_summary()


if __name__ == "__main__":
    main()
