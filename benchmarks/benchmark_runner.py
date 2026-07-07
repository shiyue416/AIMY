#!/usr/bin/env python3
"""XBOW Benchmark Runner — 全量 104 靶机自动跑测。

用法:
  python benchmark_runner.py                    # 跑全部 104
  python benchmark_runner.py --batch 5          # 跑前 5 个
  python benchmark_runner.py --resume           # 从断点继续
  python benchmark_runner.py --list             # 列出所有靶机
"""
import json, os, sys, re, time, subprocess, glob, socket
from pathlib import Path
from datetime import datetime
from collections import Counter

BENCH_DIR = "C:/Users/PC/Desktop/validation-benchmarks/benchmarks"
HIST_FILE = Path.home() / ".aimy" / "benchmark_history.jsonl"
PARALLEL = 3  # 并发数
TIMEOUT_MIN = 10  # 每个靶机超时(分钟)
FLAG_RE = re.compile(r'flag\{[^}]+\}', re.IGNORECASE)

# 结果统计
results = Counter()
details = []


def get_benchmarks():
    """获取所有靶机列表(按编号排序)。"""
    dirs = sorted(glob.glob(os.path.join(BENCH_DIR, "XBEN-*")))
    return [os.path.basename(d) for d in dirs]


def read_config(name):
    """读取靶机配置。"""
    for path in [
        os.path.join(BENCH_DIR, name, "benchmark.json"),
        os.path.join(BENCH_DIR, name, "benchmark", "benchmark-config.json"),
    ]:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    return {}


def run_cmd(cmd, timeout=120, cwd=None):
    """运行命令并返回输出。"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout, cwd=cwd)
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return str(e), -1


def find_flag(text):
    """从文本中提取 flag。"""
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def get_port(container_name):
    """获取容器暴露端口。"""
    out, _ = run_cmd(f"docker compose port {container_name} 80 2>/dev/null",
                     timeout=10, cwd=os.path.join(BENCH_DIR, container_name.split("_")[0] if "_" not in container_name else container_name))
    # Also try docker ps
    if not out.strip():
        out, _ = run_cmd(f'docker ps --filter "name={container_name[:20]}" --format "{{{{.Ports}}}}"', timeout=10)
    # Parse port from output
    m = re.search(r'(\d+)->80/tcp', out)
    return m.group(1) if m else None


def test_port(host, port):
    """测试端口是否可连。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        r = s.connect_ex((host, port))
        s.close()
        return r == 0
    except:
        return False


def run_benchmark(name):
    """运行单个靶机，返回 (found_flag, details)。"""
    config = read_config(name)
    tags = config.get("tags", [])
    level = config.get("level", "?")
    desc = config.get("description", "")[:80]

    print(f"\n{'='*60}")
    print(f"[{name}] {desc}")
    print(f"[{name}] Tags: {','.join(tags)} Level:{level}")
    print(f"{'='*60}")

    cwd = os.path.join(BENCH_DIR, name)
    result = {"name": name, "tags": tags, "level": level, "flag": None,
              "status": "unknown", "port": None, "error": None}

    # Step 1: Build
    print(f"[{name}] Building...")
    out, code = run_cmd("docker compose build --build-arg FLAG=test_flag_2026",
                       timeout=300, cwd=cwd)
    if code != 0:
        print(f"[{name}] BUILD FAILED: {out[-200:]}")
        result["status"] = "build_fail"
        result["error"] = out[-200:]
        return result
    print(f"[{name}] Build OK")

    # Step 2: Start
    print(f"[{name}] Starting...")
    out, code = run_cmd("docker compose up -d", timeout=60, cwd=cwd)
    if code != 0:
        print(f"[{name}] START FAILED: {out[-200:]}")
        result["status"] = "start_fail"
        result["error"] = out[-200:]
        return result
    print(f"[{name}] Started")

    # Step 3: Wait for port
    time.sleep(3)
    container_name = name.lower().replace("-", "_").replace("_24", "")
    # Try to find port
    port = None
    for _ in range(10):
        out, _ = run_cmd(f'docker ps --filter "name={container_name}" --format "{{{{.Ports}}}}"', timeout=5)
        m = re.search(r'0\.0\.0\.0:(\d+)->80/tcp', out)
        if m:
            port = int(m.group(1))
            break
        m = re.search(r':(\d+)->80/tcp', out)
        if m:
            port = int(m.group(1))
            break
        time.sleep(2)

    if not port:
        print(f"[{name}] No port found, trying docker ps...")
        out, _ = run_cmd("docker ps --format '{{.Names}} {{.Ports}}'", timeout=5)
        print(f"  Docker: {out[:200]}")
        result["status"] = "no_port"
        result["error"] = "Could not find exposed port"
        # Cleanup
        run_cmd("docker compose down -v", timeout=30, cwd=cwd)
        return result

    result["port"] = port
    url = f"http://localhost:{port}/"
    print(f"[{name}] Port: {port} URL: {url}")

    # Step 4: Probe for flag
    print(f"[{name}] Probing...")
    found_flag = None
    probe_urls = ["/", "/flag", "/admin", "/api/flag"]
    for pu in probe_urls:
        out, _ = run_cmd(f'curl -s --max-time 5 "{url.strip("/")}{pu}"', timeout=10)
        if not out:
            continue
        flag = find_flag(out)
        if flag:
            found_flag = flag
            print(f"[{name}] 🔥 FLAG found at {pu}: {flag}")
            break

    # Step 5: Recursive flag search (try common patterns)
    if not found_flag:
        # Try order/ID patterns
        for id_val in [1, 100, 500, 300401, 10032]:
            out, _ = run_cmd(
                f'curl -s --max-time 5 "{url.strip("/")}/order/{id_val}/receipt" 2>/dev/null || '
                f'curl -s --max-time 5 "{url.strip("/")}/api/user/{id_val}" 2>/dev/null || true',
                timeout=10)
            if out:
                flag = find_flag(out)
                if flag:
                    found_flag = flag
                    print(f"[{name}] 🔥 FLAG found at order/{id_val}: {flag}")
                    break

    # Step 6: Still nothing? Do a broader sweep
    if not found_flag:
        out, _ = run_cmd(
            f'curl -s --max-time 10 "{url}"; '
            f'curl -s --max-time 5 -X POST -d "username=admin&password=admin" "{url}" 2>/dev/null; '
            f'curl -s --max-time 5 -X POST -d "username=test&password=test" "{url}" 2>/dev/null',
            timeout=30)
        flag = find_flag(out)
        if flag:
            found_flag = flag
            print(f"[{name}] 🔥 FLAG found via auth: {flag}")

    result["flag"] = found_flag
    result["status"] = "found" if found_flag else "not_found"

    # Step 7: Cleanup
    print(f"[{name}] Cleaning up...")
    run_cmd("docker compose down -v", timeout=60, cwd=cwd)
    print(f"[{name}] Done {'✅' if found_flag else '❌'}")

    return result


def save_result(result):
    """保存结果到历史文件。"""
    HIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now().isoformat(),
        "name": result["name"],
        "tags": result.get("tags", []),
        "level": result.get("level", "?"),
        "flag_found": result.get("flag") is not None,
        "flag": result.get("flag", ""),
        "status": result.get("status", "unknown"),
        "port": result.get("port"),
        "error": result.get("error"),
    }
    with open(HIST_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def load_history():
    """加载历史结果，跳过已完成的。"""
    if not HIST_FILE.exists():
        return []
    done = []
    with open(HIST_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    done.append(json.loads(line))
                except:
                    pass
    return done


def print_summary():
    """打印统计。"""
    history = load_history()
    if not history:
        return

    total = len(history)
    found = sum(1 for h in history if h.get("flag_found"))

    print(f"\n{'='*60}")
    print(f"XBOW Benchmark Results: {found}/{total} flags found ({found*100//total if total else 0}%)")
    print(f"{'='*60}")

    # By tag
    tag_stats = Counter()
    tag_found = Counter()
    for h in history:
        for t in h.get("tags", []):
            tag_stats[t] += 1
            if h.get("flag_found"):
                tag_found[t] += 1

    print("\nBy vulnerability type:")
    for tag, cnt in tag_stats.most_common():
        fcnt = tag_found.get(tag, 0)
        pct = fcnt * 100 // cnt
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        print(f"  {tag:25s} {fcnt:3d}/{cnt:<3d} ({pct:2d}%) {bar}")

    # By level
    level_stats = Counter()
    level_found = Counter()
    for h in history:
        lv = str(h.get("level", "?"))
        level_stats[lv] += 1
        if h.get("flag_found"):
            level_found[lv] += 1

    print("\nBy difficulty:")
    for lv in sorted(level_stats):
        print(f"  Level {lv}: {level_found.get(lv,0)}/{level_stats[lv]}")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="XBOW Benchmark Runner")
    ap.add_argument("--batch", type=int, default=0, help="跑前 N 个")
    ap.add_argument("--resume", action="store_true", help="从断点继续")
    ap.add_argument("--list", action="store_true", help="列出所有靶机")
    args = ap.parse_args()

    all_benches = get_benchmarks()

    if args.list:
        print(f"Total: {len(all_benches)} benchmarks")
        for b in all_benches:
            cfg = read_config(b)
            tags = ",".join(cfg.get("tags", []))
            lv = cfg.get("level", "?")
            desc = cfg.get("description", "")[:50]
            print(f"  {b:15s} L{lv} [{tags:30s}] {desc}")
        return

    # Load history for resume
    done_names = set()
    if args.resume:
        for h in load_history():
            done_names.add(h["name"])
        print(f"Resume mode: {len(done_names)} already done")

    # Filter batch
    if args.batch > 0:
        benches = [b for b in all_benches if b not in done_names][:args.batch]
    else:
        benches = [b for b in all_benches if b not in done_names]

    if not benches:
        print("All benchmarks already completed!")
        print_summary()
        return

    print(f"Running {len(benches)}/{len(all_benches)} benchmarks...")

    # Run sequentially (avoid Docker conflicts)
    start = time.time()
    for i, name in enumerate(benches, 1):
        eta = (time.time() - start) / i * (len(benches) - i) / 60
        print(f"\n{'#'*60}")
        print(f"# [{i}/{len(benches)}] {name}  (ETA: {eta:.1f} min)")
        print(f"{'#'*60}")

        result = run_benchmark(name)
        save_result(result)

        # Update counters
        if result.get("flag"):
            results["found"] += 1
        else:
            results["not_found"] += 1
        details.append(result)

    # Summary
    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"Total time: {elapsed/60:.1f} min")
    print(f"Completed:  {len(benches)}/{len(all_benches)}")
    print_summary()


if __name__ == "__main__":
    main()
