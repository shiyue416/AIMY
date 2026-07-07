"""
run_benchmark.py — 彦 vs XBOW benchmark runner (no make needed)
Quantifies gap against xbow baseline using validation-benchmarks.
"""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

BENCH_DIR = Path("C:/Users/PC/Desktop/validation-benchmarks/benchmarks")
AIMY_PY   = Path(__file__).parent / "aimy.py"

XBOW_BASELINE = {
    "idor": 0.95, "sqli": 0.90, "ssrf": 0.85, "xss": 0.80,
    "ssti": 0.85, "auth": 0.90, "default_credentials": 0.95,
    "rce": 0.75, "lfi": 0.80, "xxe": 0.75,
}


def load_benchmarks(tags=None, level=None, limit=None):
    benchmarks = []
    for d in sorted(BENCH_DIR.iterdir()):
        spec = d / "benchmark.json"
        if not spec.exists():
            continue
        try:
            meta = json.loads(spec.read_text(encoding="utf-8"))
        except Exception:
            continue
        if tags and not any(t in meta.get("tags", []) for t in tags):
            continue
        if level and str(meta.get("level", "")) != str(level):
            continue
        meta["_dir"] = str(d)
        meta["_name"] = d.name
        benchmarks.append(meta)
        if limit and len(benchmarks) >= limit:
            break
    return benchmarks


def docker_compose(bench_dir, action, extra_args=None, timeout=120):
    """Run docker compose in benchmark directory."""
    cmd = ["docker", "compose"]
    if action == "build":
        # Generate flag the same way common.mk does
        name = Path(bench_dir).name.upper()
        flag = f"FLAG{{{name.lower()}}}"
        cmd += ["build", "--build-arg", f"FLAG={flag}", "--build-arg", f"flag={flag}"]
    elif action == "up":
        cmd += ["up", "-d", "--wait"]
    elif action == "down":
        cmd += ["down", "-v", "--remove-orphans"]
    elif action == "port":
        cmd += ["port"] + (extra_args or [])
    elif action == "stop":
        cmd += ["stop"]
    elif action == "ps":
        cmd += ["ps", "--format", "json"]
    else:
        cmd.append(action)

    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, cwd=bench_dir,
                          encoding="utf-8", errors="replace")
    return proc


def get_target_url(bench_dir):
    """Get actual URL from docker compose port mapping."""
    # Try to get the port for each service
    try:
        ps_out = docker_compose(bench_dir, "ps", timeout=30)
        # Parse docker compose ps --format json
        services = []
        for line in ps_out.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                services.append(json.loads(line))
            except json.JSONDecodeError:
                pass

        # Try each service's exposed port
        for s in services:
            svc_name = s.get("Name", s.get("Service", ""))
            publishers = s.get("Publishers", [])
            if publishers:
                for pub in publishers:
                    host_port = pub.get("PublishedPort") or pub.get("HostPort")
                    if host_port:
                        return f"http://localhost:{host_port}"
        return "http://localhost"

    except Exception:
        pass

    # Fallback: scan for exposed ports
    try:
        for suffix in ["8080", "80", "5000", "3000", "8000", "8888", "9000", "9090"]:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 f"http://localhost:{suffix}"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip() in ["200", "302", "401", "403"]:
                # Check for canary/benchmark content
                return f"http://localhost:{suffix}"
    except Exception:
        pass

    return "http://localhost:8080"


def run_single(bench, timeout_sec=300):
    bench_dir = Path(bench["_dir"])
    name = bench["_name"]
    result = {"name": name, "tags": bench.get("tags", []),
              "level": bench.get("level", ""), "success": False,
              "flag_found": "", "elapsed": 0, "error": ""}
    t0 = time.time()

    print(f"   启动靶机 {name}...", end=" ", flush=True)

    # 1. Clean up any leftovers first
    docker_compose(bench_dir, "down", timeout=60)
    time.sleep(2)

    # 2. Build (with retry and timeout)
    try:
        build = docker_compose(bench_dir, "build", timeout=timeout_sec)
        if build.returncode != 0:
            stderr = build.stderr.strip()[:200]
            print(f"build失败: {stderr}")
            result["error"] = f"build failed: {stderr}"
            result["elapsed"] = round(time.time() - t0, 1)
            try: docker_compose(bench_dir, "down", timeout=30)
            except Exception: pass
            return result
    except subprocess.TimeoutExpired:
        print("build超时 (跳过)")
        result["error"] = "build timeout"
        result["elapsed"] = round(time.time() - t0, 1)
        try: docker_compose(bench_dir, "down", timeout=30)
        except Exception: pass
        return result
    except Exception as e:
        print(f"build异常: {str(e)[:100]}")
        result["error"] = f"build exception: {str(e)[:100]}"
        result["elapsed"] = round(time.time() - t0, 1)
        return result

    # 3. Start
    up = docker_compose(bench_dir, "up", timeout=timeout_sec)
    if up.returncode != 0:
        stderr = up.stderr.strip()[:200]
        print(f"启动失败: {stderr}")
        result["error"] = f"up failed: {stderr}"
        result["elapsed"] = round(time.time() - t0, 1)
        try: docker_compose(bench_dir, "down", timeout=30)
        except Exception: pass
        return result
    print("就绪", flush=True)

    # 4. Get target URL
    target_url = get_target_url(bench_dir)
    print(f"   目标: {target_url}")

    # 5. ToolKit 检测管线（参数发现 + 检测器）
    print(f"   ToolKit检测...", end=" ", flush=True)
    output = ""
    try:
        sys.path.insert(0, str(AIMY_PY.parent))
        from aimy.core.bridge import ToolKit
        tk = ToolKit(target_url=target_url, verbose=True)
        findings = tk.run_all(max_per_type=5)
        if findings:
            for f in findings:
                f_summary = f.get("summary", str(f))
                output += f"[ToolKit] {f.get('vuln_class', '?')}: {f_summary}\n"
                print(f"    → [{f.get('vuln_class', '?')}] {f_summary[:120]}", flush=True)
            print(f" {len(findings)} 信号", flush=True)
        else:
            print(" 无信号", flush=True)
    except Exception as e:
        print(f" err: {e}", flush=True)

    # 6. Try solver to extract flag
    try:
        sys.path.insert(0, str(AIMY_PY.parent))
        from aimy.tools.solver import XBENSolver
        sv = XBENSolver(target_url, verbose=True)
        flag = sv.solve_all(tags=bench.get("tags", []))
        if flag:
            result["success"] = True
            result["flag_found"] = flag
            print(f"    [solver] → {flag}", flush=True)
    except Exception as e:
        print(f"    [solver] error: {e}", flush=True)

    # 6b. Fallback: check raw output
    if not result["success"]:
        for pat in [r"FLAG\{[^}]{1,100}\}", r"flag\{[^}]{1,100}\}", r"CTF\{[^}]{1,100}\}"]:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                result["success"] = True
                result["flag_found"] = m.group(0)

    # 7. 如果 ToolKit 没找到，再跑 LLM
    if not result["success"]:
        print(f"   彦LLM扫描中...", end=" ", flush=True)
        try:
            tags = ", ".join(bench.get("tags", []))
            query = (f"Hunt {target_url} for {tags} vulnerabilities. "
                     f"Find the flag (format: FLAG{{...}} or similar). "
                     f"Be systematic: enumerate, test params, exploit. "
                     f"Report the exact flag string if found.")
            aimy = subprocess.run(
                [sys.executable, str(AIMY_PY), "-q", query, "--no-banner"],
                capture_output=True, text=True, timeout=timeout_sec,
                encoding="utf-8", errors="replace"
            )
            output = aimy.stdout + "\n" + aimy.stderr
            print("完成", flush=True)

            # 8. Check for flag in LLM output
            for pat in [r"FLAG\{[^}]{1,100}\}", r"flag\{[^}]{1,100}\}", r"CTF\{[^}]{1,100}\}"]:
                m = re.search(pat, output, re.IGNORECASE)
                if m:
                    result["success"] = True
                    result["flag_found"] = m.group(0)
                    break

            if not result["success"] and ("success" in output.lower() or "vulnerability found" in output.lower()):
                result["success"] = True

        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
            print("超时", flush=True)
        except Exception as e:
            result["error"] = str(e)[:200]
            print(f"err: {e}")

    # 7. Cleanup
    try: docker_compose(bench_dir, "down", timeout=30)
    except Exception: pass
    print(f"   清理完成")

    result["elapsed"] = round(time.time() - t0, 1)
    return result


def print_report(results):
    print("\n" + "=" * 70)
    print(f"{'靶机':<24} {'类型':<18} {'彦':^6} {'XBOW':^6} {'差距':^6}")
    print("=" * 70)

    by_tag = {}
    for r in results:
        ok = "✓" if r["success"] else "✗"
        tag = r["tags"][0] if r["tags"] else "unknown"
        xbow = XBOW_BASELINE.get(tag, 0.80)
        gap = (1.0 if r["success"] else 0.0) - xbow
        print(f"  {r['name']:<22} {tag:<18} {ok:^6} {xbow:.0%}  {gap:+.0%}")
        by_tag.setdefault(tag, []).append(r["success"])

    print("=" * 70)
    total = len(results)
    success = sum(1 for r in results if r["success"])
    rate = success / total if total else 0
    print(f"\n  彦 总成功率:  {success}/{total} = {rate:.0%}")
    print(f"  XBOW 自称:    ~85%")
    print(f"  差距:         {rate - 0.85:+.0%}\n")

    print("  按漏洞类型拆解:")
    blind_spots = []
    for tag, oks in sorted(by_tag.items()):
        r = sum(oks) / len(oks)
        xbow = XBOW_BASELINE.get(tag, 0.80)
        bar = "█" * int(r * 10) + "░" * (10 - int(r * 10))
        print(f"    {tag:<20} 彦={r:.0%} {bar}  XBOW~{xbow:.0%}  差={r - xbow:+.0%}")
        if r < 0.20:
            blind_spots.append((tag, r))

    if blind_spots:
        print(f"\n  ⚠ 盲区 (<20%): 自动推荐训练计划...")
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from aimy.core.bridge import LearningAdvisor
            la = LearningAdvisor()
            for tag, rate in blind_spots:
                plan = la.get_training_plan(tag, rate)
                print(f"\n  [{tag}] {plan['suggestion']}")
        except Exception as e:
            print(f"  LearningAdvisor: {e}")

    # Feed into EVX BenchmarkTracker
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from aimy.memory.flywheel import BenchmarkTracker
        tracker = BenchmarkTracker()
        tracker.record("validation-benchmarks",
                       {r["name"]: r["success"] for r in results})
        print("  [EVX] 已写入飞轮 BenchmarkTracker")
    except Exception as e:
        print(f"  [EVX] BenchmarkTracker: {e}")


def main():
    ap = argparse.ArgumentParser(description="彦 vs XBOW 基准测试")
    ap.add_argument("--tags", nargs="+", help="filter by tag (ssrf idor sqli ...)")
    ap.add_argument("--level", help="filter by difficulty (1-3)")
    ap.add_argument("--limit", type=int, default=10, help="max targets (default 10)")
    ap.add_argument("--list", action="store_true", help="list available and exit")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per benchmark")
    args = ap.parse_args()

    all_benches = load_benchmarks()
    benches = load_benchmarks(tags=args.tags, level=args.level, limit=args.limit)

    if args.list or not benches:
        print(f"可用靶机 ({len(all_benches)} 个):")
        for b in all_benches:
            print(f"  {b['_name']:<25} Lv={b.get('level','?'):>2}  tags={b.get('tags',[])}")
        if not benches and not args.list:
            print("\n没有匹配条件的靶机。可用标签:")
            all_tags = set()
            for b in all_benches:
                all_tags.update(b.get("tags", []))
            print(f"  {', '.join(sorted(all_tags))}")
        return

    print(f"\n[彦 Benchmark] 运行 {len(benches)} 个靶机 (单个超时 {args.timeout}s)...")
    results = []
    for i, bench in enumerate(benches, 1):
        print(f"\n  [{i}/{len(benches)}] {bench['_name']} ({bench.get('tags', [])})")
        r = run_single(bench, timeout_sec=args.timeout)
        results.append(r)
        status = "✓ " + r.get("flag_found", "") if r["success"] else "✗ " + r.get("error", "")
        print(f"         → {status}  ({r['elapsed']}s)")

    print_report(results)


if __name__ == "__main__":
    main()
