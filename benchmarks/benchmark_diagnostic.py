"""
XBOW Benchmark 批量诊断 — 找 75 个故障靶机的 root cause.

用法:
    python benchmark_diagnostic.py          # 全量诊断
    python benchmark_diagnostic.py --single XBEN-003-24  # 单靶机
    python benchmark_diagnostic.py --build-only          # 只尝试构建
    python benchmark_diagnostic.py --fix                 # 自动修复已知问题
"""

import json, os, sys, re, subprocess, argparse
from pathlib import Path
from collections import Counter
from datetime import datetime

BENCH_DIR = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")

# Known fixes
COMMON_MISSING_PACKAGES = ["cryptography", "bcrypt", "passlib", "python-multipart"]
PYTHON_MIRROR = "--trusted-host pypi.org --trusted-host files.pythonhosted.org --default-timeout=100"
HEALTHCHECK_TIMEOUT_PATCH = 'timeout: 1s\n      retries: 5\n      interval: 10s'


def read_config(name: str) -> dict:
    for fname in ["benchmark.json"]:
        path = BENCH_DIR / name / fname
        if path.exists():
            with open(path) as f:
                return json.load(f)
    return {}


def run_cmd(cmd: str, timeout: int = 120, cwd=None) -> tuple:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return (r.stdout + "\n" + r.stderr), r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return str(e), -1


def diagnose_build(name: str) -> dict:
    """Try to build and report specific failure."""
    cwd = BENCH_DIR / name
    result = {"name": name, "status": "unknown", "error_type": None, "error_detail": ""}

    # Find build files
    has_compose = (cwd / "docker-compose.yml").exists() or (cwd / "docker-compose.yaml").exists()
    has_dockerfile = (cwd / "Dockerfile").exists() or (cwd / "app" / "Dockerfile").exists()

    if not has_compose and not has_dockerfile:
        result["status"] = "no_build_file"
        result["error_type"] = "missing_files"
        return result

    if not has_compose:
        result["status"] = "no_compose"
        result["error_type"] = "missing_compose"
        return result

    out, code = run_cmd(
        f'docker compose build --build-arg FLAG="testflag123" '
        f'--build-arg flag="testflag123" 2>&1',
        timeout=300, cwd=str(cwd))

    if code == 0:
        result["status"] = "build_ok"
        return result

    # Classify error
    out_lower = out.lower()
    if "could not find a version that satisfies the requirement" in out_lower:
        result["error_type"] = "pip_version_mismatch"
    elif "no matching distribution found" in out_lower:
        result["error_type"] = "pip_no_distribution"
    elif "connection timed out" in out_lower or "failed to resolve" in out_lower:
        result["error_type"] = "network_timeout"
    elif "no such file or directory" in out_lower and "requirements" in out_lower:
        result["error_type"] = "missing_requirements"
    elif "syntax error" in out_lower or "invalid" in out_lower:
        result["error_type"] = "dockerfile_syntax"
    elif "returned a non-zero code" in out_lower:
        # Extract the actual pip error
        for line in out.split("\n"):
            if "error" in line.lower() and ("package" in line.lower() or "requirement" in line.lower()):
                result["error_type"] = "pip_error"
                result["error_detail"] = line.strip()[:200]
                break
        if not result["error_type"]:
            result["error_type"] = "build_nonzero"
    elif "no space left" in out_lower:
        result["error_type"] = "disk_full"
    elif "permission denied" in out_lower:
        result["error_type"] = "permission"
    else:
        result["error_type"] = "build_unknown"

    result["error_detail"] = result["error_detail"] or out[-500:]
    result["status"] = "build_fail"
    return result


def diagnose_port(name: str) -> dict:
    """Try to start and check port exposure."""
    cwd = BENCH_DIR / name
    result = {"name": name, "status": "unknown", "error_type": None}

    # Already built?
    out, code = run_cmd("docker compose up -d 2>&1", timeout=120, cwd=str(cwd))
    if code != 0:
        # Try without --wait for older docker compose
        out, code = run_cmd("docker compose up -d 2>&1", timeout=60, cwd=str(cwd))

    if code != 0:
        result["status"] = "start_fail"
        result["error_type"] = "compose_up_failed"
        result["error_detail"] = out[-300:]
        return result

    # Wait for port
    import time
    time.sleep(3)

    # Check docker ps
    short = name.lower().replace("-", "_").replace("_24", "")[:20]
    out, _ = run_cmd(f'docker ps --filter "name={short}" --format "{{{{.Ports}}}}"', timeout=5)
    ports = re.findall(r'(\d+)->(\d+)/tcp', out)

    if not ports:
        # Try docker compose port
        out, _ = run_cmd("docker compose port app 80 2>&1", timeout=5, cwd=str(cwd))
        m = re.search(r'(\d+)', out)
        if m:
            result["status"] = "port_ok"
            result["port"] = int(m.group(1))
        else:
            result["status"] = "no_port"
            result["error_type"] = "port_not_exposed"

            # Check docker-compose for port config
            compose_file = cwd / "docker-compose.yml"
            if compose_file.exists():
                content = compose_file.read_text()
                if "ports:" not in content:
                    result["error_type"] = "no_ports_section"
                elif "80:" not in content and "8080:" not in content:
                    result["error_type"] = "port_not_mapped"
    else:
        result["status"] = "port_ok"
        result["port"] = int(ports[0][0])

    # Cleanup
    run_cmd("docker compose down -v 2>&1", timeout=60, cwd=str(cwd))
    return result


def auto_fix_dockerfile(dockerfile_path: Path) -> list:
    """Apply known fixes to a Dockerfile. Returns list of fixes applied."""
    fixes = []
    if not dockerfile_path.exists():
        return fixes

    content = dockerfile_path.read_text()
    original = content

    # Fix 1: Add trusted-host and timeout to pip install
    if "pip install" in content and "--trusted-host" not in content:
        content = content.replace(
            "pip install",
            f"pip install {PYTHON_MIRROR}")
        fixes.append("trusted_host")

    # Fix 2: Ensure cryptography is in requirements if missing
    # (handled in requirements fix below)

    # Fix 3: Add --no-cache-dir to pip install if missing
    if "pip install" in content and "--no-cache-dir" not in content:
        content = content.replace(
            "pip install",
            "pip install --no-cache-dir")
        fixes.append("no_cache_dir")

    if content != original:
        dockerfile_path.write_text(content)

    return fixes


def auto_fix_requirements(req_path: Path) -> list:
    """Add missing packages and fix version issues."""
    fixes = []
    if not req_path.exists():
        return fixes

    content = req_path.read_text()
    original = content
    lines = content.strip().split("\n")

    # Ensure critical packages present
    for pkg in COMMON_MISSING_PACKAGES:
        if pkg not in content.lower():
            lines.append(pkg)
            fixes.append(f"added_{pkg}")

    if lines != original.strip().split("\n"):
        req_path.write_text("\n".join(lines) + "\n")

    return fixes


def auto_fix_compose(compose_path: Path) -> list:
    """Fix common docker-compose issues."""
    fixes = []
    if not compose_path.exists():
        return fixes

    content = compose_path.read_text()
    original = content

    # Fix: Ensure ports are correctly formatted (not just port number)
    # "ports:\n      - 80" → "ports:\n      - \"80:80\""
    # This is too fragile to auto-fix reliably, just flag it

    # Fix: Add healthcheck if missing (for port detection)
    if "healthcheck:" not in content.lower():
        # Too complex to auto-add reliably
        pass

    return fixes


def diagnose_all(build_only: bool = False, auto_fix: bool = False):
    """Run full diagnostic on all 104 benchmarks."""
    all_benches = sorted(d.name for d in BENCH_DIR.glob("XBEN-*"))
    if not all_benches:
        print("No benchmarks found in", BENCH_DIR)
        return

    print(f"Diagnosing {len(all_benches)} benchmarks...\n")

    results = []
    error_types = Counter()
    build_ok = 0
    port_ok = 0
    total = len(all_benches)

    for i, name in enumerate(all_benches):
        config = read_config(name)
        tags = config.get("tags", [])
        print(f"[{i+1:3d}/{total}] {name} [{','.join(tags[:3])}] ", end="", flush=True)

        # Build
        build_result = diagnose_build(name)
        results.append(build_result)

        if build_result["status"] == "build_ok":
            build_ok += 1
            print("BUILD OK", end="")

            if auto_fix:
                # Try auto-fix before build
                cwd = BENCH_DIR / name
                for df in list(cwd.glob("**/Dockerfile")) + list(cwd.glob("**/Dockerfile.*")):
                    fixed = auto_fix_dockerfile(df)
                    if fixed:
                        print(f" [fixed Dockerfile: {','.join(fixed)}]", end="")
                for req in cwd.glob("**/requirements*.txt"):
                    fixed = auto_fix_requirements(req)
                    if fixed:
                        print(f" [fixed requirements: {','.join(fixed)}]", end="")

            if not build_only:
                # Port check
                port_result = diagnose_port(name)
                results.append(port_result)
                if port_result["status"] == "port_ok":
                    port_ok += 1
                    print(f" | PORT OK ({port_result.get('port', '?')})", end="")
                else:
                    print(f" | {port_result['status']} ({port_result.get('error_type', '?')})", end="")
                    error_types[port_result.get("error_type", "unknown")] += 1
        else:
            print(f"{build_result['status']} ({build_result.get('error_type', '?')})", end="")
            error_types[build_result.get("error_type", "unknown")] += 1

        print()

    # Summary
    print(f"\n{'='*60}")
    print(f"  Diagnostic Summary")
    print(f"  {'='*60}")
    print(f"  Total:        {total}")
    print(f"  Build OK:     {build_ok} ({build_ok*100//total}%)")
    if not build_only:
        print(f"  Port OK:      {port_ok} ({port_ok*100//total}%)")
        print(f"  Ready to use: {port_ok}")

    if error_types:
        print(f"\n  Error breakdown:")
        for err_type, cnt in error_types.most_common():
            print(f"    {err_type:30s} {cnt:3d}")

    # Save results
    report = {
        "timestamp": datetime.now().isoformat(),
        "total": total,
        "build_ok": build_ok,
        "port_ok": port_ok if not build_only else None,
        "error_types": dict(error_types.most_common()),
        "results": [{k: v for k, v in r.items() if k != "error_detail"} for r in results]
    }

    report_path = BENCH_DIR.parent / "benchmark_diagnostic.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved to {report_path}")


def main():
    ap = argparse.ArgumentParser(description="XBOW Benchmark Diagnostic")
    ap.add_argument("--single", type=str, help="Diagnose single benchmark")
    ap.add_argument("--build-only", action="store_true")
    ap.add_argument("--fix", action="store_true", help="Auto-apply known fixes")
    args = ap.parse_args()

    if args.single:
        name = args.single
        config = read_config(name)
        print(f"Diagnosing {name}: {config.get('description', '')[:80]}")
        print(f"Tags: {config.get('tags', [])}")

        build = diagnose_build(name)
        print(f"\nBuild: {build['status']}")
        if build.get("error_type"):
            print(f"Error: {build['error_type']}")
            print(build.get("error_detail", "")[:500])

        if build["status"] == "build_ok" and not args.build_only:
            port = diagnose_port(name)
            print(f"\nPort: {port['status']}")
            if port.get("port"):
                print(f"Port: {port['port']}")

        if args.fix and build["status"] != "build_ok":
            cwd = BENCH_DIR / name
            for df in list(cwd.glob("**/Dockerfile")):
                fixes = auto_fix_dockerfile(df)
                if fixes:
                    print(f"\nFixed Dockerfile: {fixes}")
            for req in cwd.glob("**/requirements*.txt"):
                fixes = auto_fix_requirements(req)
                if fixes:
                    print(f"\nFixed requirements: {fixes}")
    else:
        diagnose_all(build_only=args.build_only, auto_fix=args.fix)


if __name__ == "__main__":
    main()
