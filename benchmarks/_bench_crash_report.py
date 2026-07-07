"""Collect crash logs from all 104 benchmarks, categorize by error type."""
import subprocess, json, re, time
from pathlib import Path
from collections import Counter

BENCH = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")
targets = sorted(d.name for d in BENCH.glob("XBEN-*"))

error_types = Counter()
crashed = []
alive = []
start_fail = []

for i, t in enumerate(targets):
    cwd = BENCH / t
    print("[{:3d}/{}] {} ".format(i+1, len(targets), t), end="", flush=True)

    # docker compose up -d
    r = subprocess.run("docker compose up -d 2>&1", shell=True,
                      capture_output=True, text=True, timeout=90, cwd=str(cwd))
    if r.returncode != 0:
        start_fail.append(t)
        error_types["compose_start_fail"] += 1
        print("COMPOSE FAIL")
        subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))
        continue

    time.sleep(8)

    # Check if container is alive
    short = t.lower().replace("-", "_")[:20]
    ps = subprocess.run(
        f'docker ps -a --filter "name={short}" --format "{{{{.Status}}}}"',
        shell=True, capture_output=True, text=True, timeout=5)

    if "Up" in ps.stdout:
        alive.append(t)
        print("ALIVE")
        # Get port and URL
        port_check = subprocess.run(
            "docker compose port app 80 2>&1 || docker compose port web 80 2>&1 || docker compose port web 5000 2>&1",
            shell=True, capture_output=True, text=True, timeout=5, cwd=str(cwd))
        port_m = re.search(r':(\d+)', port_check.stdout)
        if port_m:
            print("   -> port {}".format(port_m.group(1)))
    elif "Exited" in ps.stdout:
        # Collect crash logs
        log = subprocess.run("docker compose logs --tail=15 2>&1", shell=True,
                            capture_output=True, text=True, timeout=10, cwd=str(cwd))
        logs_text = log.stdout + log.stderr

        # Classify
        if "soft_unicode" in logs_text or "markupsafe" in logs_text:
            error_types["markupsafe_jinja2_conflict"] += 1
            crash_type = "markupsafe/jinja2"
        elif "No module named" in logs_text:
            error_types["missing_module"] += 1
            m = re.search(r"No module named '(\w+)'", logs_text)
            crash_type = "no_module:{}".format(m.group(1) if m else "?")
        elif "ModuleNotFoundError" in logs_text:
            error_types["module_not_found"] += 1
            m = re.search(r"ModuleNotFoundError.*'(\w+)'", logs_text)
            crash_type = "ModuleNotFound:{}".format(m.group(1) if m else "?")
        elif "ImportError" in logs_text:
            error_types["import_error"] += 1
            crash_type = "ImportError"
        elif "syntax error" in logs_text.lower():
            error_types["python_syntax"] += 1
            crash_type = "syntax_error"
        elif "Can't connect" in logs_text or "Connection refused" in logs_text:
            error_types["db_connection"] += 1
            crash_type = "db_connection"
        elif "address already in use" in logs_text.lower():
            error_types["port_conflict"] += 1
            crash_type = "port_conflict"
        else:
            error_types["other"] += 1
            # Extract last error line
            last_err = ""
            for line in logs_text.split("\n"):
                if "error" in line.lower() or "traceback" in line.lower() or "exception" in line.lower():
                    last_err = line.strip()[-100:]
            crash_type = last_err[:80] if last_err else "unknown"

        crashed.append((t, crash_type))
        print("CRASH: {}".format(crash_type[:60]))

    else:
        error_types["no_status"] += 1
        print("NO STATUS")

    # Cleanup
    subprocess.run("docker compose down -v 2>&1", shell=True, timeout=30, cwd=str(cwd))

# Report
print("\n" + "=" * 60)
print("  Benchmark Crash Report")
print("=" * 60)
print("  Total:   {}".format(len(targets)))
print("  Alive:   {}".format(len(alive)))
print("  Crashed: {}".format(len(crashed)))
print("  Fail:    {}".format(len(start_fail)))

print("\n  Error breakdown:")
for err, cnt in error_types.most_common(15):
    bar = "#" * min(cnt, 40)
    print("  {:35s} {:3d} {}".format(err, cnt, bar))

print("\n  Alive targets:")
for t in alive:
    print("    {}".format(t))

# Save detailed report
report = {
    "alive": alive,
    "crashed": [{"name": t, "reason": r} for t, r in crashed],
    "start_fail": start_fail,
    "error_types": dict(error_types.most_common()),
}
with open(BENCH.parent / "crash_report.json", "w") as f:
    json.dump(report, f, indent=2)
print("\n  Full report: {}".format(BENCH.parent / "crash_report.json"))
