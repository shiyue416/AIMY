import subprocess, re, os, time
from pathlib import Path

bench_dir = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")
targets = ["XBEN-{:03d}-24".format(i) for i in [3, 8, 12, 18, 25, 35, 48, 62, 78, 95]]
results = {}

for t in targets:
    cwd = bench_dir / t
    if not cwd.exists():
        results[t] = "MISSING"
        continue

    # Check if docker image already exists
    image_check = subprocess.run(
        f'docker images --format "{{{{.Repository}}}}" | grep -i "{t.lower()}"',
        shell=True, capture_output=True, text=True, timeout=10)

    has_image = image_check.returncode == 0 and bool(image_check.stdout.strip())

    if has_image:
        r = subprocess.run("docker compose up -d 2>&1", shell=True,
                          capture_output=True, text=True, timeout=120, cwd=str(cwd))
        if r.returncode == 0:
            time.sleep(3)
            port_check = subprocess.run(
                "docker compose port app 80 2>&1", shell=True,
                capture_output=True, text=True, timeout=10, cwd=str(cwd))
            m = re.search(r":(\d+)", port_check.stdout)
            if m:
                results[t] = "OK (port {})".format(m.group(1))
            else:
                results[t] = "NO_PORT"
            subprocess.run("docker compose down 2>&1", shell=True, timeout=30, cwd=str(cwd))
        else:
            results[t] = "START_FAIL"
    else:
        sys.stdout.write("Building {}... ".format(t))
        sys.stdout.flush()
        r = subprocess.run(
            'docker compose build --build-arg FLAG=test123 --build-arg flag=test123 2>&1',
            shell=True, capture_output=True, text=True, timeout=300, cwd=str(cwd))
        if r.returncode == 0:
            results[t] = "BUILD_OK"
        else:
            out = r.stdout + r.stderr
            if "no matching distribution" in out.lower():
                results[t] = "PIP_NODIST"
            elif "could not find a version" in out.lower():
                results[t] = "PIP_VERSION"
            elif "no such file" in out.lower():
                results[t] = "MISSING_FILE"
            elif "error" in out.lower()[:500]:
                results[t] = "BUILD_ERR"
            else:
                results[t] = "BUILD_FAIL"

print()
for t, r in results.items():
    print("{}: {}".format(t, r))

ok = sum(1 for v in results.values() if v.startswith("OK") or v == "BUILD_OK")
fail = len(results) - ok
print("\n{}/{} OK, {} fail".format(ok, len(results), fail))
