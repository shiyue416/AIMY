#!/bin/bash
# ============================================================================
# Kali Benchmark Auto-Setup & Runner
# 用法: bash kali_setup.sh
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
BENCH_SRC="/mnt/hgfs/benchmarks"
AIMY_SRC="/mnt/hgfs/aimy-tools"
YAN_SRC="/mnt/hgfs/yan"
WORK_DIR="$HOME/xbow-benchmarks"
AIMY_DIR="$HOME/aimy-tools"
RESULTS="$HOME/.aimy/kali_bench_results.jsonl"

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  Kali XBOW Benchmark Setup & Runner${NC}"
echo -e "${CYAN}================================================${NC}"

# ---- Step 1: Mount shared folders ----
echo -e "\n${CYAN}[1/5] Mounting shared folders...${NC}"
sudo mkdir -p /mnt/hgfs/benchmarks /mnt/hgfs/aimy-tools /mnt/hgfs/yan 2>/dev/null || true
sudo mount -t fuse.vmhgfs-fuse .host:/benchmarks /mnt/hgfs/benchmarks -o allow_other 2>/dev/null || \
  sudo vmhgfs-fuse .host:/benchmarks /mnt/hgfs/benchmarks -o allow_other 2>/dev/null || \
  sudo mount -t vmhgfs .host:/benchmarks /mnt/hgfs/benchmarks 2>/dev/null || true

sudo mount -t fuse.vmhgfs-fuse .host:/aimy-tools /mnt/hgfs/aimy-tools -o allow_other 2>/dev/null || \
  sudo vmhgfs-fuse .host:/aimy-tools /mnt/hgfs/aimy-tools -o allow_other 2>/dev/null || true

sudo mount -t fuse.vmhgfs-fuse .host:/yan /mnt/hgfs/yan -o allow_other 2>/dev/null || \
  sudo vmhgfs-fuse .host:/yan /mnt/hgfs/yan -o allow_other 2>/dev/null || true

if ls /mnt/hgfs/benchmarks/XBEN-001-24 2>/dev/null; then
    echo -e "${GREEN}  Shared folders mounted OK${NC}"
else
    echo -e "${RED}  Shared folders mount FAILED. Trying copy fallback...${NC}"
fi

# ---- Step 2: Install Docker ----
echo -e "\n${CYAN}[2/5] Checking Docker...${NC}"
if ! command -v docker &>/dev/null; then
    echo "  Installing Docker..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker.io docker-compose-v2 2>&1 | tail -1
    sudo systemctl start docker
    sudo usermod -aG docker kali
    echo -e "${GREEN}  Docker installed${NC}"
else
    echo -e "${GREEN}  Docker: $(docker --version)${NC}"
fi

# ---- Step 3: Copy benchmarks to local disk (Docker + HGFS don't mix well) ----
echo -e "\n${CYAN}[3/5] Copying benchmarks to local disk...${NC}"
if [ -d "$WORK_DIR" ] && [ "$(ls -1 $WORK_DIR/benchmarks/ 2>/dev/null | wc -l)" -gt 50 ]; then
    echo "  Already copied, skipping"
else
    echo "  Copying ~150MB from shared folder..."
    rsync -a --info=progress2 "$BENCH_SRC/" "$WORK_DIR/" 2>/dev/null || \
      cp -r "$BENCH_SRC" "$WORK_DIR" 2>/dev/null || {
        echo -e "${RED}  Copy failed. Trying tar pipe...${NC}"
        (cd "$BENCH_SRC" && tar cf - .) | (cd "$WORK_DIR" && tar xf -)
    }
    echo -e "${GREEN}  Benchmarks copied to $WORK_DIR${NC}"
fi
echo "  Total benchmarks: $(ls -d $WORK_DIR/benchmarks/XBEN-* 2>/dev/null | wc -l)"

# ---- Step 4: Copy AIMY tools ----
echo -e "\n${CYAN}[4/5] Setting up AIMY tools...${NC}"
if [ ! -d "$AIMY_DIR" ]; then
    rsync -a "$AIMY_SRC/" "$AIMY_DIR/" 2>/dev/null || cp -r "$AIMY_SRC" "$AIMY_DIR"
fi
pip install -q requests rich click beautifulsoup4 2>/dev/null || true
echo -e "${GREEN}  AIMY tools ready at $AIMY_DIR${NC}"

# ---- Step 5: Run benchmarks ----
echo -e "\n${CYAN}[5/5] Running benchmarks...${NC}"
echo -e "  Results file: $RESULTS"
echo -e "  Press Ctrl+C to stop at any time (progress saved)\n"

mkdir -p "$(dirname "$RESULTS")"

python3 - "$WORK_DIR" "$AIMY_DIR" "$RESULTS" << 'PYEOF'
import json, os, sys, re, time, subprocess, socket
from pathlib import Path
from datetime import datetime

BENCH_DIR = Path(sys.argv[1]) / "benchmarks"
AIMY_MAIN = Path(sys.argv[2]) / "main.py"
RESULTS_FILE = Path(sys.argv[3])
FLAG_RE = re.compile(r'flag\{[^}]+\}|FLAG\{[^}]+\}', re.IGNORECASE)
TIMEOUT = 600  # 10 min per benchmark

def load_done():
    if not RESULTS_FILE.exists(): return set()
    done = set()
    with open(RESULTS_FILE) as f:
        for line in f:
            try:
                r = json.loads(line.strip())
                if r.get("flag") or r.get("status") in ("build_fail","start_fail"):
                    done.add(r["name"])
            except: pass
    return done

def run(cmd, timeout=120, cwd=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=str(cwd) if cwd else None)
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return str(e), -1

def find_flag(text):
    m = FLAG_RE.search(text) if text else None
    return m.group(0) if m else None

def get_port(name):
    short = name.lower().replace("-","_").replace("_24","")[:20]
    out, _ = run(f"docker ps --filter name={short} --format {{{{.Ports}}}}", timeout=5)
    m = re.search(r'(\d+)->\d+/tcp', out)
    return int(m.group(1)) if m else None

def run_one(name, config):
    tags = config.get("tags",[]); level = config.get("level","?")
    desc = config.get("description","")[:100]

    result = {"name":name,"tags":tags,"level":level,"flag":None,"status":"pending","ts":datetime.now().isoformat()}
    cwd = BENCH_DIR / name

    print(f"\n{'='*55}")
    print(f"[{name}] L{level} | {','.join(tags)}")
    print(f"[{name}] {desc}")

    # Build
    out, code = run('docker compose build --build-arg FLAG="XBOW_KALI_2026" --build-arg flag="XBOW_KALI_2026"', timeout=300, cwd=cwd)
    if code != 0:
        result["status"]="build_fail"; result["error"]=out[-300:]
        print(f"  BUILD FAIL"); return result
    print(f"  Build OK")

    # Start
    out, code = run("docker compose up -d --wait", timeout=120, cwd=cwd)
    if code != 0:
        out, code = run("docker compose up -d", timeout=60, cwd=cwd)
    if code != 0:
        result["status"]="start_fail"; result["error"]=out[-300:]
        print(f"  START FAIL"); return result

    # Get port
    time.sleep(3)
    port = None
    for _ in range(15):
        port = get_port(name)
        if port: break
        time.sleep(2)
    if not port:
        result["status"]="no_port"; run("docker compose down -v", timeout=30, cwd=cwd)
        print(f"  NO PORT"); return result

    result["port"] = port
    url = f"http://localhost:{port}/"
    print(f"  URL: {url}")

    # Hunt: try tag-specific then generic
    flag = None
    for tag in tags:
        t = tag.lower().replace("-","_")
        cmds = {
            "idor": f'python3 "{AIMY_MAIN}" auth-bypass "{url}"',
            "sqli": f'python3 "{AIMY_MAIN}" sqlcheck "{url}"',
            "xss": f'python3 "{AIMY_MAIN}" xsscheck "{url}"',
            "ssrf": f'python3 "{AIMY_MAIN}" ssrf "{url}"',
            "cmdi": f'python3 "{AIMY_MAIN}" cmdi "{url}"',
            "ssti": f'python3 "{AIMY_MAIN}" ssti "{url}"',
            "lfi": f'python3 "{AIMY_MAIN}" lfi "{url}"',
            "jwt": f'python3 "{AIMY_MAIN}" jwt "{url}"',
            "deserialization": f'python3 "{AIMY_MAIN}" deser "{url}"',
            "graphql": f'python3 "{AIMY_MAIN}" graphql "{url}"',
        }
        cmd = cmds.get(t)
        if not cmd: continue
        out, code = run(cmd, timeout=120)
        flag = find_flag(out)
        if flag:
            print(f"  FOUND via {tag}: {flag}")
            break

    # fallback: curl flag endpoints
    if not flag:
        for ep in ["/flag","/api/flag","/admin","/.flag"]:
            out, _ = run(f'curl -s --max-time 3 "{url.rstrip("/")}{ep}"', timeout=5)
            flag = find_flag(out)
            if flag: break

    # Cleanup
    run("docker compose down -v", timeout=60, cwd=cwd)

    result["flag"] = flag
    result["status"] = "found" if flag else "not_found"

    tag_str = f"[{','.join(tags)}]" if tags else "[generic]"
    print(f"  RESULT: {'FOUND' if flag else 'NOT FOUND'} {tag_str}")
    return result

# ---- Main ----
done = load_done()
all_benches = sorted([d.name for d in BENCH_DIR.iterdir() if d.is_dir() and d.name.startswith("XBEN-")])
todo = [b for b in all_benches if b not in done]

print(f"\nTotal: {len(all_benches)} | Done: {len(done)} | Remaining: {len(todo)}")

if not todo:
    print("All done!")
    sys.exit(0)

found = 0; total = 0
start_time = time.time()

for i, name in enumerate(todo):
    elapsed = time.time() - start_time
    eta = (elapsed / (i+1) * (len(todo)-i-1) / 60) if i > 0 else 0
    print(f"\n{'#'*55}\n# [{i+1}/{len(todo)}] {name}  ETA: {eta:.1f}min\n{'#'*55}")

    # Read config
    config = {}
    for fn in ["benchmark.json","benchmark/benchmark-config.json"]:
        cf = BENCH_DIR / name / fn
        if cf.exists():
            config = json.load(open(cf)); break

    result = run_one(name, config)
    total += 1
    if result.get("flag"): found += 1

    # Save
    with open(RESULTS_FILE, "a") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(f"  Progress: {found}/{total} found")

elapsed = time.time() - start_time
print(f"\n{'='*55}")
print(f"  FINISHED: {found}/{total} flags found in {elapsed/60:.1f} min")
print(f"  Results: {RESULTS_FILE}")
print(f"{'='*55}")
PYEOF

echo -e "\n${GREEN}Done!${NC}"
