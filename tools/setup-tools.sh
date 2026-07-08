#!/bin/bash
# AIMY 完整工具链一键安装
# 用法: bash setup-tools.sh
# 前置: Go 1.21+, Python 3.10+, Git

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           AIMY 工具链安装                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Go 工具 (21个) ──
echo "=== Go 工具链安装 (21个) ==="

GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/owasp-amass/amass/v4/...@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "github.com/tomnomnom/anew@latest"
  "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/003random/getJS@latest"
  "github.com/trufflesecurity/trufflehog/v3@latest"
  "github.com/projectdiscovery/uncover/cmd/uncover@latest"
)

for pkg in "${GO_TOOLS[@]}"; do
  name=$(basename "$pkg" | cut -d@ -f1)
  if which "$name" >/dev/null 2>&1; then
    echo "  SKIP  go: $name (已安装)"
  else
    echo "  INST  go: $name ..."
    go install -v "$pkg" 2>&1 | tail -1 || echo "    FAIL  $name — 手动: go install $pkg"
  fi
done

# ── Python 工具 ──
echo ""
echo "=== Python 工具 ==="
PY_TOOLS=(arjun sqlmap dirsearch dnsgen bbot)
for pkg in "${PY_TOOLS[@]}"; do
  if pip show "$pkg" >/dev/null 2>&1; then
    echo "  SKIP  pip: $pkg"
  else
    echo "  INST  pip: $pkg"
    pip install -q "$pkg" 2>&1 | tail -1
  fi
done

# ── enscan ──
echo ""
echo "=== enscan (企业侦察) ==="
ENSCAN_DIR="$HOME/go/bin"
ENSCAN_BIN="$ENSCAN_DIR/enscan"
if [ -f "$ENSCAN_BIN" ] || [ -f "$ENSCAN_BIN.exe" ]; then
  echo "  SKIP  enscan (已安装)"
else
  echo "  INFO  手动下载: https://github.com/wgpsec/ENScan_GO/releases"
  echo "  INFO  下载后解压 enscan + config.yaml → $ENSCAN_DIR/"
fi

# ── OneForAll ──
echo ""
echo "=== OneForAll (全量子域名) ==="
OFA_DIR="$HOME/tools/OneForAll"
if [ -f "$OFA_DIR/oneforall.py" ]; then
  echo "  SKIP  OneForAll (已安装)"
else
  echo "  INST  git clone OneForAll ..."
  git clone -q https://github.com/shmilylty/OneForAll.git "$OFA_DIR" 2>/dev/null || \
    echo "  WARN  clone 失败，手动: git clone https://github.com/shmilylty/OneForAll.git $OFA_DIR"
  if [ -f "$OFA_DIR/requirements.txt" ]; then
    pip install -q -r "$OFA_DIR/requirements.txt" 2>&1 | tail -1 || true
  fi
fi

# ── Shell 管线 ──
echo ""
echo "=== Shell 管线部署 ==="
CLAUDE_TOOLS="$HOME/.claude/tools"
mkdir -p "$CLAUDE_TOOLS"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for script in "$SCRIPT_DIR"/*.sh; do
  name=$(basename "$script")
  if [ "$name" = "setup-tools.sh" ]; then continue; fi
  cp "$script" "$CLAUDE_TOOLS/$name" 2>/dev/null && chmod +x "$CLAUDE_TOOLS/$name"
  echo "  OK  $name → $CLAUDE_TOOLS/"
done

# ── gf 模式 ──
echo ""
echo "=== gf 模式 (URL 分桶) ==="
GF_DIR="$HOME/.gf"
if [ -d "$GF_DIR" ] && [ "$(ls "$GF_DIR"/*.json 2>/dev/null | wc -l)" -gt 3 ]; then
  echo "  SKIP  gf 模式 (已安装)"
else
  git clone -q https://github.com/1ndianl33t/Gf-Patterns "$GF_DIR" 2>/dev/null || \
  git clone -q https://github.com/tomnomnom/gf "$GF_DIR" 2>/dev/null
  echo "  OK  gf 模式已安装"
fi

# ── 验证 ──
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           验证结果                                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

FAILED=0
for tool in subfinder amass assetfinder httpx dnsx naabu nuclei katana gau \
            waybackurls hakrawler ffuf interactsh-client dalfox alterx anew \
            asnmap gf getJS trufflehog uncover; do
  if which "$tool" >/dev/null 2>&1; then
    echo "  ✅  $tool"
  else
    echo "  ❌  $tool — go install 手动安装"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "Python:"
for tool in arjun sqlmap; do
  if which "$tool" >/dev/null 2>&1; then
    echo "  ✅  $tool"
  else
    echo "  ❌  $tool"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "企业工具:"
[ -f "$ENSCAN_BIN" ] || [ -f "$ENSCAN_BIN.exe" ] && echo "  ✅  enscan" || { echo "  ⚠️  enscan — 手动下载"; }
[ -f "$OFA_DIR/oneforall.py" ] && echo "  ✅  OneForAll" || echo "  ⚠️  OneForAll — 安装失败"

echo ""
echo "Shell 管线:"
ls "$CLAUDE_TOOLS"/*.sh 2>/dev/null | while read s; do echo "  ✅  $(basename "$s")"; done

echo ""
if [ "$FAILED" -eq 0 ]; then
  echo "全部就绪，可以开始挖洞。"
else
  echo "$FAILED 个工具缺失，请按提示手动安装。"
fi
echo ""
