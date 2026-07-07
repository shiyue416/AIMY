#!/bin/bash
# AIMY 工具链一键安装
# 运行: bash ~/.claude/tools/setup-tools.sh

echo "=== 安装缺失 Go 工具 ==="
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

echo "=== 安装缺失 Python 工具 ==="
pip install arjun sqlmap dirsearch dnsgen

echo "=== 验证 ==="
for tool in subfinder amass assetfinder httpx dnsx naabu nuclei katana gau waybackurls hakrawler ffuf gf anew interactsh-client dalfox alterx; do
  path=$(which "$tool" 2>/dev/null)
  if [ -n "$path" ]; then echo "✅ $tool"; else echo "❌ $tool"; fi
done

for tool in arjun sqlmap; do
  path=$(which "$tool" 2>/dev/null)
  if [ -n "$path" ]; then echo "✅ $tool"; else echo "❌ $tool"; fi
done

echo "=== 安装 gf 模式 ==="
if [ -d ~/.gf ]; then
  echo "gf patterns already exist"
else
  git clone https://github.com/tomnomnom/gf ~/.gf 2>/dev/null || \
  git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf 2>/dev/null
fi

echo "=== 完成 ==="
