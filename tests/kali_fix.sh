#!/bin/bash
set -euo pipefail
echo "=== Kali Docker Fix + Benchmark Runner ==="

echo "[1/6] Fix Docker config..."
sudo mkdir -p /etc/docker
echo '{"registry-mirrors":["https://docker.m.daocloud.io","https://dockerproxy.com","https://mirror.ccs.tencentyun.com"]}' | sudo tee /etc/docker/daemon.json > /dev/null

echo "[2/6] Start Docker..."
sudo systemctl reset-failed docker 2>/dev/null; sudo systemctl start docker; sleep 1
sudo docker --version
sudo docker pull hello-world 2>&1 | tail -1

echo "[3/6] Fix docker group..."
sudo usermod -aG docker kali 2>/dev/null
sudo chmod 666 /var/run/docker.sock 2>/dev/null

echo "[4/6] Create dirs..."
mkdir -p $HOME/.aimy

echo "[5/6] Download runner..."
wget -q "http://192.168.81.1:8888/%E5%BD%A6/kali_runner.sh" -O $HOME/kali_runner.sh

echo "[6/6] Run (ctrl+c to stop, can resume later)..."
bash $HOME/kali_runner.sh
