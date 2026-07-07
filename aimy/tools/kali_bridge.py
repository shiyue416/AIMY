#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KaliBridge — 彦 ↔ Kali 桥梁

用法:
    python -m aimy.tools.kali_bridge --run "nmap -sV target.com"
    python -m aimy.tools.kali_bridge --shell    # 交互式shell
    python -m aimy.tools.kali_bridge --check    # 测试连接

前置条件:
    1. Kali VM 已开机
    2. Kali 已装 ssh: sudo apt install openssh-server -y
    3. Windows 已配 SSH: ssh kali@<IP>
"""

import argparse
import os
import subprocess
import sys

# ── Kali SSH 配置 ─────────────────────────────────
KALI_HOST = "kali"         # ~/.ssh/config 里的 Host 名
KALI_USER = "kali"
KALI_IP = "192.168.137."   # VMnet8 NAT 网段, 需要补全最后一位


def check():
    """测试 Kali 连通性"""
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=5", KALI_HOST, "whoami"],
                       capture_output=True, text=True, timeout=10)
    if r.returncode == 0:
        print(f"[+] Kali 连接成功: {r.stdout.strip()}")
        return True
    else:
        print(f"[-] Kali 连接失败")
        print(f"    请确认:")
        print(f"    1. Kali VM 已开机")
        print(f"    2. Kali 网络模式: NAT (VMnet8)")
        print(f"    3. Kali IP: 在 Kali 里运行 ip addr")
        print(f"    4. Windows 端: ssh kali@{KALI_IP} 测试")
        return False


def run(cmd: str, capture: bool = True) -> subprocess.CompletedProcess:
    """在 Kali 上执行命令"""
    full_cmd = ["ssh", KALI_HOST] + cmd.split()
    r = subprocess.run(full_cmd, capture_output=True, text=True, timeout=300)
    return r


def shell():
    """交互式 Kali shell"""
    os.system(f"ssh {KALI_HOST}")


def nmap(target: str, args: str = "-sV"):
    """快捷调用 nmap"""
    print(f"[*] Kali nmap {args} {target}")
    r = run(f"nmap {args} {target}")
    print(r.stdout)
    if r.stderr:
        print(f"[!] {r.stderr[:200]}")


def hydra(target: str, service: str = "ssh", userlist: str = "", passlist: str = ""):
    """快捷调用 hydra"""
    print(f"[*] Kali hydra {service} {target}")
    r = run(f"hydra -L {userlist or '/usr/share/wordlists/rockyou.txt'} "
            f"-P {passlist or '/usr/share/wordlists/rockyou.txt'} "
            f"{service}://{target}")
    print(r.stdout[-500:])


def main():
    parser = argparse.ArgumentParser(description="彦 ↔ Kali 桥梁")
    parser.add_argument("--run", help="在Kali上执行命令")
    parser.add_argument("--shell", action="store_true", help="交互式shell")
    parser.add_argument("--check", action="store_true", help="测试连接")
    parser.add_argument("--nmap", help="nmap扫描目标")
    parser.add_argument("--hydra", help="hydra爆破目标")
    args = parser.parse_args()

    if args.check:
        check()
    elif args.shell:
        shell()
    elif args.nmap:
        nmap(args.nmap)
    elif args.hydra:
        hydra(args.hydra)
    elif args.run:
        r = run(args.run)
        print(r.stdout)
        if r.stderr:
            print(f"[!] {r.stderr[:300]}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
