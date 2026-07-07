"""
aimy doctor — 依赖自检与运行时诊断。

检查项:
    1. Python 版本 ≥ 3.8
    2. pip 包依赖 (requests, beautifulsoup4, PyJWT, cryptography)
    3. 外部 CLI 工具可用性 (subfinder, amass, nuclei, sqlmap, katana, httpx, dnsx, naabu, gau, waybackurls)
    4. Kali Linux 集成状态
    5. MCP 服务器连接状态 (Burp, Fiddler, Playwright)
    6. 关键文件完整性 (skills/, tools/, references/)
    7. 网络连通性 (可选)
    8. 速率限制与安全配置

用法:
    # 全面检查
    python tools/doctor.py

    # 仅检查外部工具
    python tools/doctor.py --tools-only

    # JSON 输出 (供 CI/自动化消费)
    python tools/doctor.py --json

    # 静默模式，仅返回状态码
    python tools/doctor.py --quiet

CLI 入口:
    python main.py doctor
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import platform
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


VERSION = "1.0.0"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── 检查项定义 ─────────────────────────────────────────────────────────────


@dataclass
class CheckResult:
    name: str
    status: str  # "ok", "warn", "error", "skipped"
    message: str
    detail: Optional[str] = None
    fix_hint: Optional[str] = None


CHECK_RESULTS: List[CheckResult] = []


def _ok(name: str, msg: str = "", detail: str = None) -> CheckResult:
    r = CheckResult(name=name, status="ok", message=msg, detail=detail)
    CHECK_RESULTS.append(r)
    return r


def _warn(name: str, msg: str, detail: str = None, fix: str = None) -> CheckResult:
    r = CheckResult(name=name, status="warn", message=msg, detail=detail, fix_hint=fix)
    CHECK_RESULTS.append(r)
    return r


def _error(name: str, msg: str, detail: str = None, fix: str = None) -> CheckResult:
    r = CheckResult(name=name, status="error", message=msg, detail=detail, fix_hint=fix)
    CHECK_RESULTS.append(r)
    return r


def _cmd_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# ── 各检查函数 ─────────────────────────────────────────────────────────────


def check_python_version() -> CheckResult:
    v = sys.version_info
    ver_str = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 8):
        return _ok("Python 版本", f"Python {ver_str} [OK]")
    else:
        return _error("Python 版本", f"Python {ver_str} (< 3.8 不兼容)",
                      f"当前: {sys.version}", "升级到 Python 3.8+ 或设置 uv/pyenv 虚拟环境")


def check_pip_packages() -> List[CheckResult]:
    results = []
    required = {
        "requests": "requests>=2.28.0",
        "bs4": "beautifulsoup4>=4.11.0",
        "jwt": "PyJWT>=2.6.0",
        "cryptography": "cryptography>=39.0.0",
    }
    for mod_name, pkg_spec in required.items():
        try:
            m = importlib.import_module(mod_name)
            ver = getattr(m, "__version__", "?")
            results.append(_ok(f"pip: {pkg_spec}", f"已安装 ({ver})"))
        except ImportError:
            results.append(_error(f"pip: {pkg_spec}", "未安装",
                                  fix=f"pip install {pkg_spec}"))
    return results


def _try_run(cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout[:200] or r.stderr[:200])
    except FileNotFoundError:
        return False, "命令未找到"
    except subprocess.TimeoutExpired:
        return False, f"超时 ({timeout}s)"
    except Exception as e:
        return False, str(e)[:200]


def check_external_tools() -> List[CheckResult]:
    """检查外部 CLI 工具"""
    results = []

    # 核心工具 (必须有)
    core_tools = {
        "httpx": ["httpx", "-version"],
        "nuclei": ["nuclei", "-version"],
        "subfinder": ["subfinder", "-version"],
    }
    # 重要工具 (强烈推荐)
    recommended_tools = {
        "amass": ["amass", "-version"],
        "sqlmap": ["sqlmap", "--version"],
        "katana": ["katana", "-version"],
        "dnsx": ["dnsx", "-version"],
        "naabu": ["naabu", "-version"],
    }
    # 辅助工具
    optional_tools = {
        "gau": ["gau", "--version"],
        "waybackurls": ["waybackurls", "--version"],
        "gitleaks": ["gitleaks", "version"],
        "gf": ["gf", "-h"],
        "anew": ["anew"],
    }

    for name, cmd in {**core_tools, **recommended_tools, **optional_tools}.items():
        if _cmd_exists(cmd[0]):
            ok, out = _try_run(cmd)
            if ok:
                ver_line = out.strip().split("\n")[0][:80]
                results.append(_ok(f"工具: {name}", ver_line))
            else:
                results.append(_warn(f"工具: {name}", "已安装但执行异常", out[:100]))
        else:
            if name in core_tools:
                results.append(_error(f"工具: {name}", "未安装 (核心)",
                                      fix=f"go install 或从 GitHub 安装 {name}"))
            elif name in recommended_tools:
                results.append(_warn(f"工具: {name}", "未安装 (推荐)",
                                     fix=f"go install 或从 GitHub 安装 {name}"))
            else:
                results.append(CheckResult(name=f"工具: {name}", status="skipped",
                                           message="未安装 (可选)", fix_hint=f"按需安装 {name}"))
    return results


def check_kali_integration() -> CheckResult:
    try:
        from aimy.tools.kali_executor import is_available as kali_avail
        if kali_avail():
            from aimy.tools.kali_executor import get_kali
            k = get_kali()
            return _ok("Kali 集成", f"可用 ({k.get('mode', '?')})")
        return _warn("Kali 集成", "不可用 (本地模式)", fix="配置 WSL Kali 或 SSH 远程 Kali 实例")
    except ImportError:
        return _warn("Kali 集成", "kali_executor 加载失败")


def check_mcp_servers() -> List[CheckResult]:
    """检查 MCP 服务器连接状态 (通过环境变量 + 探测)"""
    results = []

    # Burp Suite MCP
    burp_port = os.environ.get("BURP_MCP_PORT", "8080")
    burp_enabled = os.environ.get("BURP_MCP_ENABLED", "").lower() in ("1", "true", "yes")
    if burp_enabled:
        results.append(_ok("MCP: Burp Suite", f"端口 {burp_port}"))
    else:
        results.append(_warn("MCP: Burp Suite", "未启用",
                             fix="设置 BURP_MCP_ENABLED=1 并启动 BurpMCP-Ultra 扩展"))

    # Fiddler
    fiddler_port = os.environ.get("FIDDLER_MCP_PORT", "8888")
    fiddler_enabled = os.environ.get("FIDDLER_MCP_ENABLED", "").lower() in ("1", "true", "yes")
    if fiddler_enabled:
        results.append(_ok("MCP: Fiddler", f"端口 {fiddler_port}"))
    else:
        results.append(CheckResult(name="MCP: Fiddler", status="skipped",
                                   message="未启用 (仅 Burp+Playwright 双引擎默认)", fix_hint="设置 FIDDLER_MCP_ENABLED=1"))

    # Playwright
    pw_enabled = os.environ.get("PLAYWRIGHT_MCP_ENABLED", "").lower() in ("1", "true", "yes")
    if pw_enabled:
        results.append(_ok("MCP: Playwright", "已启用"))
    else:
        results.append(CheckResult(name="MCP: Playwright", status="skipped",
                                   message="未启用 (按需)", fix_hint="设置 PLAYWRIGHT_MCP_ENABLED=1"))

    return results


def check_file_integrity() -> List[CheckResult]:
    results = []
    required_dirs = {
        "skills/": os.path.join(PROJECT_ROOT, "skills"),
        "tools/": os.path.join(PROJECT_ROOT, "tools"),
        "references/": os.path.join(PROJECT_ROOT, "references"),
    }
    required_files = {
        "SKILL.md": os.path.join(PROJECT_ROOT, "SKILL.md"),
        "FUSION_ROUTES.md": os.path.join(PROJECT_ROOT, "FUSION_ROUTES.md"),
        "main.py": os.path.join(PROJECT_ROOT, "main.py"),
        "tools/__init__.py": os.path.join(PROJECT_ROOT, "tools", "__init__.py"),
        "tools/settings.py": os.path.join(PROJECT_ROOT, "tools", "settings.py"),
    }

    for label, path in required_dirs.items():
        if os.path.isdir(path):
            count = len(os.listdir(path))
            results.append(_ok(f"目录: {label}", f"{count} 个文件"))
        else:
            results.append(_error(f"目录: {label}", "缺失", fix=f"恢复 {label} 目录"))

    for label, path in required_files.items():
        if os.path.isfile(path):
            size_kb = os.path.getsize(path) / 1024
            results.append(_ok(f"文件: {label}", f"{size_kb:.1f} KB"))
        else:
            results.append(_error(f"文件: {label}", "缺失", fix=f"恢复 {label} 文件"))

    return results


def check_network() -> CheckResult:
    import requests
    try:
        r = requests.get("https://crt.sh", timeout=10)
        return _ok("网络连通性", f"crt.sh 可达 ({r.status_code})")
    except requests.RequestException as e:
        return _warn("网络连通性", f"crt.sh 不可达: {e}", fix="检查代理/VPN/防火墙设置")


def check_safety_config() -> List[CheckResult]:
    results = []
    rate_limit = os.environ.get("AIMY_RATE_LIMIT", "1")
    max_day = os.environ.get("AIMY_MAX_DAILY", "500")
    max_concurrency = os.environ.get("AIMY_MAX_CONCURRENCY", "5")

    try:
        rl = float(rate_limit)
        if rl <= 1:
            results.append(_ok("速率限制", f"{rl} req/s (安全)"))
        else:
            results.append(_warn("速率限制", f"{rl} req/s (偏高)", fix="建议设为 ≤1 req/s"))
    except ValueError:
        results.append(_warn("速率限制", f"无效值: {rate_limit}"))

    try:
        md = int(max_day)
        if md <= 500:
            results.append(_ok("日请求上限", f"{md}/天"))
        else:
            results.append(_warn("日请求上限", f"{md}/天 (偏高)"))
    except ValueError:
        results.append(_warn("日请求上限", f"无效值: {max_day}"))

    try:
        mc = int(max_concurrency)
        if mc <= 5:
            results.append(_ok("并发上限", str(mc)))
        else:
            results.append(_warn("并发上限", f"{mc} (偏高)", fix="建议设为 ≤5"))
    except ValueError:
        results.append(_warn("并发上限", f"无效值: {max_concurrency}"))

    mode = os.environ.get("AIMY_MODE", "rookie")
    results.append(_ok("运行模式", mode))

    scope_file = os.environ.get("AIMY_SCOPE_FILE", "")
    if scope_file:
        if os.path.isfile(scope_file):
            results.append(_ok("Scope 文件", scope_file))
        else:
            results.append(_warn("Scope 文件", f"不存在: {scope_file}"))
    else:
        results.append(CheckResult(name="Scope 文件", status="skipped",
                                   message="未设置 (每次会要求确认)"))

    return results


# ── 汇总 ───────────────────────────────────────────────────────────────────


def run_all_checks(tools_only: bool = False, skip_network: bool = True) -> Dict[str, Any]:
    global CHECK_RESULTS
    CHECK_RESULTS = []

    check_python_version()

    if not tools_only:
        check_pip_packages()

    check_external_tools()

    if not tools_only:
        check_kali_integration()
        check_mcp_servers()
        check_file_integrity()
        check_safety_config()
        if not skip_network:
            check_network()

    ok_count = sum(1 for r in CHECK_RESULTS if r.status == "ok")
    warn_count = sum(1 for r in CHECK_RESULTS if r.status == "warn")
    err_count = sum(1 for r in CHECK_RESULTS if r.status == "error")
    skip_count = sum(1 for r in CHECK_RESULTS if r.status == "skipped")

    return {
        "version": VERSION,
        "platform": platform.platform(),
        "python": sys.version,
        "project_root": PROJECT_ROOT,
        "summary": {"ok": ok_count, "warn": warn_count, "error": err_count, "skipped": skip_count},
        "healthy": err_count == 0,
        "checks": [
            {"name": r.name, "status": r.status, "message": r.message,
             "detail": r.detail, "fix_hint": r.fix_hint}
            for r in CHECK_RESULTS
        ],
    }


def format_report(report: Dict[str, Any], json_output: bool = False, quiet: bool = False) -> str:
    if json_output:
        return json.dumps(report, ensure_ascii=False, indent=2)

    if quiet:
        return "" if report["healthy"] else "ERROR: " + ", ".join(
            c["name"] for c in report["checks"] if c["status"] == "error")

    lines = []
    lines.append("=" * 60)
    lines.append("  AIMY Doctor v{} - System Check".format(VERSION))
    lines.append("  {}  |  Python {}".format(report["platform"], report["python"]))
    lines.append("  项目: {}".format(report["project_root"]))
    lines.append("=" * 60)

    # 按状态分组显示
    emoji = {"ok": "[OK]", "warn": "[WARN]", "error": "[ERR]", "skipped": "[SKIP]"}

    for r in report["checks"]:
        icon = emoji.get(r["status"], "?")
        lines.append(f"  {icon} {r['name']}: {r['message']}")
        if r.get("fix_hint"):
            lines.append(f"    -> fix: {r['fix_hint']}")

    lines.append("=" * 60)
    s = report["summary"]
    lines.append(f"  结果: {s['ok']} OK  {s['warn']} WARN  {s['error']} ERROR  {s['skipped']} SKIP")

    if report["healthy"]:
        lines.append("  Status: [PASS] all critical checks passed")
    else:
        lines.append(f"  Status: [FAIL] {s['error']} errors need fixing")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AIMY Doctor — 依赖自检工具")
    parser.add_argument("--tools-only", action="store_true", help="仅检查外部工具")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--quiet", action="store_true", help="静默模式，仅返回状态码")
    parser.add_argument("--network", action="store_true", help="包含网络连通性检查")
    args = parser.parse_args()

    report = run_all_checks(tools_only=args.tools_only, skip_network=not args.network)
    output = format_report(report, json_output=args.json, quiet=args.quiet)

    if not args.quiet:
        print(output)

    sys.exit(0 if report["healthy"] else 1)


if __name__ == "__main__":
    main()
