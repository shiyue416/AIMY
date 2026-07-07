"""Security tool handlers — wire AIMY tools to claude-bug-bounty scripts.

Each handler takes (args: dict) -> str and is registered in ToolRunner.
"""

from __future__ import annotations

import os
import subprocess
import json
import time
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────
BB_TOOLS = "C:/Users/PC/tools/claude-bug-bounty/tools"
BB_BASE  = "C:/Users/PC/tools/claude-bug-bounty"
BB_RECON = f"{BB_BASE}/recon"
BB_FINDINGS = f"{BB_BASE}/findings"

# Ensure directories exist
os.makedirs(BB_RECON, exist_ok=True)
os.makedirs(BB_FINDINGS, exist_ok=True)


def _run_script(script_name: str, args_str: str = "", timeout: int = 600,
                cwd: str = BB_BASE, env: dict | None = None) -> str:
    """Run a shell script and return stdout+stderr."""
    script_path = os.path.join(BB_TOOLS, script_name)
    if not os.path.isfile(script_path):
        return f"ERROR: Script not found: {script_path}"

    child_env = os.environ.copy()
    if env:
        child_env.update(env)

    cmd = f'bash "{script_path}" {args_str}'
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=timeout, cwd=cwd, env=child_env)
        out = r.stdout.strip() or "(no output)"
        if r.stderr:
            stderr = r.stderr.strip()
            # Filter out common non-error stderr
            if any(kw in stderr.lower() for kw in ("error", "fail", "fatal", "traceback")):
                out += f"\n[STDERR]\n{stderr[:2000]}"
        if r.returncode != 0:
            out += f"\n[EXIT: {r.returncode}]"
        return out
    except subprocess.TimeoutExpired:
        return f"ERROR: {script_name} timed out after {timeout}s"
    except Exception as e:
        return f"ERROR: {e}"


# ── Recon tools ───────────────────────────────────────────────────

def run_recon(args: dict) -> str:
    """Full subdomain enumeration + live host discovery."""
    domain = args.get("domain", args.get("target", ""))
    quick = args.get("quick", False)
    scope_lock = args.get("scope_lock", False)

    if not domain:
        return "ERROR: domain is required for recon"

    flags = ""
    if quick:
        flags += "--quick "
    if scope_lock:
        flags += "--scope-lock "

    recon_dir = f"{BB_RECON}/{domain}"
    os.makedirs(recon_dir, exist_ok=True)

    return _run_script("recon_engine.sh", f'"{domain}" {flags}', timeout=1800)


def run_vuln_scan(args: dict) -> str:
    """Run vulnerability scanner on recon results."""
    domain = args.get("domain", args.get("target", ""))
    quick = args.get("quick", False)
    full = args.get("full", False)

    if not domain:
        return "ERROR: domain is required for vuln_scan"

    recon_dir = f"{BB_RECON}/{domain}"
    if not os.path.isdir(recon_dir):
        return f"ERROR: No recon data found for {domain}. Run run_recon first."

    flags = ""
    if quick:
        flags += "--quick "
    if full:
        flags += "--full "

    return _run_script("vuln_scanner.sh", f'"{recon_dir}" {flags}', timeout=1800)


def run_js_analysis(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    recon_dir = f"{BB_RECON}/{domain}"
    js_dir = f"{recon_dir}/js"
    if os.path.isdir(js_dir):
        js_files = list(Path(js_dir).glob("*.js"))
        return f"JS analysis: {len(js_files)} files in {js_dir}. Key endpoints/secrets would be extracted here."
    return f"No JS files directory found at {js_dir}. Run recon first."


def run_secret_hunt(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    return _run_script("secrets_hunter.sh", f'"{domain}"', timeout=600)


def run_param_discovery(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    cookies = args.get("cookies", "")
    if cookies:
        return _run_script("param_discovery.sh", f'"{domain}" --cookies "{cookies}"', timeout=600)
    return _run_script("param_discovery.sh", f'"{domain}"', timeout=600)


def run_api_fuzz(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    return f"API fuzzing on {domain}: Use terminal to run targeted IDOR/auth bypass tests on API endpoints found in recon."


def run_cors_check(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    return f"CORS check on {domain}: Use terminal with curl -H 'Origin: null' to test CORS on live hosts."


def run_cms_exploit(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    return _run_script("cve_scan.sh", f'"{domain}" --cms', timeout=600)


def run_rce_scan(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    return _run_script("cve_scan.sh", f'"{domain}" --rce', timeout=600)


def run_sqlmap_targeted(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    return f"SQLMap targeted on {domain}: Parameterized URLs from recon would be tested with sqlmap --batch."


def run_sqlmap_on_file(args: dict) -> str:
    req_file = args.get("request_file", "")
    if not req_file or not os.path.isfile(req_file):
        return f"ERROR: request_file not found: {req_file}"
    domain = args.get("domain", args.get("target", ""))
    level = args.get("level", 5)
    risk = args.get("risk", 3)
    return f"SQLMap on {req_file}: sqlmap -r {req_file} --level={level} --risk={risk} --batch"


def run_jwt_audit(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    if not domain:
        return "ERROR: domain required"
    return f"JWT audit on {domain}: Use terminal with jwt_tool or hashcat to test JWT tokens found in recon."


def run_bypass_403(args: dict) -> str:
    url = args.get("url", "")
    if not url:
        return "ERROR: url required"
    return _run_script("bypass_403.sh", f'"{url}"', timeout=120)


def run_waf_analysis(args: dict) -> str:
    url = args.get("url", "")
    if not url:
        return "ERROR: url required"
    return f"WAF analysis on {url}: Use wafw00f for detection, then test encoding bypasses."


def run_asn_discovery(args: dict) -> str:
    domain = args.get("domain", args.get("target", ""))
    org = args.get("org", "")
    if not domain:
        return "ERROR: domain required"
    if org:
        return _run_script("asn_discovery.sh", f'--domain "{domain}" --org "{org}"', timeout=300)
    return _run_script("asn_discovery.sh", f'--domain "{domain}"', timeout=300)


def run_favicon_hunt(args: dict) -> str:
    url = args.get("url", "")
    if not url:
        return "ERROR: url required"
    return _run_script("favicon_hunt.sh", f'--url "{url}"', timeout=120)


def run_js_sourcemap(args: dict) -> str:
    recon_dir = args.get("recon_dir", "")
    if not recon_dir:
        return "ERROR: recon_dir required"
    return _run_script("js_sourcemap.sh", f'--recon-dir "{recon_dir}"', timeout=300)


# ── Handler registry ──────────────────────────────────────────────

SECURITY_TOOL_HANDLERS = {
    "run_recon":             run_recon,
    "run_vuln_scan":         run_vuln_scan,
    "run_js_analysis":       run_js_analysis,
    "run_secret_hunt":       run_secret_hunt,
    "run_param_discovery":   run_param_discovery,
    "run_api_fuzz":          run_api_fuzz,
    "run_cors_check":        run_cors_check,
    "run_cms_exploit":       run_cms_exploit,
    "run_rce_scan":          run_rce_scan,
    "run_sqlmap_targeted":   run_sqlmap_targeted,
    "run_sqlmap_on_file":    run_sqlmap_on_file,
    "run_jwt_audit":         run_jwt_audit,
    "run_bypass_403":        run_bypass_403,
    "run_waf_analysis":      run_waf_analysis,
    "run_asn_discovery":     run_asn_discovery,
    "run_favicon_hunt":      run_favicon_hunt,
    "run_js_sourcemap":      run_js_sourcemap,
}


def register_all(runner) -> None:
    """Register all security tool handlers on a ToolRunner."""
    for name, handler in SECURITY_TOOL_HANDLERS.items():
        runner._handlers[name] = handler
