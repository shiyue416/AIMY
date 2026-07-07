"""
QuickHunt — 信号驱动的快速漏洞探测。

10 分钟从 URL 到第一个高危发现。跳过全量侦察，
解析 URL 信号 → 选择检测器 → 发包验证 → 输出结果。

用法:
    python quickhunt.py https://target.com/page?id=123
    python quickhunt.py https://target.com/api/users/1
    python quickhunt.py https://target.com/login
"""

import re, sys, time
from typing import Optional, Dict, List
from urllib.parse import urlparse, parse_qs
import requests

from aimy.tools.settings import settings
from aimy.tools.log_utils import get_logger
from aimy.tools.http_client import build_url

logger = get_logger("quickhunt")

# ── Signal → Vulnerability Type ──────────────────────────────

PARAM_SIGNALS = {
    "id": ["idor", "sqli"],
    "user_id": ["idor", "sqli"],
    "uid": ["idor", "sqli"],
    "order_id": ["idor"],
    "order": ["idor"],
    "user": ["idor"],
    "account": ["idor"],
    "profile": ["idor"],
    "uuid": ["idor"],
    "guid": ["idor"],
    "token": ["jwt"],
    "access_token": ["jwt"],
    "auth": ["jwt", "auth_bypass"],
    "q": ["xss", "sqli"],
    "search": ["xss", "sqli"],
    "query": ["xss", "sqli"],
    "keyword": ["xss"],
    "s": ["xss", "sqli"],
    "file": ["lfi", "path_traversal"],
    "path": ["lfi", "path_traversal"],
    "page": ["lfi", "ssti"],
    "template": ["ssti"],
    "view": ["lfi", "ssti"],
    "name": ["ssti", "xss"],
    "url": ["ssrf"],
    "redirect": ["ssrf", "open_redirect"],
    "redirect_uri": ["ssrf", "open_redirect"],
    "callback": ["ssrf"],
    "webhook": ["ssrf"],
    "cmd": ["cmdi"],
    "exec": ["cmdi"],
    "command": ["cmdi"],
    "ip": ["cmdi"],
    "host": ["cmdi", "ssrf"],
    "email": ["xss", "email_header"],
    "message": ["xss", "ssti"],
    "comment": ["xss"],
    "username": ["sqli", "auth_bypass"],
    "password": ["auth_bypass"],
    "xml": ["xxe"],
    "data": ["deserialization"],
}

PATH_SIGNALS = {
    "/api/": ["api_auth", "idor"],
    "/graphql": ["graphql"],
    "/login": ["auth_bypass"],
    "/signin": ["auth_bypass"],
    "/auth": ["auth_bypass"],
    "/admin": ["auth_bypass", "idor"],
    "/upload": ["file_upload"],
    "/file": ["file_upload", "lfi"],
    "/download": ["lfi", "path_traversal"],
    "/reset": ["auth_bypass"],
    "/password": ["auth_bypass"],
}

# ── Priority (highest ROI first) ─────────────────────────────

VULN_PRIORITY = [
    "ssrf",        # P0: RCE gateway, highest bounty
    "cmdi",         # P0: RCE
    "ssti",         # P0: RCE
    "sqli",         # P0: Data breach
    "idor",         # P1: Data access
    "auth_bypass",  # P1: Privilege escalation
    "deserialization",  # P0: RCE
    "xxe",          # P1: File read/SSRF
    "lfi",          # P1: File read → RCE
    "path_traversal",  # P2: File read
    "jwt",          # P1: Token abuse
    "xss",          # P2: Client-side
    "graphql",      # P2: API abuse
    "open_redirect",  # P3: Low impact
    "file_upload",  # P1: RCE gateway
]


def analyze_url(url: str) -> Dict:
    """Parse a URL and extract vulnerability signals."""
    signals = {
        "vuln_types": set(),
        "params": [],
        "has_login_form": False,
        "has_api": False,
        "has_jwt": False,
        "has_graphql": False,
    }

    parsed = urlparse(url)
    path = parsed.path or "/"

    # Check path signals
    for sig_path, vulns in PATH_SIGNALS.items():
        if sig_path in path.lower():
            for v in vulns:
                signals["vuln_types"].add(v)

    if "/api/" in path.lower():
        signals["has_api"] = True

    # Check query params
    params = parse_qs(parsed.query)
    for param_name in params:
        signals["params"].append(param_name)
        param_lower = param_name.lower()
        for sig_param, vulns in PARAM_SIGNALS.items():
            if sig_param in param_lower:
                for v in vulns:
                    signals["vuln_types"].add(v)

    # Detect numeric params → likely IDOR/SQLi
    for param_name, values in params.items():
        for val in values:
            if val.isdigit() and len(val) < 10:
                signals["vuln_types"].add("idor")
                signals["vuln_types"].add("sqli")
                break

    # Detect JWT in URL
    if re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', url):
        signals["has_jwt"] = True
        signals["vuln_types"].add("jwt")

    return signals


def quick_fetch(url: str, sess: requests.Session, timeout: float = 5.0) -> dict:
    """Fetch page and extract additional signals from HTML/headers."""
    result = {"html": "", "headers": {}, "cookies": {}, "forms": [],
              "has_login": False, "has_jwt": False, "comments": []}

    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True)
        result["html"] = r.text
        result["headers"] = dict(r.headers)
        result["cookies"] = dict(r.cookies)
        result["status"] = r.status_code

        # Detect login form
        if re.search(r'(?i)(login|sign\s*in|password|username)', r.text[:2000]):
            result["has_login"] = True

        # Detect JWT in cookies/headers
        for k, v in {**dict(r.headers), **dict(r.cookies)}.items():
            if re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', str(v)):
                result["has_jwt"] = True

        # Extract HTML comments (potential credentials)
        result["comments"] = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
        for c in result["comments"]:
            if re.search(r'(?i)(test|password|credential|TODO.*account)', c):
                result["has_login"] = True

        # Extract forms
        result["forms"] = re.findall(
            r'<form[^>]*>(.*?)</form>', r.text, re.DOTALL | re.IGNORECASE)

    except Exception as e:
        logger.debug("quick_fetch: %s", e)

    return result


def discover_endpoints(url: str, html: str, forms: list) -> List[Dict]:
    """Parse HTML to find testable endpoints with params.

    Returns list of {url, method, params} sorted by priority.
    """
    base = url.rstrip("/")
    endpoints = []

    # 0. Always include root URL
    endpoints.append({
        "url": url, "method": "GET", "params": ["id"],
        "source": "root"
    })

    # 1. Extract form actions
    for form_html in forms:
        action_m = re.search(r'action=["\']([^"\']+)["\']', form_html, re.I)
        method_m = re.search(r'method=["\'](\w+)["\']', form_html, re.I)
        action = action_m.group(1) if action_m else ""
        method = (method_m.group(1) or "GET").upper()

        # Resolve relative URLs
        if action.startswith("http"):
            target_url = action
        elif action.startswith("/"):
            parsed = urlparse(url)
            target_url = "{}://{}{}".format(parsed.scheme, parsed.netloc, action)
        elif action:
            target_url = "{}/{}".format(base, action)
        else:
            target_url = url  # No action = POST to current page

        # Extract input names
        params = re.findall(r'name=["\']([^"\']+)["\']', form_html, re.I)
        if not params:
            params = ["username", "password"] if "login" in target_url.lower() or "sign" in target_url.lower() else ["q"]

        endpoints.append({
            "url": target_url, "method": method, "params": params,
            "source": "form"
        })

    # 2. Extract links to API-like paths
    api_patterns = set()
    for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.I):
        path = m.group(1)
        if any(kw in path.lower() for kw in
               ["api", "graphql", "search", "query", "login", "auth",
                "user", "order", "admin", "file", "upload", "download",
                ".php", ".json", ".xml"]):
            api_patterns.add(path)

    for path in list(api_patterns)[:10]:
        if path.startswith("http"):
            target_url = path
        elif path.startswith("/"):
            parsed = urlparse(url)
            target_url = "{}://{}{}".format(parsed.scheme, parsed.netloc, path)
        else:
            target_url = "{}/{}".format(base, path)
        endpoints.append({
            "url": target_url, "method": "GET", "params": ["id"],
            "source": "link"
        })

    # Deduplicate by URL (build seen set first)
    seen = set()
    unique = []
    for ep in endpoints:
        key = ep["url"] + ep["method"]
        if key not in seen:
            seen.add(key)
            unique.append(ep)
    endpoints = unique

    # 3. Key API paths
    parsed = urlparse(url)
    root = "{}://{}".format(parsed.scheme, parsed.netloc)
    for path in ["/api", "/graphql", "/admin"]:
        key = root + path + "GET"
        if key not in seen:
            seen.add(key)
            endpoints.append({
                "url": root + path, "method": "GET", "params": ["id"],
                "source": "common"
            })
    logger.info("Discovered %d endpoints from %d forms + %d links",
                len(endpoints), len(forms), len(api_patterns))
    return endpoints[:15]


def run_detector(vuln_type: str, url: str, param: str,
                 sess: requests.Session, timeout: float = 10.0) -> dict:
    """Run a single detector, augmented with Skill payloads."""
    result = {"vuln_type": vuln_type, "vulnerable": False,
              "error": None, "evidence": [], "skill_used": False}

    # Load Skill payloads for this vulnerability type
    try:
        from aimy.tools.skill_payload_loader import get_skill_payload_context
        skill_ctx = get_skill_payload_context(vuln_type)
        skill_payloads = skill_ctx.get("payloads", [])
        skill_techniques = skill_ctx.get("techniques", [])
        if skill_payloads:
            logger.info("Loaded %d Skill payloads for %s", len(skill_payloads), vuln_type)
            result["skill_payloads_available"] = len(skill_payloads)
            result["skill_techniques"] = skill_techniques[:5]
    except Exception as e:
        logger.debug("Skill load failed for %s: %s", vuln_type, e)
        skill_payloads = []
        skill_techniques = []

    try:
        if vuln_type == "idor" or vuln_type == "auth_bypass":
            from aimy.tools.auth_bypass import check
            r = check(url, sess=sess, timeout=min(timeout, 5.0), max_time=20.0)
        elif vuln_type == "sqli":
            from aimy.tools.sql_injection import check
            # 支持 POST JSON（如 /jobs 端点）
            if "/jobs" in url or "/api" in url:
                r = check(url, param, sess=sess, timeout=timeout,
                         post_body=True, post_data={param: "1"})
            else:
                r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "xss":
            from aimy.tools.xss_detector import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "ssti":
            from aimy.tools.ssti_detector import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "cmdi":
            from aimy.tools.cmdi_detector import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "ssrf":
            from aimy.tools.ssrf_detector import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "lfi" or vuln_type == "path_traversal":
            from aimy.tools.lfi_scanner import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "jwt":
            from aimy.tools.jwt_detector import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "deserialization":
            from aimy.tools.deserialization_detector import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "graphql":
            from aimy.tools.graphql_scanner import check
            r = check(url, param, sess=sess, timeout=timeout)
        elif vuln_type == "xxe":
            from aimy.tools.deserialization_detector import check
            r = check(url, param, sess=sess, timeout=timeout)
        else:
            return result

        if isinstance(r, dict):
            result["vulnerable"] = r.get("vulnerable", False)
            result["evidence"] = r.get("evidence", [])
            result["detail"] = r

        # Fallback: if detector missed, try Skill payloads manually
        if not result["vulnerable"] and skill_payloads:
            result["skill_used"] = True
            logger.info("%s: detector missed, trying %d Skill payloads",
                        vuln_type, len(skill_payloads))

            for skill_payload in skill_payloads[:15]:  # Cap at 15 tries
                try:
                    test_url = build_url(url, param, skill_payload)
                    r2 = sess.get(test_url, timeout=timeout)

                    # Check for common indicators
                    if vuln_type == "xss":
                        # Look for unescaped reflection
                        if skill_payload in r2.text:
                            escaped = skill_payload.replace("<", "&lt;").replace(">", "&gt;")
                            if escaped not in r2.text:
                                result["vulnerable"] = True
                                result["evidence"].append(
                                    "Skill XSS: '%s' reflected unescaped (%dB)" % (
                                        skill_payload[:40], len(r2.text)))
                                break
                    elif vuln_type == "sqli":
                        for pat in [r"SQL syntax", r"mysql_fetch", r"ORA-\d{5}",
                                     r"PostgreSQL.*ERROR", r"SqlException",
                                     r"Unclosed quotation mark", r"SQLite.*Exception"]:
                            if re.search(pat, r2.text, re.IGNORECASE):
                                result["vulnerable"] = True
                                result["evidence"].append(
                                    "Skill SQLi: error pattern '%s' with payload '%s'" % (
                                        pat[:30], skill_payload[:30]))
                                break
                        if result["vulnerable"]:
                            break
                    elif vuln_type == "cmdi":
                        for pat in [r"uid=\d+", r"root:", r"bin/bash",
                                     r"Microsoft Windows", r"Linux",
                                     r"command not found"]:
                            if re.search(pat, r2.text):
                                result["vulnerable"] = True
                                result["evidence"].append(
                                    "Skill CMDi: pattern '%s' with payload '%s'" % (
                                        pat[:20], skill_payload[:30]))
                                break
                        if result["vulnerable"]:
                            break
                    elif vuln_type == "ssti":
                        if "49" in r2.text or "A" in r2.text:
                            result["vulnerable"] = True
                            result["evidence"].append(
                                "Skill SSTI: computed result with payload '%s'" % skill_payload[:30])
                            break
                except Exception:
                    continue

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def quickhunt(url: str, timeout: float = 10.0,
              max_detectors: int = 3,
              max_time: float = 600.0) -> Dict:
    """
    Speedrun vulnerability scan.

    1. Fetch URL, analyze signals
    2. Pick top-N most likely vulnerability types
    3. Run relevant detectors
    4. Return findings

    Time budget: ~10 minutes max.
    """
    start_time = time.time()
    sess = requests.Session()
    sess.verify = settings.verify_ssl

    result = {
        "url": url,
        "findings": [],
        "tested": [],
        "skipped": [],
        "errors": [],
        "elapsed_sec": 0,
    }

    logger.info("QuickHunt: %s", url)

    # Phase 1: Signal analysis (5s)
    signals = analyze_url(url)
    logger.info("Signals from URL: %s params=%s",
                ",".join(signals["vuln_types"]) if signals["vuln_types"] else "none",
                signals["params"])

    # Phase 2: Page fetch + additional signals (10s)
    page = quick_fetch(url, sess, timeout=min(timeout, 5.0))

    if page.get("has_login"):
        signals["vuln_types"].add("auth_bypass")
        logger.info("Login form detected → +auth_bypass")
    if page.get("has_jwt"):
        signals["vuln_types"].add("jwt")
        logger.info("JWT detected → +jwt")

    # Check HTML comments for credentials
    for comment in page.get("comments", []):
        if re.search(r'(?i)(test|password|credential|TODO.*account)', comment):
            signals["vuln_types"].add("auth_bypass")
            logger.info("Credential hint in HTML comment → +auth_bypass")

    # Phase 3: Endpoint discovery
    endpoints = discover_endpoints(url, page.get("html", ""), page.get("forms", []))
    if not endpoints:
        # Fallback: use root URL with detected params
        params = signals["params"] or ["id"]
        endpoints = [{"url": url, "method": "GET", "params": params, "source": "fallback"}]

    # Phase 4: Prioritize vulnerability types
    ordered_vulns = [v for v in VULN_PRIORITY if v in signals["vuln_types"]]
    if not ordered_vulns:
        ordered_vulns = ["idor", "sqli", "xss"]

    detectors_to_run = ordered_vulns[:max_detectors]

    logger.info("Testing %d vuln types across %d endpoints: %s",
                len(detectors_to_run), len(endpoints),
                ",".join(detectors_to_run))

    # Track authenticated session for chaining
    auth_session = None

    for vuln_type in detectors_to_run:
        elapsed = time.time() - start_time
        if elapsed > max_time:
            result["skipped"].append(vuln_type)
            break

        # If we have an authenticated session from a previous hit,
        # use it for subsequent detectors (chain: auth → IDOR/SQLi/etc)
        test_sess = auth_session if auth_session else sess
        found = False

        # Try each discovered endpoint (top 3)
        for ep in endpoints[:3]:
            if time.time() - start_time > max_time:
                break

            param = ep["params"][0] if ep["params"] else "id"
            ep_url = ep["url"]

            t0 = time.time()
            finding = run_detector(vuln_type, ep_url, param, test_sess, timeout)
            finding["elapsed"] = round(time.time() - t0, 1)
            finding["endpoint"] = ep_url

            if finding.get("vulnerable"):
                result["findings"].append(finding)
                logger.info("HIT: %s @ %s → %s",
                           vuln_type, ep_url, finding.get("evidence", [])[:2])

                # Chain: if we just found credentials, try to login and
                # use the session for subsequent detectors
                if vuln_type == "auth_bypass" and finding.get("detail"):
                    detail = finding["detail"]
                    if detail.get("default_creds"):
                        creds = detail["default_creds"][0]
                        try:
                            auth_sess = requests.Session()
                            auth_sess.verify = settings.verify_ssl
                            login_url = creds.get("endpoint", url)
                            r = auth_sess.post(login_url,
                                data={"username": creds["username"],
                                      "password": creds["password"]},
                                timeout=timeout, allow_redirects=True)
                            if r.status_code == 200 or "welcome" in r.text.lower():
                                auth_session = auth_sess
                                logger.info("Chain: authenticated session established")
                        except Exception:
                            pass
                found = True
                break
            elif finding.get("error"):
                result["errors"].append(finding)
            else:
                # WAF detection: if all payloads returned same response,
                # try bypass
                if vuln_type == "xss" and not found:
                    for ep2 in endpoints[:3]:
                        ep_url2 = ep2["url"]
                        param2 = ep2["params"][0] if ep2["params"] else "q"
                        try:
                            from aimy.tools.waf_bypass import check as waf_check
                            waf_r = waf_check(ep_url2, param2, sess=test_sess, timeout=timeout)
                            if isinstance(waf_r, dict) and waf_r.get("vulnerable"):
                                result["findings"].append({
                                    "vuln_type": "xss_waf_bypass",
                                    "vulnerable": True,
                                    "evidence": waf_r.get("evidence", ["WAF bypass"])[:2],
                                    "endpoint": ep_url2,
                                })
                                logger.info("WAF BYPASS HIT: %s", ep_url2)
                                found = True
                                break
                        except Exception:
                            pass

        if not found and not finding.get("error"):
            result["tested"].append(vuln_type)

    result["elapsed_sec"] = round(time.time() - start_time, 1)
    result["endpoints_tested"] = len(endpoints)
    logger.info("QuickHunt done: %d findings, %d tested, %d endpoints, %.1fs",
                len(result["findings"]), len(result["tested"]),
                len(endpoints), result["elapsed_sec"])

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python quickhunt.py <URL>")
        print("Example: python quickhunt.py https://target.com/page?id=123")
        sys.exit(1)

    url = sys.argv[1]
    result = quickhunt(url)

    print("\n" + "=" * 60)
    print("  QuickHunt Result")
    print("=" * 60)
    print("  URL:     {}".format(result["url"]))
    print("  Time:    {:.1f}s".format(result["elapsed_sec"]))
    print("  Findings: {}".format(len(result["findings"])))
    print("  Tested:   {}".format(",".join(result["tested"]) if result["tested"] else "none"))
    print("  Skipped:  {}".format(",".join(result["skipped"]) if result["skipped"] else "none"))

    if result["findings"]:
        print("\n  --- FINDINGS ---")
        for f in result["findings"]:
            print("  [{}] {}".format(
                f["vuln_type"].upper(),
                f.get("evidence", ["no details"])[0] if f.get("evidence") else "detected"))
    else:
        print("\n  No vulnerabilities found in quick scan.")

    if result["errors"]:
        print("\n  --- ERRORS ---")
        for e in result["errors"]:
            print("  [{}] {}".format(e["vuln_type"], e.get("error", "unknown")))


if __name__ == "__main__":
    main()
