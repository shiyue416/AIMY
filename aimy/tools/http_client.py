import io
import ssl
import socket
import urllib.parse
import re
import subprocess
import json
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from http.client import HTTPResponse

import time as _time
import threading

from aimy.tools.log_utils import get_logger
from aimy.tools.settings import settings

logger = get_logger("http_client")


# ═══════════════════════════════════════════
# P0 修补: CAPTCHA / MFA 自动检测 (bounty 模式硬拦截)
# ═══════════════════════════════════════════

# CAPTCHA 检测模式 — 匹配响应中的验证码/人机验证特征
_CAPTCHA_PATTERNS = [
    # 中文验证码
    r"验证码", r"请输入验证码", r"图形验证码", r"滑块验证",
    r"人机验证", r"行为验证", r"安全验证",
    # 英文验证码
    r"captcha", r"reCAPTCHA", r"hCaptcha", r"h-captcha",
    r"g-recaptcha", r"grecaptcha", r"cf-turnstile",
    r"please verify you.{0,10}human", r"are you a robot",
    r"security check", r"challenge.*platform",
    # CDN/厂商验证
    r"cf-challenge", r"akamai.*bot", r"cloudflare.*challenge",
    r"ddos.*protection", r"bot.*detect",
    # 行为特征 (HTML title)
    r"<title>.*(?:验证|verify|challenge|security check).*</title>",
    # JS 挑战
    r"window\._cf_chl", r"setTimeout.*challenge",
    r"document\.cookie.*=.*challenge",
]

# MFA/2FA 检测模式 — 匹配多因素认证页面特征
_MFA_PATTERNS = [
    # 中文 MFA
    r"双因素认证", r"两步验证", r"双重验证",
    r"手机验证码", r"短信验证码", r"动态口令",
    r"身份验证器", r"安全令牌", r"请输入验证码",
    r"已发送.*验证码", r"验证码已发送",
    # 英文 MFA
    r"two.factor", r"2fa", r"mfa",
    r"multi.factor", r"multi-factor",
    r"authenticator app", r"authentication code",
    r"verification code", r"security code",
    r"enter the code", r"enter code",
    r"one.time passcode", r"otp",
    r"google authenticator", r"microsoft authenticator",
    r"duo security", r"okta verify",
    r"authy", r"totp",
    # TOTP/QR
    r"scan.*qr.*code", r"qr.*authenticator",
    # SMS/Email code
    r"code.*sent.*to.*(?:phone|email|device)",
    r"we.{0,5}sent.*code",
    # Hardware key
    r"security key", r"yubikey", r"webauthn",
    r"passkey", r"fido",
]

# 连续命中 CAPTCHA 阈值 → 触发熔断
_CAPTCHA_MELTDOWN_THRESHOLD = 3
_captcha_strikes = 0
_captcha_meltdown_until = 0.0

# MFA 命中标记 — 标记当前认证向量，停止探测
_mfa_hit_endpoints: set = set()
_mfa_warned_endpoints: set = set()


def _detect_captcha(response_body: str, url: str) -> bool:
    """检测响应是否为验证码/人机验证页面。"""
    global _captcha_strikes, _captcha_meltdown_until

    # 已熔断中 → 跳过检测
    if _time.time() < _captcha_meltdown_until:
        return True

    # 只检查前 8KB (性能优化)
    sample = response_body[:8192].lower()
    if len(sample) < 100:
        return False

    for pattern in _CAPTCHA_PATTERNS:
        if re.search(pattern, sample, re.IGNORECASE):
            _captcha_strikes += 1
            host = urlparse(url).hostname or "unknown"
            logger.warning(
                "[CAPTCHA] 检测到验证码页面 (strike %d/%d): %s → %s",
                _captcha_strikes, _CAPTCHA_MELTDOWN_THRESHOLD, host, url
            )

            if _captcha_strikes >= _CAPTCHA_MELTDOWN_THRESHOLD:
                melt_secs = 600  # 10 分钟熔断
                _captcha_meltdown_until = _time.time() + melt_secs
                logger.critical(
                    "[CAPTCHA] 连续 %d 次命中验证码 → 熔断 %d 秒! "
                    "bounty 模式下禁止绕过验证码。停止所有请求。",
                    _captcha_strikes, melt_secs
                )
                raise RuntimeError(
                    f"[CAPTCHA] 连续命中验证码 {_captcha_strikes} 次 → 自动熔断 {melt_secs}s。"
                    f" bounty 模式禁止绕过人机验证。"
                )
            return True
    return False


def _detect_mfa(response_body: str, resp_headers: dict, url: str) -> bool:
    """检测响应是否为 MFA/2FA 验证页面。"""
    global _mfa_hit_endpoints, _mfa_warned_endpoints

    host = urlparse(url).hostname or "unknown"
    # 对同一端点只告警一次
    endpoint_key = f"{host}{urlparse(url).path}"

    if endpoint_key in _mfa_warned_endpoints:
        return endpoint_key in _mfa_hit_endpoints

    sample = response_body[:8192].lower()
    if len(sample) < 100:
        return False

    # 额外检查: 302 跳转到 /mfa /2fa /verify 等路径
    location = resp_headers.get("location", "").lower()
    mfa_redirect = any(p in location for p in ("/mfa", "/2fa", "/verify", "/otp",
                                                "/authenticate", "/challenge"))

    body_match = False
    for pattern in _MFA_PATTERNS:
        if re.search(pattern, sample, re.IGNORECASE):
            body_match = True
            break

    if body_match or mfa_redirect:
        _mfa_hit_endpoints.add(endpoint_key)
        _mfa_warned_endpoints.add(endpoint_key)
        logger.warning(
            "[MFA] 检测到多因素认证页面 (body=%s, redirect=%s): %s → %s",
            body_match, mfa_redirect, host, url
        )
        logger.warning(
            "[MFA] bounty 模式禁止绕过 MFA/2FA。此端点将从认证向量中排除。"
        )
        return True

    _mfa_warned_endpoints.add(endpoint_key)
    return False


def is_captcha_meltdown() -> bool:
    """检查是否处于 CAPTCHA 熔断状态。"""
    return _time.time() < _captcha_meltdown_until


def get_captcha_meltdown_remaining() -> float:
    """返回 CAPTCHA 熔断剩余时间 (秒)。"""
    return max(0.0, _captcha_meltdown_until - _time.time())


def is_mfa_hit(url: str) -> bool:
    """检查指定 URL 是否已命中 MFA。"""
    parsed = urlparse(url)
    endpoint_key = f"{parsed.hostname or 'unknown'}{parsed.path}"
    return endpoint_key in _mfa_hit_endpoints


def reset_captcha_state():
    """重置 CAPTCHA 计数器 (用于新目标切换)。"""
    global _captcha_strikes, _captcha_meltdown_until
    _captcha_strikes = 0
    _captcha_meltdown_until = 0.0


def reset_mfa_state():
    """重置 MFA 标记 (用于新目标切换)。"""
    global _mfa_hit_endpoints, _mfa_warned_endpoints
    _mfa_hit_endpoints = set()
    _mfa_warned_endpoints = set()


# ═══════════════════════════════════════════
# P0 修补: 速率控制器 (Token 桶 + 熔断)
# ═══════════════════════════════════════════

class _RateLimiter:
    """Token 桶速率控制器，带熔断机制。线程安全。

    - 默认 1 req/s（从 settings.rate_limit 读取）
    - 429 响应 → 递进熔断 (60s→120s→180s→300s max)
    - 503 响应 → 固定 600s 熔断
    - 连续超时 → 跳过该端点
    """

    def __init__(self):
        import os
        rate = float(os.environ.get("AIMY_RATE", "1.0"))
        self._interval = 1.0 / max(0.2, rate) if rate > 0 else 1.0
        self._last = 0.0
        self._consecutive_429 = 0
        self._consecutive_timeouts = 0
        self._meltdown_until = 0.0
        self._lock = threading.Lock()

    @property
    def rate(self) -> float:
        return settings.rate_limit

    @property
    def is_meltdown(self) -> bool:
        return _time.time() < self._meltdown_until

    @property
    def meltdown_remaining(self) -> float:
        return max(0.0, self._meltdown_until - _time.time())

    def wait(self):
        """阻塞直到可以发下一个请求（速率 + 熔断）。线程安全。"""
        with self._lock:
            now = _time.time()

            # ── 熔断等待 ──
            if now < self._meltdown_until:
                remaining = self._meltdown_until - now
                logger.warning("[FUSE] 熔断中 — 等待 %.0fs", remaining)
                _time.sleep(remaining)
                now = _time.time()
                self._meltdown_until = 0.0

            # ── 速率控制 ──
            elapsed = now - self._last
            if elapsed < self._interval:
                _time.sleep(self._interval - elapsed)
            self._last = _time.time()

    def report_status(self, status_code: int):
        """根据响应码更新熔断/超时计数器。线程安全。"""
        with self._lock:
            if status_code == 429:
                self._consecutive_429 += 1
                pause = min(300, 60 * self._consecutive_429)  # 60→120→180→240→300
                self._meltdown_until = _time.time() + pause
                logger.warning("[FUSE] 429 Too Many Requests — 熔断 %ds (第%d次)",
                               pause, self._consecutive_429)
            elif status_code == 503:
                self._meltdown_until = _time.time() + settings.fuse_503_seconds
                logger.warning("[FUSE] 503 Service Unavailable — 熔断 %ds",
                               settings.fuse_503_seconds)
            elif status_code == 0:
                self._consecutive_timeouts += 1
                if self._consecutive_timeouts >= settings.fuse_consecutive_timeouts:
                    logger.warning("[FUSE] 连续 %d 次超时 — 建议跳过此端点",
                                   self._consecutive_timeouts)
            else:
                self._consecutive_429 = 0
                self._consecutive_timeouts = 0

    def update_interval(self):
        """同步 settings.rate_limit 变更。"""
        with self._lock:
            self._interval = 1.0 / settings.rate_limit if settings.rate_limit > 0 else 1.0

    @property
    def is_meltdown(self) -> bool:
        return _time.time() < self._meltdown_until

    @property
    def meltdown_remaining(self) -> float:
        return max(0.0, self._meltdown_until - _time.time())


# 全局单例
_rate_limiter = _RateLimiter()

_CHALLENGE_PATTERN = re.compile(
    r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)',
    re.DOTALL,
)
_AES_JS_CACHE: Optional[str] = None


def _get_aes_js(base_url: str) -> Optional[str]:
    global _AES_JS_CACHE
    if _AES_JS_CACHE is not None:
        return _AES_JS_CACHE
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    try:
        hc = _RawHttpClient(timeout=10)
        status, headers, body = hc.request("GET", f"{origin}/aes.js")
        if status == 200 and len(body) > 1000:
            _AES_JS_CACHE = body
            return _AES_JS_CACHE
    except Exception as e:
        logger.debug("Failed to fetch aes.js: %s", e)
    return None


def _solve_challenge(html: str, base_url: str) -> Optional[str]:
    m = _CHALLENGE_PATTERN.search(html)
    if not m:
        logger.debug("No challenge pattern found in response")
        return None
    a, b, c = m.group(1), m.group(2), m.group(3)
    aes_js = _get_aes_js(base_url)
    if not aes_js:
        logger.debug("Cannot solve challenge: aes.js not available")
        return None
    js_code = aes_js + f"""
function toNumbers(d){{var e=[];d.replace(/(..)/g,function(d){{e.push(parseInt(d,16))}});return e}}
function toHex(){{for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e='',f=0;f<d.length;f++)e+=(16>d[f]?'0':'')+d[f].toString(16);return e.toLowerCase()}}
try {{ console.log(toHex(slowAES.decrypt(toNumbers("{c}"),2,toNumbers("{a}"),toNumbers("{b}")))); }} catch(e) {{ console.error(e.message); }}
"""
    try:
        result = subprocess.run(
            ["node", "-e", js_code],
            capture_output=True, text=True, timeout=15,
        )
        cookie_val = result.stdout.strip()
        if cookie_val and len(cookie_val) == 32 and all(c in "0123456789abcdef" for c in cookie_val):
            logger.debug("Solved anti-bot challenge: __test=%s", cookie_val)
            return cookie_val
        logger.debug("Challenge solver output invalid: %s", result.stdout.strip()[:50])
    except Exception as e:
        logger.debug("Failed to solve challenge via node: %s", e)
    return None


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if not settings.verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _RawHttpClient:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._ctx = _build_ssl_context()

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[str] = None, cookie: Optional[str] = None) -> Tuple[int, Dict[str, str], str]:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        sock = socket.create_connection((hostname, port), timeout=self.timeout)
        if parsed.scheme == "https":
            ssock = self._ctx.wrap_socket(sock, server_hostname=hostname)
        else:
            ssock = sock

        req_headers = {
            "Host": hostname,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)
        if cookie:
            req_headers["Cookie"] = f"__test={cookie}"

        req_body = body or ""
        header_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in req_headers.items():
            header_lines.append(f"{k}: {v}")
        header_lines.append(f"Content-Length: {len(req_body.encode())}" if req_body else "")
        header_lines.append("")
        header_lines.append(req_body)
        request_bytes = "\r\n".join(header_lines).encode()

        ssock.sendall(request_bytes)
        response_bytes = b""
        while True:
            try:
                chunk = ssock.recv(65536)
                if not chunk:
                    break
                response_bytes += chunk
            except socket.timeout:
                break
            except Exception:
                break
        ssock.close()

        # Parse HTTP response
        response_str = response_bytes.decode("utf-8", errors="replace")
        header_end = response_str.find("\r\n\r\n")
        if header_end == -1:
            return (0, {}, response_str)

        raw_headers = response_str[:header_end]
        response_body = response_str[header_end + 4:]

        header_lines = raw_headers.split("\r\n")
        status_line = header_lines[0]
        status_code = int(status_line.split(" ")[1]) if len(status_line.split(" ")) > 1 else 0

        resp_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return (status_code, resp_headers, response_body)


class HttpClient:
    def __init__(self, sess: Optional[Any] = None, timeout: float = 10.0):
        self.timeout = timeout
        self._cookie: Optional[str] = None
        self._challenge_solved = False

    def _ensure_session(self):
        if not hasattr(self, "_raw"):
            self._raw = _RawHttpClient(timeout=self.timeout)

    def _auto_solve(self, body: str, url: str) -> Optional[str]:
        if self._challenge_solved:
            return None
        if "slowAES" not in body or "toNumbers" not in body[:2000]:
            return None
        cookie_val = _solve_challenge(body, url)
        if cookie_val:
            self._cookie = cookie_val
            self._challenge_solved = True
            return cookie_val
        return None

    def request(self, method: str, url: str, **kwargs) -> "FakeResponse":
        # ═══════════════════════════════════════════
        # P0 修补: 三道安全闸门
        # ═══════════════════════════════════════════

        # ── 闸门 1: Scope 校验 ──
        if not settings.is_in_scope(url):
            if settings._scope_domains:
                # scope 已配置且 URL 不在白名单 → 阻断
                raise PermissionError(
                    f"[SCOPE] {urlparse(url).hostname} 不在授权范围内。"
                    f" 已加载 {len(settings._scope_domains)} 个授权域名。"
                )
            # else: scope 未配置 → 允许但警告
            logger.warning("[SCOPE] 未配置 scope 文件，请求未校验: %s", urlparse(url).hostname)

        # ── 闸门 2: 日配额 ──
        if not settings.check_daily_quota():
            raise RuntimeError(
                f"[QUOTA] 今日请求已达上限 {settings.max_requests_per_day}。"
                f" 请等待次日或调整 AIMY_DAILY_MAX。"
            )

        # ── 闸门 3: 并发槽位 ──
        slot_acquired = settings.acquire_slot()
        if not slot_acquired:
            raise RuntimeError(
                f"[CONCUR] 并发已达上限 {settings.max_concurrency}。"
                f" 当前活跃请求: {settings.active_requests}"
            )

        try:
            # ── 速率控制 ──
            _rate_limiter.wait()

            self._ensure_session()
            headers = kwargs.pop("headers", {})
            body = kwargs.pop("data", None)

            status, resp_headers, resp_body = self._raw.request(
                method, url, headers=headers, body=body, cookie=self._cookie
            )

            if not self._challenge_solved:
                cookie_val = self._auto_solve(resp_body, url)
                if cookie_val:
                    # Retry with cookie
                    status, resp_headers, resp_body = self._raw.request(
                        method, url, headers=headers, body=body, cookie=self._cookie
                    )

            # ── 闸门 4: CAPTCHA 自动检测 (bounty 模式) ──
            if getattr(settings, 'read_only', True):
                _detect_captcha(resp_body, url)

            # ── 闸门 5: MFA 自动检测 (bounty 模式) ──
            if getattr(settings, 'read_only', True):
                _detect_mfa(resp_body, resp_headers, url)

            # ── 响应反馈（熔断跟踪） ──
            _rate_limiter.report_status(status)

            # ── 记录请求 ──
            settings.record_request()

            return FakeResponse(status, resp_headers, resp_body, url)

        finally:
            settings.release_slot()

    def get(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("DELETE", url, **kwargs)

    def resolve_url(self, base: str, path: str) -> str:
        base = base.rstrip("/")
        path = path.lstrip("/")
        return "%s/%s" % (base, path)


class FakeResponse:
    def __init__(self, status_code: int, headers: Dict[str, str], text: str, url: str):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.url = url
        self.content = text.encode("utf-8", errors="replace")
        self.ok = 200 <= status_code < 400

    def __repr__(self):
        return f"<FakeResponse [{self.status_code}]>"


def build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.ParseResult(
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ).geturl()
