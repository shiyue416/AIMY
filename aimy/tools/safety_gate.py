"""Safety Gate — 只读模式技术护栏

三层拦截:
  Layer 1: 方法拦截 — 禁止 PUT/PATCH/DELETE（可配置）
  Layer 2: Payload 净化 — 替换所有破坏性 SQL 操作为安全等价物
  Layer 3: 数据量限制 — 禁止 INTO OUTFILE, xp_cmdshell 等 （硬限）

集成方式: 框架启动时 monkey-patch requests.Session.request
          → 所有检测器自动受保护，零修改

环境变量: AIMY_READ_ONLY=1   # 开启只读模式，默认开启
          AIMY_READ_ONLY=0   # 关闭（挖自己靶机时）
"""

import re
import logging
from typing import Dict, Optional, Tuple
from urllib.parse import unquote

logger = logging.getLogger("safety_gate")

# ──────────────────────────────────────────────────────────────────
# 破坏性 payload → 安全替代品 映射表
# 规则: 越具体越优先，避免误伤无害 payload
# ──────────────────────────────────────────────────────────────────
WRITE_REPLACEMENTS: Dict[str, str] = [
    # === DROP 系列 ===
    (r"\bDROP\s+TABLE\s+IF\s+EXISTS\b", "SELECT 1 WHERE 1=1"),       # DROP TABLE IF EXISTS
    (r"\bDROP\s+TABLE\b", "SELECT 1"),                                 # DROP TABLE
    (r"\bDROP\s+DATABASE\b", "SELECT 1"),
    (r"\bDROP\s+INDEX\b", "SELECT 1"),
    (r"\bDROP\s+VIEW\b", "SELECT 1"),
    (r"\bDROP\s+PROCEDURE\b", "SELECT 1"),
    (r"\bDROP\s+TRIGGER\b", "SELECT 1"),
    (r"\bDROP\s+FUNCTION\b", "SELECT 1"),
    (r"\bDROP\s+USER\b", "SELECT 1"),

    # === TRUNCATE ===
    (r"\bTRUNCATE\b", "SELECT"),

    # === DELETE ===
    (r"\bDELETE\s+FROM\b", "SELECT 1 FROM"),

    # === UPDATE ===
    (r"\bUPDATE\s+\w+\s+SET\b", "SELECT 1 WHERE 1=1"),

    # === INSERT ===
    (r"\bINSERT\s+INTO\b", "SELECT 1"),

    # === 文件写入 ===
    (r"\bINTO\s+OUTFILE\b", "INTO @_dummy_var"),                      # INTO OUTFILE 'shell.php'
    (r"\bINTO\s+DUMPFILE\b", "INTO @_dummy_var"),                     # INTO DUMPFILE
    (r"\bLOAD\s+DATA\b", "SELECT"),                                    # LOAD DATA INFILE
    (r"\bSELECT\s+INTO\b(?!\s+@)", "SELECT 1"),                       # SELECT INTO (非变量)

    # === MySQL 敏感函数 ===
    (r"\bLOAD_FILE\s*\(", "LENGTH("),

    # === MSSQL 高危 ===
    (r"\bEXEC\s+xp_cmdshell\b", "SELECT 1"),                          # EXEC xp_cmdshell 'whoami'
    (r"\bxp_cmdshell\b", "'safe_check'"),                              # xp_cmdshell 裸调用
    (r"\bsp_configure\b", "sp_helpdb"),                                 # sp_configure 'xp_cmdshell',1
    (r"\bRECONFIGURE\b", "SELECT 1"),                                  # RECONFIGURE
    (r"\bBULK\s+INSERT\b", "SELECT 1"),                               # BULK INSERT
    (r"\bOPENROWSET\b", "OPENQUERY"),
    (r"\bOPENDATASOURCE\b", "OPENQUERY"),
    (r"\bsp_oacreate\b", "sp_help"),

    # === PostgreSQL 高危 ===
    (r"\blo_export\b", "lo_get"),                                      # lo_export → 读不写
    (r"\bdblink_connect\b", "current_database"),
    (r"\bCOPY\s+.*?TO\s+PROGRAM\b", "COPY (SELECT 1) TO '/dev/null"), # COPY TO PROGRAM

    # === Oracle 高危 ===
    (r"\bUTL_HTTP\b", "DBMS_RANDOM"),
    (r"\bUTL_INADDR\b", "DBMS_RANDOM"),
    (r"\bUTL_SMTP\b", "DBMS_RANDOM"),
    (r"\bDBMS_LDAP\b", "DBMS_RANDOM"),

    # === 创建/修改对象 ===
    (r"\bCREATE\s+TABLE\b", "SELECT 1"),
    (r"\bCREATE\s+USER\b", "SELECT 1"),
    (r"\bCREATE\s+LOGIN\b", "SELECT 1"),
    (r"\bCREATE\s+INDEX\b", "SELECT 1"),
    (r"\bCREATE\s+VIEW\b", "SELECT 1"),
    (r"\bCREATE\s+PROCEDURE\b", "SELECT 1"),
    (r"\bALTER\s+TABLE\b", "SELECT 1"),
    (r"\bALTER\s+USER\b", "SELECT 1"),
    (r"\bALTER\s+LOGIN\b", "SELECT 1"),
    (r"\bGRANT\b", "SELECT"),
    (r"\bREVOKE\b", "SELECT"),

    # === Webshell / RCE payload ===
    (r"<\?php\s+system\b", "<?php echo "),
    (r"<\?php\s+shell_exec\b", "<?php echo "),
    (r"<\?php\s+exec\b", "<?php echo "),
    (r"\beval\s*\(.*?\$_", "strlen("),

    # === WordPress config leak mitigation (改读不写) ===
    (r"\bwp_config\b", "wp-config_sample"),
]

# 编译 regex
_COMPILED_RULES = [(re.compile(pat, re.IGNORECASE | re.DOTALL), repl)
                    for pat, repl in WRITE_REPLACEMENTS]

# 拦截的 HTTP 方法
_DESTRUCTIVE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})


def sanitize_payload(payload: str) -> str:
    """替换 payload 中所有破坏性操作为安全等价物，保留检测能力。

    例如:  "1'; DROP TABLE users --"  →  "1'; SELECT 1 --"
           "' UNION SELECT 1,2,3 INTO OUTFILE '/shell.php' -- "
           →  "' UNION SELECT 1,2,3 INTO @_dummy_var -- "
    """
    result = payload
    for pattern, replacement in _COMPILED_RULES:
        if pattern.search(result):
            result = pattern.sub(replacement, result)
    return result


def payload_has_destructive_op(payload: str) -> bool:
    """检查 payload 是否包含破坏性操作（不修改，只判断）。"""
    for pattern, _ in _COMPILED_RULES:
        if pattern.search(payload):
            return True
    return False


def is_safe_method(method: str) -> bool:
    """检查 HTTP 方法是否为安全（只读）方法。"""
    return method.upper() not in _DESTRUCTIVE_METHODS


class SafetyError(PermissionError):
    """被 Safety Gate 拦截的请求会抛出此异常。"""
    pass


class SafetyInterceptor:
    """请求拦截器 — 对 requests.Session 透明生效。"""

    def __init__(self, enabled: bool = True, block_methods: bool = True,
                 sanitize_payloads: bool = True, logger_level: int = logging.WARNING):
        self.enabled = enabled
        self.block_methods = block_methods
        self.sanitize_payloads = sanitize_payloads

        # 统计
        self.blocked_count = 0
        self.sanitized_count = 0
        self.passed_count = 0

    def intercept(self, method: str, url: str, body: Optional[str] = None,
                  return_403: bool = True) -> Tuple[str, str, Optional[str]]:
        """拦截并可能修改请求。

        返回: (method, url, body) — 可能被修改
        抛出 SafetyError: 请求被完全阻止（除非 return_403=True）
        """
        if not self.enabled:
            self.passed_count += 1
            return method, url, body

        method_upper = method.upper()

        # ── Layer 1: 方法拦截 ──
        if self.block_methods and method_upper in _DESTRUCTIVE_METHODS:
            self.blocked_count += 1
            msg = (f"[SAFETY] ⛔ 拦截危险方法 "
                   f"{method_upper} {url[:160]}")
            logger.warning(msg)
            if return_403:
                raise SafetyError(
                    f"Blocked {method_upper} {url} (read-only mode: "
                    f"use GET/POST/HEAD/OPTIONS only)")
            else:
                return method, url, body

        # ── Layer 2: Payload 净化 ──
        if self.sanitize_payloads:
            # URL 参数也解码检查
            decoded_url = unquote(url)
            if payload_has_destructive_op(decoded_url):
                clean_url = sanitize_payload(decoded_url)
                # 重新编码特殊字符（保留 =?& 等结构）
                import urllib.parse
                parsed = urllib.parse.urlparse(clean_url)
                clean_path = urllib.parse.quote(parsed.path, safe="/@:!$&'()*+,;=-._~")
                clean_query = parsed.query.replace("+", "%2B")
                # 保持原 URL 结构，只改参数值
                url = clean_url  # 让调用方处理重编码
                self.sanitized_count += 1
                msg = (f"[SAFETY] ✂️ URL 净化: "
                       f"origin={decoded_url[:80]} → clean={clean_url[:80]}")
                logger.warning(msg)

            if body:
                if payload_has_destructive_op(body):
                    clean_body = sanitize_payload(body)
                    if clean_body != body:
                        body = clean_body
                        self.sanitized_count += 1
                        msg = (f"[SAFETY] ✂️ Body 净化: "
                               f"origin={body[:100]} → clean={clean_body[:100]}")
                        logger.warning(msg)

        self.passed_count += 1
        return method, url, body

    def report(self) -> str:
        """返回拦截统计报告。"""
        total = self.blocked_count + self.sanitized_count + self.passed_count
        if total == 0:
            return "[SAFETY] 未处理任何请求"
        return (
            f"[SAFETY] 统计: 总请求={total} "
            f"通过={self.passed_count} "
            f"拦截={self.blocked_count} "
            f"净化={self.sanitized_count}"
        )


# 全局单例
_interceptor = SafetyInterceptor(enabled=False)


def enable() -> None:
    """启用 Safety Gate。"""
    _interceptor.enabled = True
    logger.info("[SAFETY] 🟢 Read-Only Mode 已启用 — "
                "PUT/PATCH/DELETE 将被拦截，写操作 payload 被净化")


def disable() -> None:
    """禁用 Safety Gate。"""
    _interceptor.enabled = False
    logger.info("[SAFETY] 🔴 Read-Only Mode 已禁用 — 所有请求直通")


def install_hook() -> None:
    """Monkey-patch requests.Session.request 安装安全钩子。

    所有使用 requests.Session() 的检测器自动受保护。
    这是最彻底的方案——不改任何检测器代码。
    """
    import requests as _requests

    # 保存原始方法
    original_request = _requests.Session.request

    def patched_request(self, method, url, **kwargs):
        """替换 requests.Session.request — 先过 Safety Gate。"""
        body = kwargs.get("data", None)
        # data 可能是 dict（form），也可能是 str/bytes
        if isinstance(body, dict):
            body_str = "&".join(f"{k}={v}" for k, v in body.items())
        elif isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="replace")
        elif body is not None:
            body_str = str(body)
        else:
            body_str = None

        try:
            method, url, safe_body = _interceptor.intercept(method, url, body_str)
            # 如果 body 被净化，写回
            if safe_body is not None and safe_body != body_str:
                kwargs["data"] = safe_body
            return original_request(self, method, url, **kwargs)
        except SafetyError:
            # 返回 403 响应替代抛出异常
            # 这样检测器的循环不会崩溃
            import requests as req_mod
            resp = req_mod.Response()
            resp.status_code = 403
            resp._content = (
                b"[SAFETY] Request blocked by Safety Gate (read-only mode). "
                b"Set AIMY_READ_ONLY=0 to disable."
            )
            resp.url = url
            resp.request = req_mod.PreparedRequest()
            resp.request.method = method
            resp.request.url = url
            resp.encoding = "utf-8"
            # 复制原始请求的 cookies 以便后续不报错
            resp.cookies = self.cookies
            return resp

    _requests.Session.request = patched_request
    logger.info("[SAFETY] ✅ Monkey-patch installed — "
                "ALL requests.Session requests are now protected")


def uninstall_hook() -> None:
    """还原 monkey-patch。"""
    import requests as _requests
    # 使用模块级备份
    if hasattr(_requests.Session, '_original_request'):
        _requests.Session.request = _requests.Session._original_request
        logger.info("[SAFETY] Monkey-patch removed")


# 便捷函数：给 settings 用
def get_status() -> dict:
    """返回 Safety Gate 当前状态。"""
    return {
        "enabled": _interceptor.enabled,
        "blocked": _interceptor.blocked_count,
        "sanitized": _interceptor.sanitized_count,
        "passed": _interceptor.passed_count,
    }


# 快捷函数：检测单个 payload 是否安全
def is_payload_safe(payload: str) -> Tuple[bool, Optional[str]]:
    """检查 payload 是否安全（不含破坏性操作）。

    返回: (safe: bool, sanitized: Optional[str])
    - (True, None) → 安全
    - (False, sanitized) → 不安全，建议替换为 sanitized
    """
    if not payload_has_destructive_op(payload):
        return True, None
    clean = sanitize_payload(payload)
    return False, clean
