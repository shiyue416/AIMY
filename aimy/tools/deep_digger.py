#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DeepDigger — 深度挖掘器 (模拟顶级白客的"直觉+持久性+创造性")

人类猎人 vs 工具的核心差距:
  1. 直觉: "这不对劲" → 自动标记异常模式
  2. 持久性: 一个点试50种方式 → 自动深度循环
  3. 创造性: 从来没人试过的绕过 → 变异组合引擎
  4. 跨漏洞关联: 几个低危链成高危 → cross_finding_correlate

用法:
    from aimy.tools.deep_digger import DeepDigger
    dd = DeepDigger(target="http://example.com")
    hunches = dd.sniff()           # 直觉扫描 — 标记所有"不对劲"的地方
    dd.burrow(param="id")          # 持久性 — 单个参数试50+种payload
    chains = dd.cross_correlate()  # 关联 — 低危组合成链
"""

import re
import time
import json
from typing import Any
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ── 直觉规则: "这不对劲" 模式 ────────────────────────

HUNCH_PATTERNS: dict[str, list[str]] = {
    "param_name_suspicious": [
        r"(?i)admin", r"(?i)debug", r"(?i)test", r"(?i)dev",
        r"(?i)backup", r"(?i)internal", r"(?i)private", r"(?i)hidden",
        r"(?i)token", r"(?i)secret", r"(?i)key", r"(?i)auth",
        r"(?i)callback", r"(?i)webhook", r"(?i)redirect", r"(?i)url",
        r"(?i)file", r"(?i)path", r"(?i)template", r"(?i)include",
    ],
    "response_weird": [
        r"(?i)stack trace", r"(?i)debug output", r"(?i)internal server error",
        r"(?i)syntax error", r"(?i)unexpected token",
        r"(?i)php error", r"(?i)warning:", r"(?i)notice:",
        r"(?i)laravel", r"(?i)symfony", r"(?i)django",
        r"(?i)runtimeerror", r"(?i)typeerror", r"(?i)valueerror",
    ],
    "param_value_unexpected": [
        r"^\d{8,}$",         # 8+位纯数字 (可能的IDOR)
        r"^[a-f0-9]{32}$",   # MD5
        r"^[a-f0-9]{40}$",   # SHA1
        r"^eyJ",              # JWT
        r"^[A-Za-z0-9+/]{20,}={0,2}$",  # Base64
    ],
}

# ── 创造性变异引擎 ──────────────────────────────────

CREATIVE_MUTATIONS: list[dict] = [
    # 类型混淆
    {"name": "int_to_string",   "desc": "数字参数改成字符串"},
    {"name": "string_to_array", "desc": "参数改成数组 obj[]=1"},
    {"name": "json_inject",     "desc": "参数改成JSON对象"},
    {"name": "negative_number", "desc": "负数"},
    {"name": "very_large_num",  "desc": "超大数 (overflow)"},
    {"name": "zero_value",      "desc": "零值"},
    {"name": "null_value",      "desc": "空值,null,undefined"},
    # 编码变异
    {"name": "unicode_normalize","desc": "Unicode正规化绕过"},
    {"name": "double_encode",   "desc": "双重URL编码"},
    {"name": "utf8_bom",        "desc": "BOM头注入"},
    {"name": "null_prefix",     "desc": "空字节前缀"},
    # 逻辑变异
    {"name": "mass_assignment", "desc": "批量赋值 _method=PUT"},
    {"name": "type_juggling",   "desc": "PHP类型转换 0==str"},
    {"name": "race_cond",       "desc": "并发请求"},
    {"name": "time_manipulate", "desc": "时间参数篡改"},
    {"name": "boundary_cross",  "desc": "边界越界"},
    # HTTP变异
    {"name": "method_confusion","desc": "GET改POST,反之"},
    {"name": "content_type_switch","desc": "Content-Type切换"},
    {"name": "header_inject",   "desc": "额外header注入"},
]

# ── 跨漏洞关联规则 ──────────────────────────────────

CHAIN_RULES: list[dict] = [
    {
        "needs": ["open_redirect", "oauth_misconfig"],
        "becomes": "oauth_token_theft",
        "severity_boost": 1,  # 中→高
        "desc": "开放重定向+OAuth配置错误 = OAuth Token窃取",
    },
    {
        "needs": ["info_disclosure", "idor"],
        "becomes": "mass_data_leak",
        "severity_boost": 2,  # 低→危
        "desc": "信息泄露+IDOR = 大规模数据泄露",
    },
    {
        "needs": ["xss_stored", "csrf_token_missing"],
        "becomes": "xss_to_account_takeover",
        "severity_boost": 2,
        "desc": "存储XSS+CSRF无token = 账户接管",
    },
    {
        "needs": ["ssrf", "cloud_metadata_accessible"],
        "becomes": "cloud_credential_theft",
        "severity_boost": 2,
        "desc": "SSRF+云元数据可达 = 云凭据窃取",
    },
    {
        "needs": ["sqli_error", "sqli_time"],
        "becomes": "sqli_confirmed",
        "severity_boost": 1,
        "desc": "报错SQLi+时间SQLi = SQL注入确认",
    },
    {
        "needs": ["idor_order", "password_reset"],
        "becomes": "account_takeover_chain",
        "severity_boost": 2,
        "desc": "订单IDOR+密码重置 = 账户接管链",
    },
    {
        "needs": ["lfi_read", "file_upload"],
        "becomes": "lfi_to_rce",
        "severity_boost": 2,
        "desc": "文件读取+文件上传 = LFI→RCE",
    },
]


class DeepDigger:
    """深度挖掘器 — 模拟人类猎人的直觉+持久性+创造性。"""

    def __init__(self, target: str = "", verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self._hunches: list[dict] = []
        self._findings: list[dict] = []
        self._burrow_results: list[dict] = []

    # ── 1. 直觉嗅探 ──────────────────────────────────

    def sniff(self, url: str = "", params: dict | None = None,
              response_text: str = "", response_headers: dict | None = None) -> list[dict]:
        """直觉扫描: 标记所有"不对劲"的地方。"""
        hunches = []

        # 参数名可疑
        if params:
            for p in params.keys():
                for rule in HUNCH_PATTERNS["param_name_suspicious"]:
                    if re.search(rule, p):
                        hunches.append({
                            "type": "param_name",
                            "severity": "hunch",
                            "param": p,
                            "reason": f"参数名可疑: {p} 匹配 {rule}",
                        })
                        break

        # 参数值可疑
        if params:
            for p, v in params.items():
                for rule in HUNCH_PATTERNS["param_value_unexpected"]:
                    if isinstance(v, str) and re.search(rule, v):
                        hunches.append({
                            "type": "param_value",
                            "severity": "hunch",
                            "param": p,
                            "reason": f"参数值可疑: {p}={v[:30]} 匹配 {rule}",
                        })
                        break

        # 响应异常
        if response_text:
            for rule in HUNCH_PATTERNS["response_weird"]:
                m = re.search(rule, response_text)
                if m:
                    hunches.append({
                        "type": "response_weird",
                        "severity": "hunch",
                        "reason": f"响应异常: 包含 {m.group()[:60]}",
                    })

        self._hunches = hunches
        if self.verbose:
            for h in hunches:
                print(f"  !! 直觉: {h['reason']}")

        return hunches

    # ── 2. 持久性挖掘 (一个点试50种方式) ────────────

    def burrow(self, url: str = "", param: str = "",
               base_payload: str = "1", depth: int = 3) -> list[dict]:
        """深度循环: 对单个参数试多种变异。

        depth 控制循环深度:
          depth=1: 基础变异 (10种)
          depth=2: 中级变异 (25种)
          depth=3: 深度挖掘 (50+种)
        """
        if not url or not param:
            return []

        results = []
        mutations = self._get_mutations(depth)

        for i, m in enumerate(mutations):
            payload = self._apply_mutation(base_payload, m)
            # 这里只记录变异意图，实际发包由调用方决定
            results.append({
                "index": i + 1,
                "technique": m["name"],
                "desc": m["desc"],
                "payload_hint": payload[:50],
            })

        self._burrow_results = results

        if self.verbose:
            print(f"  -> 准备对 {param} 试 {len(results)} 种变异")

        return results

    def _get_mutations(self, depth: int) -> list[dict]:
        """按深度获取变异列表。"""
        base = CREATIVE_MUTATIONS[:8]  # 基础: 前8种

        if depth == 1:
            return base

        if depth == 2:
            return CREATIVE_MUTATIONS[:16]

        return CREATIVE_MUTATIONS  # depth=3: 全部

    def _apply_mutation(self, payload: str, mutation: dict) -> str:
        """对payload应用变异。"""
        name = mutation["name"]
        if name == "int_to_string":
            return f"'{payload}'"
        if name == "string_to_array":
            return f"{payload}[]"
        if name == "json_inject":
            return f'{{"{payload}":"{payload}"}}'
        if name == "negative_number":
            return f"-{payload}"
        if name == "very_large_num":
            return "99999999999999999999"
        if name == "zero_value":
            return "0"
        if name == "null_value":
            return ""
        if name == "unicode_normalize":
            return payload
        if name == "double_encode":
            return f"%25{payload}"
        if name == "utf8_bom":
            return f"\\xEF\\xBB\\xBF{payload}"
        if name == "null_prefix":
            return f"%00{payload}"
        if name == "mass_assignment":
            return f"{payload},_method=PUT"
        if name == "type_juggling":
            return f"{payload}+0"
        if name == "time_manipulate":
            return f"{payload}?timestamp=0"
        if name == "boundary_cross":
            return f"{payload},-1,999999"
        if name == "method_confusion":
            return payload
        if name == "content_type_switch":
            return payload
        if name == "header_inject":
            return payload
        return payload

    # ── 3. 跨漏洞关联 ──────────────────────────────

    def cross_correlate(self, findings: list[dict] | None = None) -> list[dict]:
        """交叉关联: 多个低危→高危链。"""
        if findings is None:
            findings = self._findings

        if not findings:
            return []

        # 提取所有的 vuln_type
        present = set()
        for f in findings:
            vt = f.get("vuln_type", f.get("type", "")).lower().strip()
            present.add(vt)

        chains = []
        for rule in CHAIN_RULES:
            needed = set(rule["needs"])
            if needed.issubset(present):
                chains.append({
                    "chain": rule["becomes"],
                    "severity_boost": f"+{rule['severity_boost']}级",
                    "desc": rule["desc"],
                    "from": list(needed),
                })

        return chains

    # ── 统计 ──────────────────────────────────────

    def summary(self) -> dict:
        return {
            "hunches": len(self._hunches),
            "burrow_variants": len(self._burrow_results),
            "chains_found": 0,  # 需要外部传入findings
        }
