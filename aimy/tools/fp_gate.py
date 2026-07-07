#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FP_Gate — 误报过滤门 (False Positive Gate)

用法:
    from aimy.tools.fp_gate import FPGate
    gate = FPGate()
    ok, reason = gate.filter(vuln_class="sqli", url="http://x?id=1",
                              payload="1 AND 1=1", response_size=20237,
                              response_text="<html>...")
    if not ok:
        print(f"FP KILL: {reason}")

设计目标:
    - 零误报：只有确认的才放行
    - 在检测器→报告之间加一道门
    - 所有检测器共用同一套过滤逻辑
    - 不增加网络请求（只分析已有数据）
"""

import re

# ── Kill List: 技术上存在但业务上不值得报的模式 ──
# 顶级白客遇到这些直接跳过，不浪费时间写报告
KILL_LIST_PATTERNS: list[dict] = [
    # 反射XSS (除非能证明有实际影响)
    {"vuln_class": "xss",  "pattern": "alert|prompt|confirm",
     "reason": "反射XSS不证明影响=低危, 除非能链ATO"},
    # 开放重定向 (除非能链OAuth)
    {"vuln_class": "open_redirect", "pattern": "",
     "reason": "开放重定向单洞=低危, 除非能链OAuth Token窃取"},
    # 信息泄露 (除非含PII/凭据)
    {"vuln_class": "information_disclosure", "pattern": "version|server|stack trace|debug",
     "reason": "版本信息/报错信息泄露=低危, 除非包含真实PII"},
    # 缺少安全头
    {"vuln_class": "missing_header", "pattern": "",
     "reason": "缺少安全头=信息性, 不报"},
    # CSP绕过 (除非能执行)
    {"vuln_class": "csp_bypass", "pattern": "",
     "reason": "CSP配置问题=低危, 除非有XSS配合"},
    # 点击劫持
    {"vuln_class": "clickjacking", "pattern": "",
     "reason": "纯点击劫持(无XSS配合)=低危"},
    # 理论风险
    {"vuln_class": "theoretical", "pattern": "",
     "reason": "理论风险无实际影响=不报"},
]

# 认证墙特征（正文片段）
AUTH_WALL_TOKENS = [
    "login", "sign in", "signin", "log in",
    "password", "username", "验证码", "登录", "登陆",
    "verifycode", "captcha",
    "forgot", "reset password", "记住我",
    "welcome back", "member login", "会员登录",
]


class FPGate:
    """误报过滤门。"""

    # 各漏洞类的确认必要条件
    RULES: dict[str, list[str]] = {
        "sqli":              ["diff_size", "no_auth_wall"],
        "blind_sqli":        ["diff_size", "no_auth_wall"],
        "xss":               ["reflect_self", "no_auth_wall"],
        "ssrf":              ["oob_callback", "no_auth_wall"],
        "ssti":              ["math_confirm", "no_auth_wall"],
        "cmdi":              ["time_diff", "oob_callback", "no_auth_wall"],
        "lfi":               ["file_content", "no_auth_wall"],
        "idor":              ["cross_session", "no_auth_wall"],
        "open_redirect":     ["redirect_diff", "no_auth_wall"],
        "information_disclosure": ["pattern_match"],
    }

    def __init__(self):
        self._stats = {"passed": 0, "killed": 0, "reasons": {}}

    def _is_auth_wall(self, text: str) -> bool:
        """检测响应是否为登录页。"""
        if not text:
            return False
        low = text.lower()
        hits = sum(1 for t in AUTH_WALL_TOKENS if t in low)
        return hits >= 3  # 3个以上特征命中判定为登录页

    def filter(
        self,
        vuln_class: str = "",
        payload: str = "",
        response_size: int = 0,
        response_text: str = "",
        true_size: int = 0,
        false_size: int = 0,
        has_oob: bool = False,
        has_reflect: bool = False,
        math_confirm: bool = False,
        baseline_size: int = 0,
    ) -> tuple[bool, str]:
        """误报过滤。返回 (通过?, 原因)。

        参数说明:
            response_size:   payload请求的响应大小
            response_text:   payload请求的响应内容(用于认证墙检测)
            true_size:       布尔盲注true条件响应大小
            false_size:      布尔盲注false条件响应大小
            has_oob:         OOB回调是否收到
            has_reflect:     payload是否在响应中反射
            math_confirm:    SSTI二次确认是否通过
            baseline_size:   无害基线请求响应大小
        """
        vc = vuln_class.lower().strip()

        # ── 通用过滤（所有漏洞类） ─────────────────

        # 1. 认证墙检测
        if response_text and self._is_auth_wall(response_text):
            self._kill("auth_wall", vc)
            return False, "auth_wall: 响应为登录页/认证墙"

        # 2. Kill List: 技术上存在但业务上不值得报
        for kl in KILL_LIST_PATTERNS:
            if vc == kl["vuln_class"] or (kl["pattern"] and re.search(kl["pattern"], str(response_text or ""), re.I)):
                self._kill("kill_list", vc)
                return False, f"kill_list: {kl['reason']}"

        # ── 按漏洞类过滤 ──────────────────────────

        if vc in ("sqli", "blind_sqli"):
            # SQL盲注：true≠false 且 一边≈基线/一边远离
            if true_size and false_size:
                diff = abs(true_size - false_size)
                if diff < 50:  # 提高阈值到50B
                    return False, f"sqli: true/false差值太小 ({diff}b)"
                if baseline_size:
                    tv = abs(true_size - baseline_size)
                    fv = abs(false_size - baseline_size)
                    # 必须一边≈基线(true正常)一边远离(false被拦截)
                    # 必须一边≈基线(true正常)一边远离(false被拦截)
                    near_baseline = min(tv, fv)
                    far_from_baseline = max(tv, fv)
                    if near_baseline < 50 and far_from_baseline < 200:
                        return False, f"sqli: true/false都靠近基线 (near={near_baseline}b/far={far_from_baseline}b)"
                    if near_baseline > 200:
                        return False, f"sqli: true/false都远离基线 (near={near_baseline}b/far={far_from_baseline}b)"
                self._pass(vc)
                return True, f"sqli: boolean diff confirmed ({diff}b)"
            return False, "sqli: 缺少true/false对比数据"

        if vc == "ssti":
            if not math_confirm:
                return False, "ssti: 缺少二次确认 ({{7*7}}→49 + {{7*6}}→42)"
            self._pass(vc)
            return True, "ssti: math double-confirmed"

        if vc == "xss":
            if not has_reflect:
                return False, "xss: payload未在响应中反射"
            self._pass(vc)
            return True, "xss: payload reflected"

        if vc == "ssrf":
            if not has_oob:
                return False, "ssrf: 无OOB回调"
            self._pass(vc)
            return True, "ssrf: OOB callback confirmed"

        if vc == "cmdi":
            if not has_oob:
                return False, "cmdi: 无OOB或时间确认"
            self._pass(vc)
            return True, "cmdi: OOB/time confirmed"

        if vc == "lfi":
            if not response_text:
                return False, "lfi: 无响应内容"
            # 检查常见文件特征
            signals = ["root:", "bin:", "daemon:", "nobody:",
                       "[extensions]", "[fonts]", "boot loader",
                       "<?php", "<?=", "<%@"]
            if any(s in response_text for s in signals):
                self._pass(vc)
                return True, "lfi: file content pattern matched"
            return False, "lfi: 响应中无文件内容特征"

        if vc == "open_redirect":
            if not has_reflect:
                return False, "open_redirect: 无跳转"
            self._pass(vc)
            return True, "open_redirect: redirect confirmed"

        # 未知类型：放行但记录
        self._pass(vc)
        return True, "unknown_vuln_class: passed"

    def _kill(self, reason: str, vc: str):
        self._stats["killed"] += 1
        self._stats["reasons"][reason] = self._stats["reasons"].get(reason, 0) + 1

    def _pass(self, vc: str):
        self._stats["passed"] += 1

    def stats(self) -> dict:
        return dict(self._stats)

    def reset_stats(self):
        self._stats = {"passed": 0, "killed": 0, "reasons": {}}


# ── 快捷函数 ──────────────────────────────────────

_gate: FPGate | None = None


def fp_filter(**kw) -> tuple[bool, str]:
    """快捷调用。"""
    global _gate
    if _gate is None:
        _gate = FPGate()
    return _gate.filter(**kw)


def fp_stats() -> dict:
    """获取FP门统计。"""
    global _gate
    if _gate is None:
        return {}
    return _gate.stats()
