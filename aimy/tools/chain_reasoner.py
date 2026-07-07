#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ChainReasoner — 动态链式推理引擎 (非固定规则)

顶级白客 vs 普通白客的核心差距:
  普通: 发现一个洞, 报一个洞, 下一个
  顶级: "我找到了X → X能让我拿到Y → Y能帮我打到Z → 链成了P1"

  静态规则(你现在的): SSRF + 云元数据 = 云凭据窃取 (7条预设)
  动态推理(这个文件): "你拿到了SSRF → 试试读云元数据 → 拿到了IAM → 试试控制台"
                        → 每一步基于上一步的实际结果动态推荐

用法:
    from aimy.tools.chain_reasoner import ChainReasoner
    cr = ChainReasoner()
    next_steps = cr.reason(current_finding={"vuln_class": "ssrf", "access": "network"})
    # -> [{"action": "读云元数据", "target": "169.254.169.254", ...},
    #     {"action": "扫描内网", "target": "127.0.0.1:8080", ...}]
"""

from typing import Any, Optional
from dataclasses import dataclass, field


# ── 漏洞能力模型 ──────────────────────────────────

@dataclass
class Finding:
    """一个漏洞发现的能力模型。"""
    vuln_class: str
    what_you_can_do: str               # 你能做什么
    access_level: str = ""             # read/write/shell/network
    data_type: str = ""                # 你能接触什么数据
    authentication: str = ""           # 是否需要认证
    protocol: str = "http"             # 协议
    notes: str = ""


# ── 能力→下一步映射（基于MITRE ATT&CK思路的推理规则） ──

# 能力推理: 你有了什么 → 你可以试什么
ABILITY_CHAINS: list[dict] = [
    # ── SSRF 链 ──
    {
        "need":     {"vuln_class": "ssrf", "access_level": "network"},
        "try":      {"vuln_class": "ssrf", "target": "cloud_metadata"},
        "if_works": {"vuln_class": "credential_access", "access_level": "read"},
        "desc":     "SSRF → 读云元数据 → IAM凭据",
        "next":     "拿到IAM凭据后 → 试云控制台API",
    },
    {
        "need":     {"vuln_class": "ssrf", "access_level": "network"},
        "try":      {"vuln_class": "ssrf", "target": "internal_port_scan"},
        "if_works": {"vuln_class": "internal_recon", "access_level": "network"},
        "desc":     "SSRF → 扫描内网端口 → 发现内部服务",
        "next":     "发现内部服务 → 试内部API的漏洞",
    },
    {
        "need":     {"vuln_class": "ssrf", "access_level": "read"},
        "try":      {"vuln_class": "lfi", "target": "cloud_credential_file"},
        "if_works": {"vuln_class": "credential_access"},
        "desc":     "SSRF读取文件 → 找到云凭据 → 控制云资源",
        "next":     "有凭据 → 试云控制台/数据库",
    },
    # ── SQLi 链 ──
    {
        "need":     {"vuln_class": "sqli", "access_level": "read"},
        "try":      {"vuln_class": "sqli", "target": "extract_admin_creds"},
        "if_works": {"vuln_class": "credential_access"},
        "desc":     "SQLi读数据 → 提取管理员凭据 → 登录后台",
        "next":     "进后台 → 试文件上传/RCE",
    },
    {
        "need":     {"vuln_class": "sqli", "access_level": "read"},
        "try":      {"vuln_class": "sqli", "target": "extract_user_pii"},
        "if_works": {"vuln_class": "data_breach"},
        "desc":     "SQLi读数据 → 提取用户PII → 数据泄露",
        "next":     "有大量用户数据 → 证明GDPR违规影响",
    },
    {
        "need":     {"vuln_class": "sqli", "access_level": "write"},
        "try":      {"vuln_class": "sqli", "target": "write_webshell"},
        "if_works": {"vuln_class": "rce"},
        "desc":     "SQLi能写文件 → 写webshell → RCE",
        "next":     "RCE → 内网横向移动",
    },
    # ── IDOR 链 ──
    {
        "need":     {"vuln_class": "idor", "access_level": "read"},
        "try":      {"vuln_class": "idor", "target": "mass_enumerate"},
        "if_works": {"vuln_class": "data_breach"},
        "desc":     "IDOR读一个 → 遍历ID → 批量泄露",
        "next":     "看同端口的PUT/DELETE → 试越权写",
    },
    {
        "need":     {"vuln_class": "idor", "access_level": "read"},
        "try":      {"vuln_class": "idor", "target": "admin_function"},
        "if_works": {"vuln_class": "privilege_escalation"},
        "desc":     "IDOR读用户数据 → 看到管理员功能 → 越权",
        "next":     "拿到管理员权限 → 全站控制",
    },
    # ── XSS 链 ──
    {
        "need":     {"vuln_class": "xss", "access_level": "read"},
        "try":      {"vuln_class": "xss", "target": "cookie_theft"},
        "if_works": {"vuln_class": "session_hijack"},
        "desc":     "XSS → 窃取Cookie → Session劫持",
        "next":     "拿到Session → 试越权/提权",
    },
    {
        "need":     {"vuln_class": "xss_stored", "access_level": "read"},
        "try":      {"vuln_class": "xss", "target": "admin_hijack"},
        "if_works": {"vuln_class": "account_takeover"},
        "desc":     "存储XSS → 等待管理员访问 → 窃取管理员Session",
        "next":     "拿到管理员权限 → 全站控制",
    },
    # ── LFI 链 ──
    {
        "need":     {"vuln_class": "lfi", "access_level": "read"},
        "try":      {"vuln_class": "lfi", "target": "log_poison"},
        "if_works": {"vuln_class": "rce"},
        "desc":     "LFI读文件 → 日志污染 → RCE",
        "next":     "RCE → 内网横向移动",
    },
    {
        "need":     {"vuln_class": "lfi", "access_level": "read"},
        "try":      {"vuln_class": "lfi", "target": "source_code"},
        "if_works": {"vuln_class": "information_disclosure"},
        "desc":     "LFI读源码 → 在源码中发现更多0day",
        "next":     "源码里的凭据/API密钥 → 扩大攻击面",
    },
    # ── Open Redirect 链 ──
    {
        "need":     {"vuln_class": "open_redirect"},
        "try":      {"vuln_class": "open_redirect", "target": "oauth_token"},
        "if_works": {"vuln_class": "account_takeover"},
        "desc":     "开放重定向 → 窃取OAuth回调Token → ATO",
        "next":     "ATO → 看账户权限",
    },
    # ── 认证绕过 链 ──
    {
        "need":     {"vuln_class": "auth_bypass"},
        "try":      {"vuln_class": "auth_bypass", "target": "admin_panel"},
        "if_works": {"vuln_class": "privilege_escalation"},
        "desc":     "认证绕过 → 试着访问后台 → 提权",
        "next":     "进后台 → 文件上传/RCE",
    },
    # ── GraphQL 链 ──
    {
        "need":     {"vuln_class": "graphql_introspection"},
        "try":      {"vuln_class": "graphql", "target": "field_auth_test"},
        "if_works": {"vuln_class": "data_breach"},
        "desc":     "GraphQL introspection → 遍历所有字段 → 无权限字段泄露数据",
        "next":     "找到敏感字段 → 批量查询",
    },
    # ── 业务逻辑 链 ──
    {
        "need":     {"vuln_class": "business_logic"},
        "try":      {"vuln_class": "business_logic", "target": "race_condition"},
        "if_works": {"vuln_class": "financial_loss"},
        "desc":     "业务逻辑缺陷 → 试试并发请求 → 提现/优惠券多次使用",
        "next":     "能重复用 → 证明经济损失",
    },
]


class ChainReasoner:
    """动态链式推理引擎。

    用法:
        cr = ChainReasoner()
        # 你找到了一个SSRF
        chains = cr.reason([{"vuln_class": "ssrf", "access_level": "network"}])
        for step in chains:
            print(f"下一步: {step['desc']}")
    """

    def __init__(self):
        self._history: list[dict] = []

    def reason(self, findings: list[dict]) -> list[dict]:
        """基于已有发现推理下一步。

        Args:
            findings: 已有发现列表, 每个包含 vuln_class 和 access_level

        Returns:
            [{"action": "...", "target": "...", "desc": "...",
              "if_works": "...", "next": "...", "priority": 1}, ...]
        """
        # 构建已有能力集合
        have = set()
        for f in findings:
            vc = f.get("vuln_class", "").lower()
            al = f.get("access_level", "").lower()
            have.add(vc)
            if al:
                have.add(f"{vc}:{al}")

        suggestions = []
        seen = set()

        for rule in ABILITY_CHAINS:
            need = rule["need"]
            needed_vc = need.get("vuln_class", "")
            needed_al = need.get("access_level", "")

            # 检查是否满足前提条件
            if needed_vc not in have:
                continue
            if needed_al and f"{needed_vc}:{needed_al}" not in have and needed_al not in have:
                continue

            # 避免重复推荐
            suggest_key = f"{rule['try']['vuln_class']}:{rule['try'].get('target', '')}"
            if suggest_key in seen:
                continue
            seen.add(suggest_key)

            suggestions.append({
                "from": needed_vc,
                "action": rule["try"]["vuln_class"],
                "target": rule["try"].get("target", "generic"),
                "desc": rule["desc"],
                "if_works": rule["if_works"]["vuln_class"],
                "next": rule.get("next", ""),
                "priority": len(suggestions) + 1,
            })

        # 按优先级排序
        # 优先推荐: rce > credential > privilege > data_breach > 其他
        priority_map = {
            "rce": 0, "credential_access": 1, "privilege_escalation": 2,
            "data_breach": 3, "account_takeover": 4, "financial_loss": 5,
        }
        suggestions.sort(key=lambda x: priority_map.get(x["if_works"], 99))

        return suggestions

    def chain_graph(self, findings: list[dict]) -> str:
        """生成链式攻击路径文本。"""
        chains = self.reason(findings)
        if not chains:
            return "当前发现无可用链式升级路径"

        lines = ["攻击链推理:", "=" * 40]
        for c in chains:
            lines.append(f"  [{c['priority']}] {c['desc']}")
            lines.append(f"      如果成功: 拿到 {c['if_works']}")
            lines.append(f"      再下一步: {c['next']}")
            lines.append("")
        return "\n".join(lines)

    def suggest_next_test(self, finding: dict) -> str:
        """对单个发现给出下一步测试建议。"""
        vc = finding.get("vuln_class", "").lower()
        tips = {
            "ssrf": "下一步: 试读云元数据(169.254.169.254), 再扫内网端口",
            "sqli": "下一步: 提admin凭据, 找写文件机会, 读源码",
            "idor": "下一步: 批量遍历, 试同端口的PUT/DELETE, 找管理员功能",
            "xss":  "下一步: 试cookie窃取, 找管理员访问的存储XSS",
            "xss_stored": "下一步: 等管理员触发, 窃取Session",
            "lfi":  "下一步: 日志污染→RCE, 读源码找更多洞",
            "open_redirect": "下一步: 找OAuth登录页用redirect_uri窃取Token",
            "auth_bypass": "下一步: 访问后台admin功能, 找文件上传",
            "cmdi": "下一步: 反弹Shell, 内网横向",
            "ssti": "下一步: RCE, 读配置",
            "business_logic": "下一步: 加并发试竞态条件, 改参数值",
            "graphql_introspection": "下一步: 逐个字段查, 找无权限字段",
        }
        return tips.get(vc, "下一步: 对同类端点批量测试, 然后链式推理")
