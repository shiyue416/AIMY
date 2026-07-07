#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ReportAssembler — 漏洞报告自动组装器

整合 ImpactEscalator + PoCGenerator + 证据 → SRC/H1格式完整报告。
顶级白客和普通白客的差距: 报告质量决定通过率和赏金。

用法:
    from aimy.tools.report_assembler import ReportAssembler
    ra = ReportAssembler()
    report = ra.assemble(
        vuln_class="sqli",
        title="SQL注入 in Show.asp?pkid= allows 布尔盲注提取数据库内容",
        url="http://target.com/Show.asp?pkid=4955",
        param="pkid",
        evidence="TRUE=20237B FALSE=179B 差异20058B",
        impact="可提取20万用户手机号+密码哈希",
        poc_script="/tmp/poc_sqli.py",
    )
    print(report)
"""

from datetime import datetime


class ReportAssembler:
    """报告组装器 — 自动生成SRC/H1格式漏洞报告."""

    # CVSS 4.0 快速映射
    CVSS_MAP: dict[str, dict] = {
        "critical": {
            "sqli": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "ssrf": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            "rce":  "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "high": {
            "sqli": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "idor": "CVSS:4.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
            "xss":  "CVSS:4.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        },
        "medium": {
            "xss":  "CVSS:4.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "csrf": "CVSS:4.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        },
    }

    # 修复建议
    REMEDIATION: dict[str, str] = {
        "sqli": """使用参数化查询(PreparedStatement)或ORM框架。
避免拼接SQL语句。对输入做严格的类型校验和转义。
实施最小权限原则, 数据库账户不应使用sa/root。""",
        "xss": """对输出进行HTML实体编码。
设置Content-Security-Policy响应头。
使用X-XSS-Protection头。
对用户输入做白名单过滤。""",
        "ssrf": """白名单允许的域名/IP列表。
禁止访问内网地址段(127.0.0.1, 10.x, 172.16.x, 192.168.x, 169.254.x)。
禁用不必要的URL重定向和协议(DICT/Gopher/File)。
使用独立的SSRF缓解网络策略。""",
        "idor": """实施对象级别的访问控制检查。
不依赖不可预测的ID作为安全控制手段。
使用UUID替代自增数字ID。
每次API请求验证用户对资源的访问权限。""",
        "lfi": """白名单允许的文件路径和扩展名。
禁止用户输入直接拼接到文件路径中。
使用chroot/jail隔离文件系统访问。""",
        "cmdi": """避免直接调用系统命令。
使用安全的API替代exec/system/popen。
对必要命令做白名单参数校验。""",
        "ssti": """避免将用户输入直接传给模板引擎。
使用沙箱模式运行模板引擎。
对模板内容做严格的输入过滤。""",
        "auth_bypass": """对所有需要认证的页面/API做服务端权限校验。
不依赖前端隐藏或disabled字段做访问控制。
实施统一的认证中间件。""",
        "business_logic": """业务逻辑需要在服务端做完整校验。
关键操作(支付/提现/下单)需要幂等性和事务保护。
对金额、数量等关键参数做服务端验证。""",
        "race_condition": """使用数据库事务和锁机制。
关键操作加分布式锁。
实施请求队列和去重机制。""",
        "information_disclosure": """移除调试信息和错误详情。
配置Web服务器隐藏版本号。
敏感信息(密钥/token)使用环境变量存储。""",
        "open_redirect": """白名单允许的重定向域名。
使用映射ID替代原始URL进行重定向。
禁止未经验证的URL参数跳转。""",
        "jwt": """使用强密钥签名JWT。
验证alg头, 禁止none算法。
设置合理的过期时间。
使用JWT标准库实现。""",
    }

    def __init__(self, hunter_name: str = ""):
        self.hunter_name = hunter_name or "aimy-skill"

    def assemble(self,
                 vuln_class: str = "",
                 title: str = "",
                 url: str = "",
                 param: str = "",
                 payload: str = "",
                 evidence: str = "",
                 impact: str = "",
                 poc_script: str = "",
                 steps: str = "",
                 severity: str = "high",
                 ) -> str:
        """组装完整漏洞报告。

        Returns:
            str: SRC/H1格式报告文本
        """
        vc = vuln_class.lower().strip()
        now = datetime.now().strftime("%Y-%m-%d")

        # 严重度
        severity_upper = severity.upper()

        # CVSS
        cvss = self.CVSS_MAP.get(severity, {}).get(vc, "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")

        # 修复建议
        remediation = self.REMEDIATION.get(vc, "参考OWASP官方修复指南。")

        # 复现步骤
        if not steps:
            steps = self._default_steps(vc, url, param, payload)

        # 影响描述
        if not impact:
            impact = self._default_impact(vc)

        # 组装报告
        report = f"""# 漏洞报告

## 漏洞标题
{title}

## 漏洞类型
{vc.upper()} — {severity_upper}

## 严重等级
{severity_upper}

## CVSS 4.0
{cvss}

## 受影响端点
{url}

## 受影响参数
{param}

## 漏洞描述
在 {url} 的 {param} 参数存在 {vc} 漏洞。
{impact}

## 复现步骤

{steps}

## 证据
{evidence}

## PoC
{poc_script if poc_script else "见附件"}

## 修复建议
{remediation}

## 发现者
{self.hunter_name}

## 发现时间
{now}
"""
        return report

    def _default_steps(self, vc: str, url: str, param: str, payload: str) -> str:
        steps_map = {
            "sqli": f"""1. 访问 {url}
2. 在 {param} 参数后添加 ` AND 1=1`（条件为真）→ 返回正常页面
3. 在 {param} 参数后添加 ` AND 1=2`（条件为假）→ 返回不同内容
4. 响应差异证明SQL注入存在
5. 利用布尔盲注逐字提取数据库内容""",
            "xss": f"""1. 在 {param} 参数注入 `<script>alert(1)</script>`
2. 查看响应中payload是否被反射
3. 在浏览器中打开确认JavaScript执行""",
            "ssrf": f"""1. 将 {param} 参数设置为内网地址 http://127.0.0.1:80
2. 观察是否有响应延迟或不同响应
3. 使用OOB平台确认服务端发起了请求""",
            "idor": f"""1. 登录获取合法session
2. 访问 {url}
3. 修改ID参数为相邻值
4. 若能访问其他用户数据则存在IDOR""",
        }
        return steps_map.get(vc, f"1. 在 {param} 参数注入测试payload\n2. 观察响应变化")

    def _default_impact(self, vc: str) -> str:
        impact_map = {
            "sqli": "攻击者可利用SQL注入提取数据库中的用户敏感信息（手机号、邮箱、密码哈希），导致大规模数据泄露。",
            "xss": "攻击者可构造恶意链接窃取用户会话Cookie，实现账户接管。",
            "ssrf": "攻击者可访问内部云元数据服务获取IAM凭据，进而控制整个云账号。",
            "idor": "攻击者可遍历ID访问其他用户的敏感数据。",
            "lfi": "攻击者可读取服务器任意文件，包括源代码和配置文件。",
            "cmdi": "攻击者可在服务器上执行任意系统命令，获得完整控制权。",
            "ssti": "攻击者可利用模板引擎注入执行任意代码。",
        }
        return impact_map.get(vc, "该漏洞可被攻击者利用造成数据泄露或权限提升。")
