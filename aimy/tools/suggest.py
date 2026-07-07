"""
Skill 智能推荐引擎 — 解决"什么时候用什么技能"的决策树问题。

将隐性知识显性化:
    - 场景 → Skill 推荐 + 优先级 + 理由
    - 技术栈感知: 根据目标框架/CMS/WAF 调整策略
    - 阶段感知: 不同 Phase 推荐不同 Skill
    - 漏洞关联: 知道先测什么后测什么

核心决策树 (Phase 3 Hunt 为例):
    有 WAF? → 先 fingerprint → waf_bypass payload
    有 JWT?  → jwt_detector
    有登录?  → auth_bypass → dual_session → biz_logic
    有文件上传? → upload_insecure_files → lfi_scanner (如果可写)
    有 API?  → api-recon-and-docs → graphql_scanner (如果 GraphQL)
    是 Java? → deserialization_detector → ssrf_detector
    是 PHP?  → lfi_scanner → sqli → deserialization_detector
    是 Node? → proto_pollution → ssti → jwt
    是 Python? → ssti_detector → sqli → ssrf

用法:
    from aimy.tools.suggest import suggest
    route = suggest(url="https://target.com", goal="full_audit")
    print(route.to_json())

CLI:
    python tools/suggest.py --url https://target.com --goal full_audit
"""

from __future__ import annotations

import json
import re
import sys
from typing import Dict, List, Optional

from aimy.tools.schemas import SkillRouteSchema, SkillPhase


VERSION = "1.0.0"


# ── 决策规则库 ─────────────────────────────────────────────────────────────

# 技术栈 → 优先检测的漏洞
TECH_VULN_MAP: Dict[str, List[str]] = {
    "java": ["deserialization", "ssrf", "sqli", "xxe", "log4j"],
    "spring": ["ssrf", "sqli", "actuator", "deserialization", "jwt"],
    "struts": ["rce", "sqli", "cmdi"],
    "php": ["sqli", "lfi", "deserialization", "file_upload"],
    "laravel": ["sqli", "deserialization", "ssti", "sqli"],
    "wordpress": ["sqli", "xss", "auth_bypass", "file_upload"],
    "drupal": ["sqli", "rce", "xss"],
    "node": ["prototype_pollution", "ssti", "jwt", "nosqli"],
    "express": ["nosqli", "jwt", "prototype_pollution", "ssti"],
    "python": ["ssti", "sqli", "ssrf", "cmdi"],
    "django": ["sqli", "ssti", "csrf", "idor"],
    "flask": ["ssti", "ssrf", "sqli"],
    "ruby": ["sqli", "ssrf", "deserialization", "cmdi"],
    "rails": ["sqli", "ssrf", "deserialization"],
    "go": ["sqli", "ssrf", "nosqli", "cmdi"],
    ".net": ["sqli", "xxe", "deserialization", "ssrf"],
    "graphql": ["graphql", "idor", "sqli", "auth_bypass"],
    "next.js": ["ssrf", "prototype_pollution", "jwt", "sqli"],
    "react": ["xss", "jwt", "idor", "csrf"],
    "vue": ["xss", "jwt", "idor", "csrf"],
    "nginx": ["path_traversal", "http_smuggling", "cache_poisoning"],
    "apache": ["path_traversal", "http_smuggling", "lfi"],
    "iis": ["path_traversal", "http_smuggling"],
    "aws": ["ssrf", "s3_bucket", "cloud_recon", "jwt"],
    "gcp": ["ssrf", "cloud_recon", "jwt"],
    "azure": ["ssrf", "cloud_recon", "jwt", "oauth"],
    "cloudflare": ["cdn_origin", "subdomain_takeover"],
    "fastly": ["cdn_origin", "subdomain_takeover"],
    "kong": ["auth_bypass", "http_smuggling", "jwt"],
    "kubernetes": ["ssrf", "cloud_recon", "jwt"],
}

# 漏洞 → 权威 Skill 映射
VULN_SKILL_MAP: Dict[str, str] = {
    "xss": "xss-cross-site-scripting",
    "sqli": "sqli-sql-injection",
    "ssrf": "ssrf-server-side-request-forgery",
    "idor": "idor-broken-object-authorization",
    "csrf": "csrf-cross-site-request-forgery",
    "cmdi": "cmdi-command-injection",
    "ssti": "ssti-server-side-template-injection",
    "xxe": "xxe-xml-external-entity",
    "lfi": "path-traversal-lfi",
    "path_traversal": "path-traversal-lfi",
    "deserialization": "deserialization-insecure",
    "jwt": "jwt-oauth-token-attacks",
    "oauth": "oauth-oidc-misconfiguration",
    "saml": "saml-sso-assertion-attacks",
    "graphql": "graphql-audit",
    "race_condition": "race-condition",
    "business_logic": "business-logic-vulnerabilities",
    "http_smuggling": "request-smuggling",
    "cache_poisoning": "web-cache-deception",
    "subdomain_takeover": "subdomain-takeover",
    "prototype_pollution": "prototype-pollution",
    "cors": "cors-cross-origin-misconfiguration",
    "open_redirect": "open-redirect",
    "llm": "llm-prompt-injection",
    "nosqli": "nosqli-detection",
    "file_upload": "upload-insecure-files",
    "auth_bypass": "authbypass-authentication-flaws",
    "rce": "cmdi-command-injection",
    "log4j": "log4j-rce-detection",
    "actuator": "spring-actuator-exposure",
    "cloud_recon": "cloud-reconnaissance",
    "s3_bucket": "cloud-reconnaissance",
    "cdn_origin": "cdn-origin-discovery",
}

# 漏洞 → 对应的 Python 工具
VULN_TOOL_MAP: Dict[str, str] = {
    "sqli": "sqlcheck",
    "xss": "xsscheck",
    "cmdi": "cmdi",
    "ssti": "ssti",
    "ssrf": "ssrf",
    "nosqli": "nosqli",
    "lfi": "lfi",
    "auth_bypass": "auth-bypass",
    "jwt": "jwt",
    "graphql": "graphql",
    "deserialization": "deser",
    "prototype_pollution": "proto-pollution",
    "cors": "cors",
    "race_condition": "logic-race",
    "business_logic": "bizlogic",
}

# WAF 类型 → 绕过策略 Skill
WAF_SKILL_MAP: Dict[str, str] = {
    "cloudflare": "waf-bypass-cloudflare",
    "akamai": "waf-bypass-akamai",
    "imperva": "waf-bypass-imperva",
    "f5": "waf-bypass-f5",
    "aws_waf": "waf-bypass-aws",
    "modsecurity": "waf-bypass-modsecurity",
    "generic": "waf-bypass",
}

# 阶段 → 默认技能（按顺序）
PHASE_SKILLS: Dict[SkillPhase, List[str]] = {
    SkillPhase.RECON: [
        "web2-recon", "api-recon-and-docs", "permutation-gen",
        "favicon-hunt", "asn-discovery", "csp-intel", "js-sourcemap",
    ],
    SkillPhase.MAP: [
        "attack-surface", "recon-ranker", "intel-engine", "param-classifier",
    ],
    SkillPhase.HUNT: [
        "bug-bounty", "web2-vuln-classes",
    ],
    SkillPhase.VALIDATE: [
        "triage-validation", "race-condition", "dual-session",
    ],
    SkillPhase.REPORT: [
        "report-writing",
    ],
}


# ── URL / Response 分析 ────────────────────────────────────────────────────


def _guess_tech_from_url(url: str) -> List[str]:
    """从 URL 模式推测技术栈"""
    techs = []
    url_lower = url.lower()

    patterns = {
        "wp-content": "wordpress",
        "wp-admin": "wordpress",
        "/wp-json": "wordpress",
        "drupal": "drupal",
        "joomla": "joomla",
        "/phpmyadmin": "php",
        "/.env": "php",
        ".php": "php",
        ".aspx": ".net",
        ".asp": ".net",
        ".jsp": "java",
        ".do": "java",
        "/spring-": "spring",
        "/actuator": "spring",
        "/graphql": "graphql",
        "/api/graphql": "graphql",
        "/_next": "next.js",
        "/__nextjs": "next.js",
        "/static/js/main.": "react",
        ".dll": ".net",
        "laravel": "laravel",
        "django": "django",
        "/admin/login/?next=": "django",
        "flask": "flask",
        "/rails/": "rails",
        "nginx": "nginx",
        ".s3.": "aws",
        "amazonaws.com": "aws",
        "cloudfront.net": "aws",
        "azurewebsites.net": "azure",
        "cloudfunctions.net": "gcp",
        "firebaseapp.com": "gcp",
        "workers.dev": "cloudflare",
    }

    for pattern, tech in patterns.items():
        if pattern in url_lower:
            techs.append(tech)

    return list(set(techs))


def _guess_tech_from_headers(headers: Dict[str, str]) -> List[str]:
    """从 HTTP 响应头推测技术栈"""
    techs = []
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()
    aspnet = headers.get("X-AspNet-Version", "")
    cf_ray = headers.get("CF-Ray", "")
    x_cache = headers.get("X-Cache", "").lower()

    header_map = {
        "nginx": "nginx",
        "apache": "apache",
        "iis": "iis",
        "cloudflare": "cloudflare",
        "express": "express",
        "gunicorn": "python",
        "uvicorn": "python",
        "waitress": "python",
        "tomcat": "java",
        "jetty": "java",
        "jboss": "java",
        "weblogic": "java",
        "websphere": "java",
    }

    for pattern, tech in header_map.items():
        if pattern in server or pattern in powered:
            techs.append(tech)

    if aspnet:
        techs.append(".net")

    if cf_ray:
        techs.append("cloudflare")

    if "fastly" in x_cache or "fastly" in server:
        techs.append("fastly")

    return list(set(techs))


# ── 推荐主函数 ─────────────────────────────────────────────────────────────


def suggest(
    url: str,
    goal: str = "full_audit",
    phase: SkillPhase = SkillPhase.HUNT,
    tech_stack: Optional[List[str]] = None,
    headers: Optional[Dict[str, str]] = None,
    waf_detected: Optional[str] = None,
    auth_required: bool = False,
    has_graphql: bool = False,
    has_api: bool = False,
    has_file_upload: bool = False,
    has_jwt: bool = False,
    veteran_mode: bool = True,
) -> SkillRouteSchema:
    """核心决策引擎 — 输入场景，输出推荐管线。

    Args:
        url: 目标 URL
        goal: 目标 ("full_audit", "find_sqli", "find_xss", "find_ssrf_rce", "recon_only", "quick_scan")
        phase: 当前阶段
        tech_stack: 已知技术栈 (如 ["php", "laravel"])
        headers: HTTP 响应头 dict
        waf_detected: WAF 类型 (cloudflare/akamai/imperva 等)
        auth_required: 是否需要认证
        has_graphql: 是否有 GraphQL 端点
        has_api: 是否有 REST API
        has_file_upload: 是否有文件上传功能
        has_jwt: 是否有 JWT token
        veteran_mode: 是否老鸟模式 (过滤低危)

    Returns:
        SkillRouteSchema: 推荐的路由决策
    """

    route = SkillRouteSchema(
        phase=phase,
        goal=goal,
        url=url,
        tech_stack=tech_stack or [],
        waf_detected=waf_detected,
        auth_required=auth_required,
    )

    # Step 1: 推测技术栈
    guessed_tech = list(tech_stack or [])
    guessed_tech.extend(_guess_tech_from_url(url))
    if headers:
        guessed_tech.extend(_guess_tech_from_headers(headers))
    route.tech_stack = list(set(guessed_tech)) or ["unknown"]

    skills: List[str] = []
    tools: List[str] = []
    reasons: List[str] = []

    # Step 2: 阶段基础技能
    phase_skills = PHASE_SKILLS.get(phase, [])
    skills.extend(phase_skills)
    reasons.append(f"[Phase {phase.value}] 加载阶段基础技能: {phase_skills[:3]}...")

    # Step 3: 目标驱动
    if goal == "full_audit":
        reasons.append("[Goal] 全面审计 → 全漏洞覆盖")
    elif goal == "find_ssrf_rce":
        reasons.append("[Goal] 聚焦 SSRF/RCE → P0 优先")
        skills.insert(0, VULN_SKILL_MAP.get("ssrf", ""))
        tools.insert(0, VULN_TOOL_MAP.get("ssrf", ""))
        skills.insert(1, VULN_SKILL_MAP.get("cmdi", ""))
        tools.insert(1, VULN_TOOL_MAP.get("cmdi", ""))
        # 同时屏蔽低危
        if veteran_mode:
            reasons.append("[Veteran] 已过滤 open_redirect | reflected_xss | info_disclosure")
    elif goal == "find_sqli":
        skills.insert(0, VULN_SKILL_MAP["sqli"])
        tools.insert(0, VULN_TOOL_MAP["sqli"])
        reasons.append("[Goal] SQLi 专项")
    elif goal == "find_xss":
        skills.insert(0, VULN_SKILL_MAP["xss"])
        tools.insert(0, VULN_TOOL_MAP["xss"])
        reasons.append("[Goal] XSS 专项")
    elif goal == "quick_scan":
        reasons.append("[Goal] 快速扫描 → 仅 P0+P1")
        route.complexity = "low"
        route.estimated_time_minutes = 15
    elif goal == "recon_only":
        route.phase = SkillPhase.RECON
        reasons.append("[Goal] 仅侦察")

    # Step 4: WAF 感知
    if waf_detected:
        waf_skill = WAF_SKILL_MAP.get(waf_detected.lower(), WAF_SKILL_MAP["generic"])
        skills.insert(0, waf_skill)
        tools.insert(0, "waf")
        reasons.append(f"[WAF] 检测到 {waf_detected} → 加载 {waf_skill} + waf_bypass 工具")
        route.complexity = "high"

    # Step 5: 功能感知
    if has_jwt:
        skills.insert(1, VULN_SKILL_MAP["jwt"])
        tools.insert(1, VULN_TOOL_MAP["jwt"])
        reasons.append("[Feature] JWT token → jwt_detector + jwt_exploiter")

    if has_graphql:
        skills.insert(1, VULN_SKILL_MAP["graphql"])
        tools.insert(1, VULN_TOOL_MAP["graphql"])
        reasons.append("[Feature] GraphQL 端点 → graphql_scanner")

    if has_file_upload:
        skills.append(VULN_SKILL_MAP["file_upload"])
        skills.append(VULN_SKILL_MAP["lfi"])
        tools.append(VULN_TOOL_MAP["lfi"])
        reasons.append("[Feature] 文件上传 → upload + LFI 联动")

    if auth_required:
        skills.insert(1, VULN_SKILL_MAP["auth_bypass"])
        tools.insert(0, "auth-bypass")
        tools.append("dual-session")
        reasons.append("[Feature] 认证系统 → auth_bypass + dual_session + biz_logic")

    # Step 6: 技术栈驱动（按优先级注入）
    tech_priorities: List[str] = []
    for tech in route.tech_stack:
        vulns = TECH_VULN_MAP.get(tech, [])
        for v in vulns:
            if v not in tech_priorities:
                tech_priorities.append(v)

    for v in tech_priorities[:8]:  # 前 8 个，避免技能爆炸
        if v in VULN_SKILL_MAP and VULN_SKILL_MAP[v] not in skills:
            skills.append(VULN_SKILL_MAP[v])
        if v in VULN_TOOL_MAP and VULN_TOOL_MAP[v] not in tools:
            tools.append(v)

    reasons.append(f"[TechStack] {route.tech_stack} → 优先: {tech_priorities[:5]}")

    # Step 7: 老鸟模式去噪
    if veteran_mode and goal == "full_audit":
        # 移除低危 skill
        filtered = ["open-redirect", "csrf-cross-site-request-forgery"]
        skills = [s for s in skills if s not in filtered]
        reasons.append("[Veteran] 已移除 open_redirect + CSRF skill (低赏金)")

    # 去重保持顺序
    seen_skills = set()
    route.recommended_skills = [s for s in skills if s and not (s in seen_skills or seen_skills.add(s))]
    seen_tools = set()
    route.recommended_tools = [t for t in tools if t and not (t in seen_tools or seen_tools.add(t))]

    route.rationale = " | ".join(reasons)

    # Step 8: 估算时间和复杂度
    if route.complexity == "high":
        route.estimated_time_minutes = max(route.estimated_time_minutes, 60)
    elif len(route.recommended_skills) > 15:
        route.complexity = "high"
        route.estimated_time_minutes = 90
    elif len(route.recommended_skills) > 8:
        route.complexity = "medium"
        route.estimated_time_minutes = 45
    else:
        route.complexity = route.complexity or "low"
        route.estimated_time_minutes = max(route.estimated_time_minutes, 20)

    return route


# ── CLI ────────────────────────────────────────────────────────────────────


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="AIMY Skill 智能推荐引擎 — 决策树显性化",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python suggest.py --url https://target.com --goal full_audit
  python suggest.py --url https://target.com --goal find_ssrf_rce --waf cloudflare
  python suggest.py --url https://target.com --tech php,laravel --auth
  python suggest.py --url https://target.com --phase recon
        """,
    )
    parser.add_argument("--url", required=True, help="目标 URL")
    parser.add_argument("--goal", default="full_audit",
                        choices=["full_audit", "find_ssrf_rce", "find_sqli", "find_xss",
                                "recon_only", "quick_scan"])
    parser.add_argument("--phase", default="hunt",
                        choices=["recon", "map", "hunt", "validate", "report"])
    parser.add_argument("--tech", help="已知技术栈 (逗号分隔: php,laravel,nginx)")
    parser.add_argument("--waf", help="WAF 类型 (cloudflare/akamai/imperva/f5/AWS)")
    parser.add_argument("--auth", action="store_true", help="需要认证")
    parser.add_argument("--graphql", action="store_true", help="有 GraphQL 端点")
    parser.add_argument("--api", action="store_true", help="有 REST API")
    parser.add_argument("--jwt", action="store_true", help="有 JWT Token")
    parser.add_argument("--upload", action="store_true", help="有文件上传功能")
    parser.add_argument("--rookie", action="store_true", help="菜鸟模式 (不过滤低危)")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    tech_stack = [t.strip() for t in args.tech.split(",")] if args.tech else None

    route = suggest(
        url=args.url,
        goal=args.goal,
        phase=SkillPhase(args.phase),
        tech_stack=tech_stack,
        waf_detected=args.waf,
        auth_required=args.auth,
        has_graphql=args.graphql,
        has_api=args.api,
        has_jwt=args.jwt,
        has_file_upload=args.upload,
        veteran_mode=not args.rookie,
    )

    if args.json:
        print(route.to_json())
    else:
        print("=" * 60)
        print(f"  AIMY Skill Router — 决策推荐")
        print(f"  目标: {args.url}")
        print(f"  阶段: {route.phase.value}  |  目标: {args.goal}")
        print(f"  推测技术栈: {route.tech_stack}")
        if args.waf:
            print(f"  WAF: {args.waf}")
        print(f"  复杂度: {route.complexity}  |  预估时间: {route.estimated_time_minutes} 分钟")
        print("=" * 60)
        print(f"\n  推理链:\n    {route.rationale}")
        print(f"\n  推荐 Skills ({len(route.recommended_skills)}):")
        for i, s in enumerate(route.recommended_skills, 1):
            print(f"    {i:2d}. {s}")
        print(f"\n  推荐 Tools ({len(route.recommended_tools)}):")
        for i, t in enumerate(route.recommended_tools, 1):
            print(f"    {i:2d}. {t}")
        print()


if __name__ == "__main__":
    main()
