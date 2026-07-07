"""
统一 JSON Schema — AIMY 所有模块的规范中间表示。

解决了 73 个工具输出格式不一致的问题：
  - 所有扫描器输出统一为 FindingSchema
  - 所有侦察工具输出统一为 AssetSchema
  - MCP 事件统一为 MCPEventSchema
  - Skill 路由决策统一为 SkillRouteSchema

使用方式:
    from aimy.tools.schemas import FindingSchema, validate_finding
    finding = FindingSchema(url="...", vuln_type="sqli", severity="critical")
    if validate_finding(finding):
        process(finding)

版本: 1.0.0
"""

from __future__ import annotations

import json
import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field, asdict


# ── Enums ──────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "information"


class Confidence(str, Enum):
    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


class VulnCategory(str, Enum):
    SSRF = "ssrf"
    RCE = "rce"
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    CMID = "cmdi"
    LFI = "lfi"
    IDOR = "idor"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    JWT = "jwt"
    OAUTH = "oauth"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    GRAPHQL = "graphql"
    RACE_CONDITION = "race_condition"
    CORS = "cors"
    HTTP_SMUGGLING = "http_smuggling"
    CACHE_POISONING = "cache_poisoning"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    BUSINESS_LOGIC = "business_logic"
    NOSQLI = "nosqli"
    FILE_UPLOAD = "file_upload"
    OPEN_REDIRECT = "open_redirect"
    LLM = "llm"
    INFO_DISCLOSURE = "info_disclosure"
    CONFIG = "config"
    OTHER = "other"


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    API_ENDPOINT = "api_endpoint"
    JS_FILE = "js_file"
    CLOUD_BUCKET = "cloud_bucket"
    GIT_REPO = "git_repo"
    CERTIFICATE = "certificate"
    ASN = "asn"
    CIDR = "cidr"
    FAVICON_HASH = "favicon_hash"
    CSP_DOMAIN = "csp_domain"
    MINIAPP = "miniapp"
    SOURCE_MAP = "source_map"


class MCPSource(str, Enum):
    BURP = "burp"
    FIDDLER = "fiddler"
    PLAYWRIGHT = "playwright"
    AIMY = "aimy"
    KALI = "kali"


class SkillPhase(str, Enum):
    RECON = "recon"
    MAP = "map"
    HUNT = "hunt"
    VALIDATE = "validate"
    REPORT = "report"


# ── Core Schemas ───────────────────────────────────────────────────────────


@dataclass
class FindingSchema:
    """漏洞发现 — 所有扫描器的统一输出格式。

    核心字段 (MUST):
        id: 唯一标识符 (sha256(url+vuln_type+param) 前16)
        url: 受影响 URL
        vuln_type: 漏洞类型 (VulnCategory)
        severity: 严重程度 (Severity)
        confidence: 置信度 (Confidence)
        title: 简短标题 (≤100 char)
        description: 详细描述
        timestamp: UTC 时间戳

    证据字段 (SHOULD):
        request_raw: 触发漏洞的 HTTP 请求
        response_raw: 存在漏洞证据的 HTTP 响应
        poc: 可复现的 PoC 步骤
        reproduction_rate: 复现成功率 (0.0-1.0)

    影响字段 (SHOULD):
        impact: 业务影响描述
        cvss_score: CVSS v3.1 评分 (0.0-10.0)
        cwe_id: CWE 编号 (如 "CWE-918")

    元数据字段 (MAY):
        param: 注入参数名
        payload: 触发载荷
        tags: 自由标签
        tool_source: 发现此漏洞的工具
        chain_id: 攻击链 ID (如多个低危串联成高危)

    过滤规则 (老鸟模式):
        vuln_type in (OPEN_REDIRECT, INFO_DISCLOSURE, CONFIG) → filtered
        severity == INFO → filtered
    """

    id: str
    url: str
    vuln_type: VulnCategory
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # 证据
    request_raw: Optional[str] = None
    response_raw: Optional[str] = None
    poc: Optional[str] = None
    reproduction_rate: Optional[float] = None

    # 影响
    impact: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None

    # 元数据
    param: Optional[str] = None
    payload: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    tool_source: Optional[str] = None
    chain_id: Optional[str] = None

    @staticmethod
    def make_id(url: str, vuln_type: str, param: str = "") -> str:
        raw = f"{url}|{vuln_type}|{param}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_filtered_veteran(self) -> bool:
        """老鸟模式过滤规则"""
        if self.severity == Severity.INFO:
            return True
        if self.vuln_type in (
            VulnCategory.OPEN_REDIRECT,
            VulnCategory.INFO_DISCLOSURE,
            VulnCategory.CONFIG,
        ):
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["vuln_type"] = self.vuln_type.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FindingSchema":
        return cls(
            id=d.get("id", cls.make_id(d["url"], d.get("vuln_type", "unknown"), d.get("param", ""))),
            url=d["url"],
            vuln_type=VulnCategory(d["vuln_type"]) if d.get("vuln_type") else VulnCategory.OTHER,
            severity=Severity(d["severity"]) if d.get("severity") else Severity.INFO,
            confidence=Confidence(d["confidence"]) if d.get("confidence") else Confidence.TENTATIVE,
            title=d.get("title", ""),
            description=d.get("description", ""),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            request_raw=d.get("request_raw"),
            response_raw=d.get("response_raw"),
            poc=d.get("poc"),
            reproduction_rate=d.get("reproduction_rate"),
            impact=d.get("impact"),
            cvss_score=d.get("cvss_score"),
            cwe_id=d.get("cwe_id"),
            param=d.get("param"),
            payload=d.get("payload"),
            tags=d.get("tags", []),
            tool_source=d.get("tool_source"),
            chain_id=d.get("chain_id"),
        )


@dataclass
class AssetSchema:
    """侦察资产 — 所有侦察工具的统一输出格式。

    六维覆盖:
        1. 子域名被动:  type=SUBDOMAIN, source=crt.sh/chaos/subfinder
        2. 排列变异:    type=SUBDOMAIN, source=dnsgen/alterx/permutation_gen
        3. 图标关联:    type=FAVICON_HASH, source=fofa/shodan
        4. ASN/IP反向:  type=ASN/CIDR/IP, source=asnmap/amass
        5. CSP 情报:    type=CSP_DOMAIN, source=csprecon/favirecon
        6. JS 源码还原: type=SOURCE_MAP, source=js-sourcemap
    """

    id: str
    type: AssetType
    value: str
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # 关联信息
    parent_domain: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    cdn_detected: bool = False
    tags: List[str] = field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None

    @staticmethod
    def make_id(value: str, asset_type: str) -> str:
        raw = f"{value}|{asset_type}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AssetSchema":
        return cls(
            id=d.get("id", cls.make_id(d["value"], d.get("type", "domain"))),
            type=AssetType(d["type"]) if d.get("type") else AssetType.DOMAIN,
            value=d["value"],
            source=d.get("source", "unknown"),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            parent_domain=d.get("parent_domain"),
            ip_addresses=d.get("ip_addresses", []),
            open_ports=d.get("open_ports", []),
            tech_stack=d.get("tech_stack", []),
            http_status=d.get("http_status"),
            cdn_detected=d.get("cdn_detected", False),
            tags=d.get("tags", []),
            raw_data=d.get("raw_data"),
        )


@dataclass
class MCPBridgeEvent:
    """MCP 统一事件 — Burp/Fiddler/Playwright/AIMY 间的跨工具消息。

    解决 MCP 层缺少统一状态管理的问题：
        - Burp 发现 JWT → 自动传递 token 给 Playwright 做 session 劫持验证
        - Fiddler 抓到的请求 → 自动导入 Burp Repeater
        - Playwright 登录后的 cookies → 注入 Burp Scanner session rule
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    source: MCPSource = MCPSource.AIMY
    event_type: str = ""  # "jwt_found", "session_captured", "request_trapped", "auth_success"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_tool: Optional[MCPSource] = None  # 推荐目标工具

    # 负载数据 — 不同 event_type 携带不同字段
    data: Dict[str, Any] = field(default_factory=dict)

    # 关联上下文
    session_id: Optional[str] = None
    target_url: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        if self.target_tool:
            d["target_tool"] = self.target_tool.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def jwt_found(cls, token: str, url: str, source: MCPSource = MCPSource.BURP) -> "MCPBridgeEvent":
        return cls(
            source=source,
            event_type="jwt_found",
            target_url=url,
            target_tool=MCPSource.PLAYWRIGHT,
            data={"token": token, "action": "verify_session_hijack"},
        )

    @classmethod
    def session_captured(cls, cookies: Dict[str, str], url: str) -> "MCPBridgeEvent":
        return cls(
            source=MCPSource.PLAYWRIGHT,
            event_type="session_captured",
            target_url=url,
            target_tool=MCPSource.BURP,
            data={"cookies": cookies, "action": "set_scanner_session"},
        )

    @classmethod
    def request_trapped(cls, request_raw: str, url: str) -> "MCPBridgeEvent":
        return cls(
            source=MCPSource.FIDDLER,
            event_type="request_trapped",
            target_url=url,
            target_tool=MCPSource.BURP,
            data={"request_raw": request_raw, "action": "send_to_repeater"},
        )

    @classmethod
    def finding_ready(cls, finding: FindingSchema) -> "MCPBridgeEvent":
        return cls(
            source=MCPSource.AIMY,
            event_type="finding_ready",
            target_url=finding.url,
            data={"finding": finding.to_dict(), "action": "add_to_sitemap"},
        )


@dataclass
class SkillRouteSchema:
    """Skill 路由决策 — 解决"什么时候用什么技能"的决策树问题。

    输入: 场景 (url, tech_stack, goal, phase)
    输出: 推荐 skill 列表 + 优先级 + 理由
    """

    route_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    phase: SkillPhase = SkillPhase.HUNT
    goal: str = ""  # "find_sqli", "full_audit", "recon_only"

    # 推荐
    recommended_skills: List[str] = field(default_factory=list)  # 按优先级排序
    recommended_tools: List[str] = field(default_factory=list)
    rationale: str = ""

    # 上下文
    url: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    auth_required: bool = False

    # 指标
    estimated_time_minutes: int = 0
    complexity: str = "medium"  # "low" | "medium" | "high"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


# ── Validation ─────────────────────────────────────────────────────────────


def validate_finding(finding: FindingSchema) -> bool:
    """基础校验: URL + vuln_type + severity 必须存在"""
    if not finding.url or not finding.vuln_type or not finding.severity:
        return False
    if not finding.title or not finding.description:
        return False
    return True


def validate_asset(asset: AssetSchema) -> bool:
    """基础校验: value + type + source 必须存在"""
    if not asset.value or not asset.type or not asset.source:
        return False
    return True


# ── Conversion Utilities ───────────────────────────────────────────────────


def burp_issue_to_finding(issue: Dict[str, Any]) -> FindingSchema:
    """将 Burp Scanner Issue 转换为 FindingSchema"""
    severity_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM,
                    "low": Severity.LOW, "information": Severity.INFO}
    return FindingSchema(
        id=FindingSchema.make_id(issue.get("url", ""), issue.get("type", "unknown")),
        url=issue.get("url", ""),
        vuln_type=_guess_vuln_type(issue.get("name", "")),
        severity=severity_map.get(issue.get("severity", "information"), Severity.INFO),
        confidence=Confidence(issue.get("confidence", "tentative")),
        title=issue.get("name", "Untitled")[:100],
        description=issue.get("detail", ""),
        request_raw=issue.get("request"),
        response_raw=issue.get("response"),
        impact=issue.get("remediation"),
        tool_source="burp",
    )


def finding_to_h1_report(finding: FindingSchema) -> Dict[str, str]:
    """将 FindingSchema 转换为 HackerOne 报告格式。

    bounty 模式强制检查: 未通过 validator 的 finding 拒绝导出。
    """
    # ═══════════════════════════════════════════
    # P0 修补: AI 报告硬门 (bounty 模式)
    # ═══════════════════════════════════════════
    from aimy.tools.settings import settings

    scene = getattr(settings, '_scene', 'bounty')
    ai_report_allowed = getattr(settings, '_scene_profile', {}).get(
        'ai_report_only', False
    )

    if scene == 'bounty' and not ai_report_allowed:
        # 检查 finding 是否经过人工验证
        validated = getattr(finding, 'human_verified', False) or getattr(
            finding, 'validator_passed', False
        )
        if not validated:
            raise ValueError(
                f"[AI-REPORT] bounty 模式禁止导出未验证的 finding: {finding.title}。"
                f" 请先通过 validator agent 验证 (7问门 + 4验收门)，"
                f" 然后设置 finding.human_verified = True。"
                f" 360SRC: 纯AI报告直接驳回, >=3条→封号。"
            )

    return {
        "title": finding.title,
        "vulnerability_type": finding.vuln_type.value,
        "severity": finding.severity.value.capitalize(),
        "affected_url": finding.url,
        "description": finding.description,
        "impact": finding.impact or "",
        "steps_to_reproduce": finding.poc or "",
        "cwe_id": finding.cwe_id or "",
        "cvss_score": str(finding.cvss_score) if finding.cvss_score else "",
    }


def _guess_vuln_type(name: str) -> VulnCategory:
    """从 Burp issue name 推测漏洞类型"""
    name_lower = name.lower()
    mappings = {
        "sql": VulnCategory.SQLI,
        "xss": VulnCategory.XSS,
        "csrf": VulnCategory.CSRF,
        "ssrf": VulnCategory.SSRF,
        "xxe": VulnCategory.XXE,
        "ssti": VulnCategory.SSTI,
        "jwt": VulnCategory.JWT,
        "idor": VulnCategory.IDOR,
        "deserial": VulnCategory.DESERIALIZATION,
        "path traversal": VulnCategory.LFI,
        "cors": VulnCategory.CORS,
        "graphql": VulnCategory.GRAPHQL,
        "race": VulnCategory.RACE_CONDITION,
        "smuggl": VulnCategory.HTTP_SMUGGLING,
        "cache": VulnCategory.CACHE_POISONING,
        "prototype": VulnCategory.PROTOTYPE_POLLUTION,
        "open redirect": VulnCategory.OPEN_REDIRECT,
        "information": VulnCategory.INFO_DISCLOSURE,
    }
    for pattern, category in mappings.items():
        if pattern in name_lower:
            return category
    return VulnCategory.OTHER


# ── Filtering ──────────────────────────────────────────────────────────────


def filter_veteran(findings: List[FindingSchema]) -> List[FindingSchema]:
    """老鸟模式: 过滤低危+反射XSS+OpenRedirect+配置问题+信息泄露"""
    return [f for f in findings if not f.is_filtered_veteran()]


def sort_by_severity(findings: List[FindingSchema]) -> List[FindingSchema]:
    """按严重程度降序"""
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFO: 4}
    return sorted(findings, key=lambda f: order.get(f.severity, 99))


def dedup_findings(findings: List[FindingSchema]) -> List[FindingSchema]:
    """按 URL + vuln_type 去重，保留最高 severity"""
    seen: Dict[str, FindingSchema] = {}
    severity_order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
                      Severity.LOW: 1, Severity.INFO: 0}
    for f in findings:
        key = f"{f.url}|{f.vuln_type.value}|{f.param or ''}"
        if key not in seen or severity_order.get(f.severity, 0) > severity_order.get(seen[key].severity, 0):
            seen[key] = f
    return list(seen.values())
