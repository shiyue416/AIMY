"""测试结果数据结构 + 匿名化器"""

from __future__ import annotations
import hashlib
import re
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List
from urllib.parse import urlparse


@dataclass
class TestResult:
    """单条测试结果 — 飞轮进化最小数据单元"""

    # === 漏洞分类 ===
    vuln_type: str  # ssrf/sqli/xss/idor/ssti/cmdi/lfi/xxe/...
    vuln_subtype: str = ""  # 子类型: blind/time-based/error-based/...

    # === 目标信息（脱敏后） ===
    target_domain: str = ""  # 仅域名，不含路径参数
    target_endpoint: str = ""  # 脱敏后端点: /api/user/{id}
    http_method: str = "GET"

    # === 检测结果 ===
    found: bool = False  # 是否确认漏洞存在
    confidence: float = 0.0  # 0.0-1.0 置信度
    severity: str = ""  # critical/high/medium/low/info

    # === 工具链 ===
    skill_used: str = ""  # 技能文件名
    tool_used: str = ""  # Python 工具名
    payload_hash: str = ""  # payload 的 sha256（不存原文）
    payload_category: str = ""  # payload 类型标签

    # === 执行信息 ===
    execution_time_ms: int = 0
    requests_sent: int = 0
    errors_encountered: int = 0
    waf_detected: bool = False
    waf_type: str = ""

    # === 环境 ===
    aimy_version: str = "3.0.0"
    aimy_mode: str = ""  # veteran/rookie
    aimy_scene: str = ""  # bounty/pentest/redteam

    # === 元数据 ===
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""  # 会话 ID（非用户 ID）
    feedback_note: str = ""  # 用户可选备注（自由文本）


class Anonymizer:
    """数据匿名化 — 确保不泄露用户隐私"""

    @staticmethod
    def hash_value(value: str, salt: str = "") -> str:
        """SHA256 哈希，不可逆"""
        return hashlib.sha256(f"{value}:{salt}".encode()).hexdigest()[:16]

    @staticmethod
    def anonymize_url(url: str) -> tuple[str, str]:
        """
        返回 (domain_only, endpoint_pattern)
        例: https://target.com/api/user/123?q=test
          → ("target.com", "/api/user/{id}?q={param}")
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split("@")[-1].split(":")[0]  # 去认证信息去端口

            # 路径参数匿名化
            path = parsed.path
            path = re.sub(r"/\d+", "/{id}", path)
            path = re.sub(r"/[a-f0-9]{32}", "/{hash}", path)
            path = re.sub(r"/[A-Za-z0-9_-]{20,}", "/{token}", path)

            # 查询参数匿名化
            if parsed.query:
                params = []
                for pair in parsed.query.split("&"):
                    if "=" in pair:
                        k, _ = pair.split("=", 1)
                        params.append(f"{k}={{value}}")
                    else:
                        params.append(pair)
                endpoint = f"{path}?{'&'.join(params)}"
            else:
                endpoint = path

            return domain, endpoint
        except Exception:
            return "unknown", url[:50]

    @classmethod
    def sanitize_result(cls, result: TestResult) -> TestResult:
        """原地脱敏，去掉所有可能追溯用户的信息"""
        result.payload_hash = cls.hash_value(result.payload_hash or "")
        if result.target_endpoint and not result.target_endpoint.startswith("/"):
            _, result.target_endpoint = cls.anonymize_url(result.target_endpoint)
        result.session_id = cls.hash_value(result.session_id or os.urandom(8).hex())
        return result


# 便于序列化
def result_to_dict(r: TestResult) -> dict:
    return asdict(r)


def dict_to_result(d: dict) -> TestResult:
    return TestResult(**{k: v for k, v in d.items() if k in TestResult.__dataclass_fields__})
