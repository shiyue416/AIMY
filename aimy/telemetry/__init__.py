"""AIMY Telemetry — 子体→本体 数据回流模块

架构:
  子体(GitHub) → 用户测试 → collector 收集 → GitHub Issues API → 本体拉取 → 飞轮进化

隐私:
  - 默认关闭，需 AIMY_TELEMETRY_ENABLED=true 显式开启
  - 自动脱敏：URL 只保留域名，参数名保留但参数值哈希
  - 不收集：Cookie/Token/密码/个人身份信息
"""

from .collector import TestResult, FeedbackCollector
from .submitter import GitHubFeedbackSubmitter
from .anonymizer import Anonymizer

__all__ = [
    "TestResult",
    "FeedbackCollector",
    "GitHubFeedbackSubmitter",
    "Anonymizer",
]
