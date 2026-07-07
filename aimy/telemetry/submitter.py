"""GitHub Issues API 提交器 — 子体→GitHub Issue→本体拉取

双模式:
  模式 A (自动): 用内置 AIMY_FEEDBACK_TOKEN 直接调 GitHub API 创建 Issue
  模式 B (降级): 无 token 时生成预填 URL，用户一键点击提交
  模式 C (本地): 始终缓存到磁盘，sync_feedback.py 同步时批量处理

Token 安全:
  - AIMY_FEEDBACK_TOKEN 是专用受限 token，仅 issues:write 单一仓库
  - 该 token 公开内置于子体中（有意为之），可随时在 GitHub 吊销
  - 用户也可用自己的 GITHUB_TOKEN 覆盖
"""

from __future__ import annotations
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Optional
from pathlib import Path

from .collector import FeedbackCollector


# ============================================================
# 内置受限 Token — 仅 issues:write 权限，可随时吊销
# 发布到 GitHub 后在此填入真实的 fine-grained PAT
# ============================================================
_BUILTIN_FEEDBACK_TOKEN = os.environ.get(
    "AIMY_FEEDBACK_TOKEN",
    ""  # 留空=一键URL模式; 填入 Fine-grained PAT 后变全自动
    # Fine-grained PAT 生成: https://github.com/settings/tokens?type=beta
    # 权限: Repository access → AIMY only → Issues → Read and Write
)
_DEFAULT_FEEDBACK_REPO = os.environ.get(
    "AIMY_FEEDBACK_REPO",
    "shiyue416/AIMY"
)


class GitHubFeedbackSubmitter:
    """双模式遥测提交器"""

    def __init__(
        self,
        repo: str = "",
        token: str = "",
        collector: Optional[FeedbackCollector] = None,
    ):
        # 优先级: 参数 > 环境变量 GITHUB_TOKEN > 内置 token
        self.repo = repo or _DEFAULT_FEEDBACK_REPO
        self.token = token or os.environ.get("GITHUB_TOKEN", "") or _BUILTIN_FEEDBACK_TOKEN
        self.collector = collector
        self._has_auto_token = bool(self.token)

    # ── 模式 A: 自动提交 ────────────────────────────

    def submit_auto(self, collector: Optional[FeedbackCollector] = None) -> dict:
        """通过 GitHub API 自动创建 Issue"""
        c = collector or self.collector
        if not c:
            return {"mode": "auto", "status": "error", "message": "无 FeedbackCollector 实例"}

        if not self.token:
            return {"mode": "auto", "status": "error", "message": "无可用 Token"}

        if not self.repo:
            return {"mode": "auto", "status": "error", "message": "AIMY_FEEDBACK_REPO 未设置"}

        body = c.export_github_issue_body()
        if not body:
            return {"mode": "auto", "status": "error", "message": "无数据可提交"}

        summary = c.export_summary()
        title = f"[遥测] {summary.get('total_tests', 0)} 次测试 | 命中率 {summary.get('hit_rate', 'N/A')}"

        issue_data = json.dumps({
            "title": title,
            "body": body,
            "labels": ["telemetry", "auto"],
        }).encode("utf-8")

        api_url = f"https://api.github.com/repos/{self.repo}/issues"
        req = urllib.request.Request(
            api_url,
            data=issue_data,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
                "User-Agent": "AIMY-Telemetry/3.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
                return {
                    "mode": "auto",
                    "status": "ok",
                    "issue_url": result.get("html_url", ""),
                    "issue_number": result.get("number", 0),
                }
        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode()[:500]
            except Exception:
                pass
            return {
                "mode": "auto",
                "status": "error",
                "message": f"HTTP {e.code}: {e.reason}",
            }
        except Exception as e:
            return {"mode": "auto", "status": "error", "message": str(e)}

    # ── 模式 B: 预填 URL 降级 ─────────────────────────

    def generate_submit_url(self, collector: Optional[FeedbackCollector] = None) -> str:
        """生成预填的 GitHub Issue 创建 URL，用户点击即可提交"""
        c = collector or self.collector
        if not c:
            return ""

        body = c.export_github_issue_body()
        if not body:
            return ""

        summary = c.export_summary()
        title = f"[遥测] {summary.get('total_tests', 0)} 次测试 | 命中率 {summary.get('hit_rate', 'N/A')}"

        params = urllib.parse.urlencode({
            "title": title,
            "body": body,
            "labels": "telemetry,auto",
        })
        return f"https://github.com/{self.repo}/issues/new?{params}" if self.repo else ""

    # ── 综合入口 ─────────────────────────────────────

    def submit(self, collector: Optional[FeedbackCollector] = None) -> dict:
        """
        智能提交: 有 Token → 自动提交; 无 Token → 生成 URL
        始终缓存到本地磁盘作为备份
        """
        c = collector or self.collector
        if not c:
            return {"mode": "none", "status": "error", "message": "无数据"}

        # 始终先存本地
        c.flush_to_disk()

        # 尝试自动提交
        if self._has_auto_token:
            return self.submit_auto(c)
        else:
            url = self.generate_submit_url(c)
            return {
                "mode": "manual_url",
                "status": "ok",
                "submit_url": url,
                "message": "无 Token，请点击链接手动提交",
            }


# ── 会话结束自动上报 ─────────────────────────────────

def auto_submit_on_exit():
    """
    会话结束时自动调用 — 由 orchestrator 或 aimy/main.py 注册 atexit 触发。
    无感上报，不打断用户工作流。
    """
    try:
        from .collector import get_collector

        collector = get_collector()
        if not collector.enabled:
            return

        summary = collector.export_summary()
        if summary.get("total_tests", 0) == 0:
            return  # 无测试数据，跳过

        submitter = GitHubFeedbackSubmitter(collector=collector)
        result = submitter.submit()

        if result.get("status") == "ok" and result.get("mode") == "auto":
            # 静默成功，只在 debug 模式打印
            if os.environ.get("AIMY_DEBUG"):
                print(f"📤 遥测已上报: {result.get('issue_url', '')}")
        elif result.get("mode") == "manual_url":
            # 无 token 时打印 URL
            print()
            print("📋 遥测数据已缓存。点击以下链接一键提交（可选）:")
            print(f"   {result.get('submit_url', '')}")
    except Exception:
        pass  # 上报失败绝不能影响主流程


# ── CLI 入口 ────────────────────────────────────────

def cmd_submit_feedback():
    """CLI: python -m aimy.telemetry.submitter"""
    from .collector import get_collector

    collector = get_collector()
    if not collector.enabled:
        print("⚠️  遥测未启用。设置 AIMY_TELEMETRY_ENABLED=true 开启。")
        sys.exit(0)

    summary = collector.export_summary()
    if summary.get("total_tests", 0) == 0:
        print("📭 暂无测试数据可提交。")
        sys.exit(0)

    print(f"📊 遥测摘要:")
    print(f"   总测试: {summary['total_tests']}")
    print(f"   命中:   {summary['vulnerabilities_found']} ({summary['hit_rate']})")
    print(f"   类型:   {dict(summary.get('top_vuln_types', []))}")
    print()

    submitter = GitHubFeedbackSubmitter(collector=collector)

    if submitter._has_auto_token:
        print("🔗 模式: 自动提交 (Token 已配置)")
        result = submitter.submit_auto()
        if result["status"] == "ok":
            print(f"✅ 已上报: {result['issue_url']}")
        else:
            print(f"❌ 自动提交失败: {result['message']}")
            # 降级到 URL
            url = submitter.generate_submit_url()
            if url:
                print(f"📋 降级方案 — 点击提交: {url}")
    else:
        print("🔗 模式: 手动提交 (无 Token)")
        url = submitter.generate_submit_url()
        if url:
            print(f"📋 一键提交链接:")
            print(f"   {url}")
        else:
            print("⚠️  无法生成提交链接，请检查 AIMY_FEEDBACK_REPO 配置。")

    # 显示本地缓存位置
    print(f"\n💾 本地缓存: {collector.CACHE_DIR}")


if __name__ == "__main__":
    cmd_submit_feedback()
