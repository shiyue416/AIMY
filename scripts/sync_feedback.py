#!/usr/bin/env python3
"""
sync_feedback.py — 本体拉取子体反馈数据

数据流:
  GitHub Issue (子体用户提交) → 本脚本拉取 → _feedback/*.jsonl → 飞轮进化

用法:
  python scripts/sync_feedback.py                  # 拉取所有新反馈
  python scripts/sync_feedback.py --repo Yan-AIMY/feedback  # 指定仓库
  python scripts/sync_feedback.py --since 2026-07-01        # 指定起始日期
  python scripts/sync_feedback.py --dry-run                  # 仅预览不写入

环境变量:
  GITHUB_TOKEN: GitHub PAT (repo scope 即可)
"""

from __future__ import annotations
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ── 配置 ──────────────────────────────────────────

FEEDBACK_REPO = os.environ.get("AIMY_FEEDBACK_REPO", "shiyue416/AIMY")
FEEDBACK_DIR = Path(os.environ.get("AIMY_FEEDBACK_DIR", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "_feedback"
)))
# 用 GitHub Issues label 过滤遥测数据
TELEMETRY_LABEL = "auto"
LAST_SYNC_FILE = FEEDBACK_DIR / ".last_sync"


# ── API 客户端 ─────────────────────────────────────

class GitHubAPI:
    """最小依赖的 GitHub Issues API 封装"""

    BASE = "https://api.github.com"

    def __init__(self, token: str = ""):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        if not self.token:
            print("[!] GITHUB_TOKEN not set. Public read-only access, rate limit 60 req/h.")
        self._rate_remaining = 5000

    def _req(self, endpoint: str) -> dict:
        """GET 请求，返回 parsed JSON"""
        url = f"{self.BASE}{endpoint}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AIMY-SyncBot/3.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                self._rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", 0))
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            print(f"[ERR] API 错误: {e.code} {e.reason}")
            return {}

    def list_issues(self, repo: str, labels: str = "", since: str = "",
                    state: str = "open", page: int = 1) -> list[dict]:
        """列出 Issues"""
        params = f"?state={state}&labels={labels}&per_page=100&page={page}&sort=created&direction=desc"
        if since:
            params += f"&since={since}"
        return self._req(f"/repos/{repo}/issues{params}") or []

    def get_issue(self, repo: str, number: int) -> dict:
        """获取单个 Issue 详情"""
        return self._req(f"/repos/{repo}/issues/{number}") or {}

    @property
    def rate_remaining(self) -> int:
        return self._rate_remaining


# ── 数据解析 ───────────────────────────────────────

def parse_issue_body(body: str) -> dict | None:
    """
    从 Issue Markdown 正文中提取遥测 JSON。
    结构约定: <details><summary>[PACKAGE] 原始数据 (JSON)</summary>
              ```json {...} ```
    """
    import re
    # 提取 JSON 代码块
    match = re.search(r"```json\s*\n(.*?)\n```", body, re.DOTALL)
    if not match:
        # Fallback: 尝试匹配任意 JSON 对象
        match = re.search(r'\{[^{}]*"total_tests"[^{}]*\}', body, re.DOTALL)
        if not match:
            return None

    try:
        return json.loads(match.group(1) if match.lastindex is None else match.group(0))
    except json.JSONDecodeError:
        return None


def save_feedback(data: dict, issue_number: int, timestamp: str) -> Path:
    """将一条反馈写入 JSONL"""
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)

    record = {
        "source": "github_issue",
        "issue_number": issue_number,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "user_timestamp": timestamp,
        "data": data,
    }

    # 按日期分文件，避免单文件过大
    date_str = timestamp[:10] if timestamp else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filepath = FEEDBACK_DIR / f"feedback_{date_str}.jsonl"

    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return filepath


# ── 状态管理 ───────────────────────────────────────

def get_last_sync_time() -> str:
    """读取上次同步时间"""
    if LAST_SYNC_FILE.exists():
        return LAST_SYNC_FILE.read_text().strip()
    # 默认：7 天前
    return (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()


def set_last_sync_time(t: str = "") -> None:
    """记录本次同步时间"""
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    LAST_SYNC_FILE.write_text(t or datetime.now(timezone.utc).isoformat())


# ── 主流程 ─────────────────────────────────────────

def sync(repo: str = "", since: str = "", dry_run: bool = False,
         token: str = "") -> dict:
    """
    从 GitHub 拉取遥测反馈数据。

    Returns:
        {"new": 新数据条数, "total_issues": 扫描的 Issue 数, "files": [写入的文件列表]}
    """
    repo = repo or FEEDBACK_REPO
    since = since or get_last_sync_time()
    api = GitHubAPI(token=token)

    print(f"[SEARCH] 扫描 {repo} 的遥测反馈...")
    print(f"   起始时间: {since}")
    print(f"   输出目录: {FEEDBACK_DIR}")
    print()

    new_count = 0
    total_issues = 0
    files_written = set()

    seen_numbers = set()  # 避免重复处理

    # 分页拉取
    for page in range(1, 11):  # 最多 10 页 = 1000 条 Issue
        issues = api.list_issues(repo, labels=TELEMETRY_LABEL,
                                 since=since, state="all", page=page)
        if not issues:
            break

        total_issues += len(issues)
        print(f"   [PAGE] 第 {page} 页: {len(issues)} 条 Issue (API 余量: {api.rate_remaining})")

        for issue in issues:
            number = issue.get("number", 0)
            if number in seen_numbers:
                continue
            seen_numbers.add(number)

            body = issue.get("body", "")
            created_at = issue.get("created_at", "")

            if not body:
                continue

            parsed = parse_issue_body(body)
            if not parsed:
                print(f"   [WARN]  #{number}: 未找到遥测 JSON，跳过")
                continue

            if dry_run:
                print(f"   [STATS] #{number}: {parsed.get('total_tests', 0)} 次测试, "
                      f"命中率 {parsed.get('hit_rate', 'N/A')}")
                continue

            filepath = save_feedback(parsed, number, created_at)
            files_written.add(str(filepath))
            new_count += 1
            print(f"   [OK] #{number}: {parsed.get('total_tests', 0)} 次测试 → {filepath.name}")

        # 检查是否还有下一页
        if len(issues) < 100:
            break

    if not dry_run and new_count > 0:
        set_last_sync_time()

    print()
    print(f"[PACKAGE] 同步完成: {new_count} 条新反馈 / 扫描 {total_issues} 条 Issue")
    if files_written:
        print(f"   写入文件: {len(files_written)} 个")

    return {
        "new": new_count,
        "total_issues": total_issues,
        "files": list(files_written),
    }


# ── 飞轮进化对接 ────────────────────────────────────

def feed_to_flywheel(feedback_dir: Path = None):
    """
    将 _feedback/ 目录的数据转化为 techniques.jsonl 条目。
    每次 sync 后自动调用。
    """
    fb_dir = feedback_dir or FEEDBACK_DIR
    if not fb_dir.exists():
        print("   没有反馈数据可转化。")
        return

    # 聚合统计
    from collections import Counter
    vuln_hits = Counter()
    total_tests = 0
    total_found = 0

    for fpath in sorted(fb_dir.glob("feedback_*.jsonl")):
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    data = rec.get("data", {})
                    total_tests += data.get("total_tests", 0)
                    total_found += data.get("vulnerabilities_found", 0)
                    for vt, cnt in data.get("top_vuln_types", []):
                        vuln_hits[vt] += cnt
                except Exception:
                    continue

    if total_tests == 0:
        return

    print()
    print("[CHART] 飞轮聚合:")
    print(f"   总测试: {total_tests}")
    print(f"   总命中: {total_found} ({total_found / total_tests * 100:.1f}%)")
    print(f"   漏洞类型分布:")
    for vt, cnt in vuln_hits.most_common(10):
        print(f"     {vt}: {cnt}")


# ── CLI ────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="AIMY 本体同步 — 从 GitHub 拉取子体反馈数据"
    )
    parser.add_argument("--repo", default="", help=f"反馈仓库 (默认: {FEEDBACK_REPO})")
    parser.add_argument("--since", default="", help="起始日期 ISO 格式")
    parser.add_argument("--token", default="", help="GitHub PAT")
    parser.add_argument("--dry-run", action="store_true", help="仅预览不写入")
    parser.add_argument("--no-flywheel", action="store_true", help="跳过飞轮聚合")
    args = parser.parse_args()

    result = sync(
        repo=args.repo,
        since=args.since,
        dry_run=args.dry_run,
        token=args.token,
    )

    if not args.no_flywheel and result["new"] > 0:
        feed_to_flywheel()

    if result["new"] == 0:
        print("[IDLE] 无新反馈数据。")
        sys.exit(0)


if __name__ == "__main__":
    main()
