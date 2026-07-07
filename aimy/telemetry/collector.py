"""测试结果收集器 — 本地缓存 + 批量提交"""

from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import List, Optional

from .anonymizer import TestResult, Anonymizer, result_to_dict


class FeedbackCollector:
    """收集用户测试结果，本地缓存，可选提交到 GitHub 反馈仓库"""

    MAX_CACHE_SIZE = 500  # 本地最多缓存 500 条，超出自动触发提交
    CACHE_DIR = os.path.join(os.path.expanduser("~"), ".aimy", "feedback_cache")

    def __init__(self, enabled: bool = False, feedback_repo: str = ""):
        self.enabled = enabled
        self.feedback_repo = feedback_repo or os.environ.get("AIMY_FEEDBACK_REPO", "")
        self._results: List[TestResult] = []
        self._anonymizer = Anonymizer()
        os.makedirs(self.CACHE_DIR, exist_ok=True)

    # ── 收集 ──────────────────────────────────────

    def record(self, result: TestResult) -> None:
        """记录一条测试结果"""
        if not self.enabled:
            return

        result = self._anonymizer.sanitize_result(result)
        self._results.append(result)
        self._flush_if_full()

    def record_batch(self, results: List[TestResult]) -> None:
        """批量记录"""
        if not self.enabled:
            return
        for r in results:
            self._results.append(self._anonymizer.sanitize_result(r))
        self._flush_if_full()

    # ── 持久化 ────────────────────────────────────

    def _flush_if_full(self) -> None:
        """缓存满时写入磁盘"""
        if len(self._results) >= self.MAX_CACHE_SIZE:
            self.flush_to_disk()

    def flush_to_disk(self) -> str:
        """将所有缓存写入磁盘 JSONL 文件"""
        if not self._results:
            return ""

        batch_id = f"feedback_{int(time.time())}_{len(self._results)}.jsonl"
        filepath = os.path.join(self.CACHE_DIR, batch_id)

        with open(filepath, "w", encoding="utf-8") as f:
            for r in self._results:
                f.write(json.dumps(result_to_dict(r), ensure_ascii=False) + "\n")

        count = len(self._results)
        self._results.clear()
        return filepath

    # ── 导出（给 GitHub Issue 用） ────────────────

    def export_summary(self) -> dict:
        """导出统计摘要（无隐私数据）"""
        if not self._results:
            self._load_from_disk()

        all_results = self._results + self._load_from_disk()

        if not all_results:
            return {"total": 0, "message": "暂无测试数据"}

        vuln_types = {}
        found_count = 0
        total_confidence = 0.0
        tools_used = set()

        for r in all_results[:1000]:  # 最多统计 1000 条
            vuln_types[r.vuln_type] = vuln_types.get(r.vuln_type, 0) + 1
            if r.found:
                found_count += 1
                total_confidence += r.confidence
            if r.tool_used:
                tools_used.add(r.tool_used)

        return {
            "total_tests": len(all_results),
            "vulnerabilities_found": found_count,
            "hit_rate": f"{found_count / max(len(all_results), 1) * 100:.1f}%",
            "avg_confidence": f"{total_confidence / max(found_count, 1):.2f}",
            "top_vuln_types": sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10],
            "tools_used": sorted(tools_used),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def export_github_issue_body(self) -> str:
        """
        生成 GitHub Issue 正文 — 用户手动提交或自动提交
        格式: Markdown 表格 + JSON 代码块
        """
        summary = self.export_summary()
        if summary["total"] == 0:
            return ""

        lines = [
            "## 🤖 AIMY 自动遥测报告",
            "",
            f"**测试总数**: {summary['total_tests']}",
            f"**命中数**: {summary['vulnerabilities_found']}",
            f"**命中率**: {summary['hit_rate']}",
            f"**平均置信度**: {summary['avg_confidence']}",
            "",
            "### 漏洞类型分布",
            "",
            "| 类型 | 数量 |",
            "|------|------|",
        ]
        for vt, cnt in summary["top_vuln_types"]:
            lines.append(f"| {vt} | {cnt} |")

        lines += [
            "",
            "### 使用的工具",
            "",
            ", ".join(summary["tools_used"]) or "无",
            "",
            f"**生成时间**: {summary['generated_at']}",
            "",
            "<details><summary>📦 原始数据 (JSON)</summary>",
            "",
            "```json",
            json.dumps(summary, ensure_ascii=False, indent=2),
            "```",
            "",
            "</details>",
        ]

        return "\n".join(lines)

    def _load_from_disk(self) -> list:
        """从磁盘加载缓存的反馈数据"""
        results = []
        if not os.path.exists(self.CACHE_DIR):
            return results
        for fname in sorted(os.listdir(self.CACHE_DIR)):
            if not fname.endswith(".jsonl"):
                continue
            fpath = os.path.join(self.CACHE_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            results.append(json.loads(line))
            except Exception:
                continue
        return results


# ── 全局单例 ──────────────────────────────────────

_collector: Optional[FeedbackCollector] = None


def get_collector() -> FeedbackCollector:
    """获取全局反馈收集器单例"""
    global _collector
    if _collector is None:
        enabled = os.environ.get("AIMY_TELEMETRY_ENABLED", "false").lower() == "true"
        repo = os.environ.get("AIMY_FEEDBACK_REPO", "")
        _collector = FeedbackCollector(enabled=enabled, feedback_repo=repo)
    return _collector
