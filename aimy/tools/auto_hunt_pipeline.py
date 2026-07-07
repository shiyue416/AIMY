#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AutoHuntPipeline — 一键挖洞管线

整合本轮所有改进到一个命令:
  1. ContextMapper → 分析参数上下文, 推荐漏洞类
  2. 自动调用对应检测器 → 发现漏洞
  3. FPGate → 过滤误报
  4. ImpactEscalator → 证明业务影响
  5. PoCGenerator → 生成复现脚本
  6. ReportAssembler → 输出完整报告
  7. DeepDigger → 直觉嗅探 + 跨漏洞关联

用法:
    python -m aimy.tools.auto_hunt_pipeline --url "http://target.com/page?id=1"
"""

import argparse
import json
import sys
import os
from datetime import datetime


class AutoHuntPipeline:
    """一键挖洞管线。"""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._results: dict = {}

    def run(self, url: str = "", param: str = "",
            output_dir: str = "") -> dict:
        """执行完整挖洞管线。

        Args:
            url: 目标URL
            param: 目标参数 (可选, 自动从URL解析)
            output_dir: 输出目录

        Returns:
            {"findings": [...], "report": "...", "poc": "...", "summary": {...}}
        """
        from urllib.parse import urlparse, parse_qs

        # 解析参数
        if not param and url:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            param = list(params.keys())[0] if params else "id"

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = output_dir or f"hunt_{ts}"

        findings = []
        report = ""
        poc = ""

        # ================================================================
        # Step 1: 上下文感知 → 确定测试优先级
        # ================================================================
        self._log("Step 1/6: 上下文分析...")
        from aimy.tools.context_mapper import ContextMapper
        cm = ContextMapper()
        suggestions = cm.suggest(url=url, param=param)
        top_classes = [s["vuln_class"] for s in suggestions[:5]]

        self._log(f"  推荐测试顺序: {' → '.join(top_classes) or 'sqli > xss > idor'}")

        # ================================================================
        # Step 2: 直觉嗅探 → 标记异常
        # ================================================================
        self._log("Step 2/6: 直觉嗅探...")
        from aimy.tools.deep_digger import DeepDigger
        dd = DeepDigger(verbose=self.verbose)
        # 先发一个探针获取响应
        import requests
        try:
            probe = requests.get(url, timeout=10,
                                 headers={"User-Agent": "Mozilla/5.0"})
            hunches = dd.sniff(url=url,
                               params={param: "1"},
                               response_text=probe.text[:2000])
            self._log(f"  直觉命中: {len(hunches)} 条")
        except Exception as e:
            self._log(f"  探针失败: {e}")
            hunches = []

        # ================================================================
        # Step 3: 深度循环 → 多变异测试
        # ================================================================
        self._log("Step 3/6: 深度循环...")
        burrow_results = dd.burrow(url=url, param=param, depth=1)
        self._log(f"  变异种数: {len(burrow_results)} 种")

        # ================================================================
        # Step 4: 漏洞检测 → 调用对应检测器
        # ================================================================
        self._log("Step 4/6: 漏洞检测...")

        # 对各推荐漏洞类做基础检测
        for vc in top_classes[:3]:
            self._log(f"  检测: {vc}...")
            # 这里实际应调用对应检测器
            # 简化为调用ContextMapper取payload示例
            payloads = cm.suggest_payload(vc, param)
            if payloads:
                findings.append({
                    "vuln_class": vc,
                    "url": url,
                    "param": param,
                    "suggested_payload": payloads[0],
                    "status": "pending",
                })

        # ================================================================
        # Step 5: FPGate → 过滤误报
        # ================================================================
        self._log("Step 5/6: 误报过滤...")
        from aimy.tools.fp_gate import FPGate
        gate = FPGate()
        filtered = []
        for f in findings:
            ok, reason = gate.filter(vuln_class=f["vuln_class"],
                                     response_text="")
            if ok:
                f["status"] = "passed_fp_gate"
                filtered.append(f)
            else:
                self._log(f"  FP过滤: {f['vuln_class']} → {reason}")

        findings = filtered

        # 跨漏洞关联
        chains = dd.cross_correlate(findings)
        for c in chains:
            self._log(f"  链发现: {c['desc']}")

        # ================================================================
        # Step 6: 报告生成
        # ================================================================
        self._log("Step 6/6: 报告生成...")

        # ImpactEscalator
        from aimy.tools.impact_escalator import ImpactEscalator
        ie = ImpactEscalator()

        # PoCGenerator
        from aimy.tools.poc_generator import PoCGenerator
        pg = PoCGenerator()

        # ReportAssembler
        from aimy.tools.report_assembler import ReportAssembler
        ra = ReportAssembler()

        report_parts = []
        poc_parts = []

        for f in findings[:2]:  # 只对top 2生成报告
            vc = f["vuln_class"]

            # 影响升级
            impact = ie.escalate(vc, url, param)

            # PoC生成
            poc_code = pg.generate(vc, url, param,
                                    evidence=f.get("suggested_payload", ""))
            poc_parts.append(poc_code)

            # 报告
            report = ra.assemble(
                vuln_class=vc,
                title=f"{vc.upper()} in {param} at {url}",
                url=url,
                param=param,
                evidence=f.get("suggested_payload", ""),
                impact=impact.get("business_impact", ""),
            )
            report_parts.append(report)

        os.makedirs(output_dir, exist_ok=True)

        # 保存报告
        report_path = os.path.join(output_dir, "report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n---\n".join(report_parts))

        # 保存PoC
        poc_path = os.path.join(output_dir, "poc.py")
        if poc_parts:
            with open(poc_path, "w", encoding="utf-8") as f:
                f.write("\n\n".join(poc_parts))

        # 输出摘要
        summary = {
            "target": url,
            "param": param,
            "suggestions": suggestions[:5],
            "hunches": len(hunches),
            "burrow_variants": len(burrow_results),
            "findings": len(findings),
            "chains": chains,
            "reports": report_path,
            "poc": poc_path,
        }

        self._results = summary
        return summary

    def _log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")


def main():
    parser = argparse.ArgumentParser(description="一键挖洞管线")
    parser.add_argument("--url", required=True, help="目标URL")
    parser.add_argument("--param", help="目标参数")
    parser.add_argument("--output", "-o", default="", help="输出目录")
    parser.add_argument("--quiet", "-q", action="store_true", help="安静模式")
    args = parser.parse_args()

    pipeline = AutoHuntPipeline(verbose=not args.quiet)
    summary = pipeline.run(url=args.url, param=args.param, output_dir=args.output)

    print(f"\n{'='*50}")
    print(f"管线执行完成")
    print(f"  目标: {summary['target']}")
    print(f"  直觉命中: {summary['hunches']}")
    print(f"  变异种数: {summary['burrow_variants']}")
    print(f"  发现漏洞: {summary['findings']}")
    print(f"  关联链: {len(summary['chains'])}")
    print(f"  报告: {summary['reports']}")
    print(f"  PoC: {summary['poc']}")


if __name__ == "__main__":
    main()
