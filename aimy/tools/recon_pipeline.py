#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ReconPipeline — 九步资产收集管线

用法:
    # 域名模式
    python -m aimy.tools.recon_pipeline --target dongchedi.com

    # 公司名模式 (企查查+FOFA联合)
    python -m aimy.tools.recon_pipeline --company "理想汽车"
    python -m aimy.tools.recon_pipeline --company "北京车励行"

    # 从文件批量读取目标
    python -m aimy.tools.recon_pipeline --list targets.txt
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


class ReconPipeline:
    """九步资产收集管线。"""

    # 速率限制
    SLEEP = 1
    TIMEOUT = 10
    LIMIT_RATE = "100K"

    # FOFA API (从环境变量读)
    FOFA_EMAIL = os.environ.get("FOFA_EMAIL", "")
    FOFA_KEY = os.environ.get("FOFA_KEY", "")

    def __init__(self, target: str = "", company: str = "",
                 target_list: str = "", output_dir: str = "", verbose: bool = True):
        self.target = target
        self.company = company
        self.target_list = target_list
        self.verbose = verbose
        self.output_dir = output_dir or self._default_output_dir()
        self.results: dict = {}
        self._step_num = 0

    def _default_output_dir(self) -> str:
        name = self.target or self.company or "unknown"
        return f"recon_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def _resolve_targets(self) -> list[str]:
        """解析最终扫的目标列表。"""
        if self.company:
            print(f"\n公司名模式: {self.company}")
            print(f"请去以下站点查询域名:")
            print(f"  1. qichacha.com 搜 \"{self.company}\"")
            print(f"  2. fofa.info 搜 body=\"{self.company}\"")
            print(f"  3. beian.miit.gov.cn ICP备案")
            print(f"然后把域名通过 --target 或 --list 传入\n")
            return []
        if self.target_list:
            path = os.path.expanduser(self.target_list)
            if os.path.exists(path):
                with open(path) as f:
                    targets = [line.strip() for line in f if line.strip()]
                self.log(f"从文件加载 {len(targets)} 个目标")
                return targets
            self.log(f"文件不存在: {path}")
            return []
        if self.target:
            return [self.target]
        return []

    def log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    def step(self, name: str):
        self._step_num += 1
        print(f"\n[{self._step_num}/9] {name}")
        print("-" * 40)

    def run(self):
        os.makedirs(self.output_dir, exist_ok=True)

        # ================================================================
        # Step 1: 被动子域名 (subfinder + crt.sh)
        # ================================================================
        self.step("被动子域名收集")
        subs = set()
        try:
            r = subprocess.run(
                ["subfinder", "-d", self.target, "-silent"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                for s in r.stdout.strip().splitlines():
                    if s:
                        subs.add(s.strip())
                self.log(f"  subfinder: {len(subs)} 子域名")
        except Exception as e:
            self.log(f"  subfinder跳过: {e}")
        time.sleep(self.SLEEP)

        # 保存
        with open(os.path.join(self.output_dir, "1_subdomains_passive.txt"), "w") as f:
            f.write("\n".join(sorted(subs)))

        # ================================================================
        # Step 1.5: FOFA 网络空间测绘
        # ================================================================
        self.step("1.5 FOFA 网络空间测绘")
        if self.FOFA_EMAIL and self.FOFA_KEY:
            try:
                from fofa import Client as FofaClient
                fc = FofaClient(self.FOFA_EMAIL, self.FOFA_KEY)
                fofa_results: dict = {"domain": [], "ip": [], "cert": []}

                query = f'domain="{self.target}" || cert="{self.target}"'
                self.log(f"  FOFA: {query}")
                data = fc.search(query, size=100)
                if data and isinstance(data, dict) and "results" in data:
                    for row in data["results"]:
                        if len(row) >= 2:
                            fofa_results["domain"].append({"ip": row[0], "domain": row[1]})
                            if row[0] not in fofa_results["ip"]:
                                fofa_results["ip"].append(row[0])
                    self.log(f"  FOFA: +{len(fofa_results['domain'])}条关联资产")

                with open(os.path.join(self.output_dir, "1.5_fofa.json"), "w") as f:
                    json.dump(fofa_results, f, indent=2, ensure_ascii=False)
                for entry in fofa_results["domain"]:
                    d = entry.get("domain", "")
                    if d and d not in subs:
                        subs.add(d)
            except Exception as e:
                self.log(f"  FOFA跳过: {e}")
        else:
            self.log(f"  FOFA未配置 (设置 FOFA_EMAIL + FOFA_KEY)")
        time.sleep(1)

        # ================================================================
        # Step 2: HTTP存活检测 (httpx)
        # ================================================================
        self.step("HTTP存活检测")
        if subs:
            sub_list = os.path.join(self.output_dir, "1_subdomains_passive.txt")
            try:
                r = subprocess.run(
                    ["httpx", "-l", sub_list, "-silent", "-status-code",
                     "-title", "-tech-detect", "-t", "1", "-o",
                     os.path.join(self.output_dir, "2_alive.txt")],
                    capture_output=True, text=True, timeout=30
                )
                self.log(f"  httpx完成")
            except Exception as e:
                self.log(f"  httpx跳过: {e}")
        time.sleep(self.SLEEP)

        # ================================================================
        # Step 3: 历史URL收集 (gau)
        # ================================================================
        self.step("历史URL收集")
        try:
            r = subprocess.run(
                ["gau", "--o", os.path.join(self.output_dir, "3_urls.txt"),
                 self.target],
                capture_output=True, text=True, timeout=60
            )
            # 统计URL数
            if os.path.exists(os.path.join(self.output_dir, "3_urls.txt")):
                count = sum(1 for _ in open(os.path.join(self.output_dir, "3_urls.txt")))
                self.log(f"  gau: {count} 个URL")
        except Exception as e:
            self.log(f"  gau跳过: {e}")
        time.sleep(self.SLEEP)

        # ================================================================
        # Step 4: JS端点挖掘 (katana)
        # ================================================================
        self.step("4 JS端点挖掘")
        self.log(f"  hakrawler(手动): echo 'https://{self.target}' | hakrawler -depth 2 -s")
        # katana: JS深度端点挖掘
        try:
            r = subprocess.run(
                ["katana", "-u", f"https://{self.target}", "-jc", "-kf",
                 "-c", "1", "-o", os.path.join(self.output_dir, "4b_js_endpoints.txt")],
                capture_output=True, text=True, timeout=30
            )
            if os.path.exists(os.path.join(self.output_dir, "4b_js_endpoints.txt")):
                count = sum(1 for _ in open(os.path.join(self.output_dir, "4b_js_endpoints.txt")))
                self.log(f"  katana: {count} 个端点")
        except Exception as e:
            self.log(f"  katana跳过: {e}")
        time.sleep(self.SLEEP)

        # ================================================================
        # Step 5: 技术指纹识别
        # ================================================================
        self.step("技术指纹识别")
        from aimy.tools.recon.tech_fingerprint import fingerprint_tech
        try:
            fp = fingerprint_tech(f"https://{self.target}")
            self.log(f"  技术栈: {fp.get('tech_stack', '未知')}")
            with open(os.path.join(self.output_dir, "5_fingerprint.json"), "w") as f:
                json.dump(fp, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log(f"  指纹识别跳过: {e}")
        time.sleep(self.SLEEP)

        # ================================================================
        # Step 6: 攻击面分析 (技术栈映射)
        # ================================================================
        self.step("攻击面分析")
        from aimy.tools.attack_surface import AttackSurfaceAnalyzer
        aa = AttackSurfaceAnalyzer()
        try:
            surface = aa.analyze(f"https://{self.target}")
            with open(os.path.join(self.output_dir, "6_attack_surface.json"), "w") as f:
                json.dump(surface, f, indent=2, ensure_ascii=False)
            self.log(f"  攻击面分析完成")
        except Exception as e:
            self.log(f"  攻击面分析跳过: {e}")
        time.sleep(self.SLEEP)

        # ================================================================
        # Step 7: 端口扫描
        # ================================================================
        self.step("端口扫描 (仅常见端口)")
        from aimy.tools.recon.port_scanner import PortScanner
        ps = PortScanner()
        try:
            ports = ps.scan(self.target, ports=[80, 443, 8080, 8443, 3000, 5000, 8000, 9090])
            with open(os.path.join(self.output_dir, "7_ports.json"), "w") as f:
                json.dump(ports, f, indent=2)
            self.log(f"  开放端口: {[p['port'] for p in ports if p.get('open')]}")
        except Exception as e:
            self.log(f"  端口扫描跳过: {e}")
        time.sleep(self.SLEEP)

        # ================================================================
        # Step 8: 目录枚举
        # ================================================================
        self.step("目录枚举 (关键路径)")
        from aimy.tools.recon.dir_fuzzer import DirFuzzer
        df = DirFuzzer()
        try:
            paths = df.fuzz(f"https://{self.target}",
                          wordlist=["/api", "/admin", "/.git", "/.env", "/swagger",
                                   "/graphql", "/actuator", "/v1", "/v2", "/health",
                                   "/metrics", "/debug", "/console", "/backup"])
            with open(os.path.join(self.output_dir, "8_paths.json"), "w") as f:
                json.dump(paths, f, indent=2)
            found = [p for p in paths if p.get("status", 0) < 400]
            self.log(f"  发现路径: {len(found)} 条")
        except Exception as e:
            self.log(f"  目录枚举跳过: {e}")
        time.sleep(self.SLEEP)

        # ================================================================
        # Step 9: 汇总报告
        # ================================================================
        self.step("汇总报告")
        summary = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "steps": {
                "1_subdomains_passive": len(subs),
                "3_urls_collected": self._count_lines("3_urls.txt"),
                "4_js_endpoints": self._count_lines("4b_js_endpoints.txt"),
                "7_open_ports": [],  # filled below
                "8_paths_found": 0,
            },
            "recommended_test_order": [],
        }

        # 读取各步骤结果
        ports_file = os.path.join(self.output_dir, "7_ports.json")
        if os.path.exists(ports_file):
            try:
                with open(ports_file) as f:
                    port_data = json.load(f)
                summary["steps"]["7_open_ports"] = [p["port"] for p in port_data if p.get("open")]
            except: pass

        paths_file = os.path.join(self.output_dir, "8_paths.json")
        if os.path.exists(paths_file):
            try:
                with open(paths_file) as f:
                    path_data = json.load(f)
                summary["steps"]["8_paths_found"] = len([p for p in path_data if p.get("status", 0) < 400])
            except: pass

        # 技术栈推荐测试顺序
        fp_file = os.path.join(self.output_dir, "5_fingerprint.json")
        if os.path.exists(fp_file):
            try:
                with open(fp_file) as f:
                    fp_data = json.load(f)
                tech = fp_data.get("tech_stack", "").lower()
                if "spring" in tech or "java" in tech:
                    summary["recommended_test_order"] = ["SpEL注入", "Actuator泄露", "反序列化"]
                elif "nginx" in tech or "php" in tech:
                    summary["recommended_test_order"] = ["LFI", "文件上传", "SQL注入"]
                elif "wordpress" in tech:
                    summary["recommended_test_order"] = ["wp插件漏洞", "SQL注入", "XSS"]
            except: pass

        with open(os.path.join(self.output_dir, "9_summary.json"), "w") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print(f"\n{'='*50}")
        print(f"资产收集完成 → {self.output_dir}")
        print(f"  子域名: {len(subs)}")
        print(f"  URL收集: {summary['steps']['3_urls_collected']}")
        print(f"  JS端点: {summary['steps']['4_js_endpoints']}")
        if summary["steps"]["7_open_ports"]:
            print(f"  开放端口: {summary['steps']['7_open_ports']}")
        print(f"  发现路径: {summary['steps']['8_paths_found']}")
        print(f"{'='*50}")

        return summary

    def _count_lines(self, filename: str) -> int:
        path = os.path.join(self.output_dir, filename)
        if os.path.exists(path):
            try:
                return sum(1 for _ in open(path))
            except:
                return 0
        return 0


def main():
    parser = argparse.ArgumentParser(description="九步资产收集管线")
    parser.add_argument("--target", "-t", help="目标域名")
    parser.add_argument("--company", "-c", help="公司名 (企查查+FOFA联合模式)")
    parser.add_argument("--list", "-l", help="目标文件 (每行一个域名)")
    parser.add_argument("--output", "-o", default="", help="输出目录")
    args = parser.parse_args()

    if not args.target and not args.company and not args.list:
        parser.print_help()
        print("\n至少需要 --target / --company / --list 其中之一")
        return

    pipeline = ReconPipeline(target=args.target, company=args.company,
                             target_list=args.list, output_dir=args.output)
    targets = pipeline._resolve_targets()
    if not targets and not args.company:
        return
    for t in targets:
        pipeline.target = t
        pipeline.run()


if __name__ == "__main__":
    main()
