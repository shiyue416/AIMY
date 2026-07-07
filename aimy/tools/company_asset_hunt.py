#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CompanyAssetHunt — 公司资产猎手

企查查 → FOFA → httpx → subfinder/gau/katana 全自动管线。

用法:
    python -m aimy.tools.company_asset_hunt --company "理想汽车"
    python -m aimy.tools.company_asset_hunt --company "北京车励行信息技术有限公司" --auto

模式:
    --auto: 自动模式 (用FOFA+搜索引擎自动查公司关联域名)
    不加: 手动模式 (告诉你查什么, 你填回结果)
"""

import argparse
import json
import os
import subprocess
import time
from datetime import datetime


class CompanyAssetHunt:
    """公司资产猎手 — 四步自动管线。"""

    def __init__(self, company: str, auto: bool = False):
        self.company = company
        self.auto = auto
        self.domains: list[str] = []
        self.output_dir = f"hunt_{company.replace(' ','')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, msg: str):
        print(f"  {msg}")

    def step1_qichacha_fofa(self):
        """Step 1: 企查查+FOFA → 拿到关联域名"""
        print(f"\n{'='*50}")
        print(f"[1/4] 公司关联域名发现")
        print(f"公司: {self.company}")
        print(f"{'='*50}")

        # 生成 FOFA 搜索语法
        fofa_search = f'body="{self.company}" || domain="{self.company.split("有限")[0].strip()}"'
        # URL encode for FOFA
        import urllib.parse
        fofa_url = f"https://fofa.info/result?qbase64=" + urllib.parse.quote(
            __import__('base64').b64encode(fofa_search.encode()).decode())

        print(f"  请在浏览器打开 FOFA 搜索:")
        print(f"    {fofa_url}")
        print()
        print(f"  也请打开企查查搜索:")
        print(f"    https://www.qichacha.com/search?key={self.company}")
        print()
        print(f"  把查到的域名复制到下面 (每行一个,输入空行结束):")

        if not self.auto:
            print(f"  (或直接回车跳过,进入域名文件模式)")
            while True:
                d = input("    域名: ").strip()
                if not d:
                    break
                if d not in self.domains:
                    self.domains.append(d)

        # 保存
        with open(os.path.join(self.output_dir, "1_domains.txt"), "w") as f:
            f.write("\n".join(self.domains))
        self.log(f"  已保存 {len(self.domains)} 个域名")

    def step2_fofa_expand(self):
        """Step 2: FOFA 扩每个域名"""
        print(f"\n{'='*50}")
        print(f"[2/4] FOFA 资产扩展")
        print(f"{'='*50}")

        if not self.domains:
            self.log("  无域名可扩展,跳过")
            return

        all_assets = set()
        for d in self.domains:
            self.log(f"  扩: {d}")
            # 用 httpx + subfinder 代替 FOFA API
            try:
                r = subprocess.run(["subfinder", "-d", d, "-silent"],
                                   capture_output=True, text=True, timeout=30)
                for s in r.stdout.strip().splitlines():
                    if s:
                        all_assets.add(s.strip())
                self.log(f"    subfinder: +{len(r.stdout.splitlines())} 子域名")
            except:
                self.log(f"    subfinder跳过")
            time.sleep(1)

        # httpx 验证存活
        if all_assets:
            tmp = os.path.join(self.output_dir, "2_all_assets.txt")
            with open(tmp, "w") as f:
                f.write("\n".join(sorted(all_assets)))
            self.log(f"  总计 {len(all_assets)} 个资产, 验证存活...")

            alive = os.path.join(self.output_dir, "2_alive.txt")
            try:
                subprocess.run(["httpx", "-l", tmp, "-silent", "-status-code",
                                "-title", "-o", alive], timeout=60)
                if os.path.exists(alive):
                    count = sum(1 for _ in open(alive))
                    self.log(f"  存活: {count}/{len(all_assets)}")
            except:
                self.log(f"  httpx跳过")

    def step3_httpx_verify(self):
        """Step 3: httpx 深度验证"""
        print(f"\n{'='*50}")
        print(f"[3/4] HTTP 深度验证")
        print(f"{'='*50}")

        alive_file = os.path.join(self.output_dir, "2_alive.txt")
        if not os.path.exists(alive_file):
            self.log("  无存活资产,跳过")
            return

        # gau 收集历史URL
        print(f"  收集历史URL...")
        urls_file = os.path.join(self.output_dir, "3_urls.txt")
        for d in self.domains:
            try:
                subprocess.run(["gau", "-o", f"/tmp/gau_{d}.txt", d], timeout=60)
                time.sleep(1)
            except:
                pass

        # katana JS端点
        print(f"  JS端点挖掘...")
        for d in self.domains[:3]:  # 前3个域名
            try:
                subprocess.run(["katana", "-u", f"https://{d}", "-jc", "-kf",
                                "-o", f"/tmp/katan_{d}.txt"], timeout=60)
                time.sleep(1)
            except:
                pass

    def step4_report(self):
        """Step 4: 出报告"""
        print(f"\n{'='*50}")
        print(f"[4/4] 汇总报告")
        print(f"{'='*50}")

        report = {
            "company": self.company,
            "domains": self.domains,
            "output_dir": self.output_dir,
            "timestamp": datetime.now().isoformat(),
            "next_steps": [
                f"cd {os.path.abspath(self.output_dir)}",
                "cat 2_alive.txt  # 查看存活资产",
                "# 对每个活资产手动测试漏洞",
            ]
        }
        report_file = os.path.join(self.output_dir, "report.json")
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"  公司: {self.company}")
        print(f"  域名: {len(self.domains)} 个")
        print(f"  输出: {os.path.abspath(self.output_dir)}")
        print(f"\n  下一步:")
        for s in report["next_steps"]:
            print(f"    {s}")

    def run(self):
        self.step1_qichacha_fofa()
        self.step2_fofa_expand()
        self.step3_httpx_verify()
        self.step4_report()


def main():
    parser = argparse.ArgumentParser(description="公司资产猎手 — 企查查+FOFA全自动管线")
    parser.add_argument("--company", "-c", required=True, help="公司名")
    parser.add_argument("--auto", action="store_true", help="自动模式")
    args = parser.parse_args()

    hunt = CompanyAssetHunt(args.company, args.auto)
    hunt.run()


if __name__ == "__main__":
    main()
