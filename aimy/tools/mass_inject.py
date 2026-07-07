#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MassInject — 批量注入已验证的 H1 报告技法到飞轮。

来源:
  1. h1-brain (PatrikFehrenbach/h1-brain) — 3600+ 条带赏金完整报告 (SQLite)
  2. low-hanging-vulns (zzzteph/low-hanging-vulns) — 全部 H1 公开报告 (JSON)
  3. hackerone-reports (reddelexc/hackerone-reports) — Top 报告 (CSV)

效果:
  注入 → FeedbackDB → 飞轮自动排名 → 优胜劣汰 → 每个漏洞类保留前5最佳技法
"""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from aimy.memory.feedback import FeedbackDB

# ── 仓库配置 ────────────────────────────────────────────────────────────────

REPOS = {
    "h1-brain": {
        "url": "https://github.com/PatrikFehrenbach/h1-brain",
        "dest": Path.home() / ".aimy/repos/h1-brain",
    },
    "low-hanging-vulns": {
        "url": "https://github.com/zzzteph/low-hanging-vulns",
        "dest": Path.home() / ".aimy/repos/low-hanging-vulns",
    },
    "hackerone-reports": {
        "url": "https://github.com/reddelexc/hackerone-reports",
        "dest": Path.home() / ".aimy/repos/hackerone-reports",
    },
}

REFERENCES_DIR = Path(__file__).parent.parent.parent / "references"

# 本地已有的数据源
LOCAL_CSV = REFERENCES_DIR / "hackerone-reports-bug-bounty" / "data.csv"
LOCAL_TOPS = REFERENCES_DIR / "hackerone-reports-bug-bounty" / "tops_by_bug_type"


# ── 克隆管理 ──────────────────────────────────────────────────────────────


def _clone(repo_name: str, verbose: bool = True) -> Optional[Path]:
    """克隆一个仓库（如果已存在就跳过）。"""
    cfg = REPOS.get(repo_name)
    if not cfg:
        print(f"  [!] 未知仓库: {repo_name}")
        return None

    dest = cfg["dest"]
    if dest.exists():
        if verbose:
            print(f"  [~] {repo_name} 已存在: {dest}")
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", cfg["url"], str(dest)],
            check=True, capture_output=True, timeout=180,
        )
        if verbose:
            print(f"  [+] 克隆 {repo_name} → {dest}")
        return dest
    except Exception as e:
        print(f"  [!] 克隆 {repo_name} 失败: {e}")
        return None


# ── 注入器基类 ────────────────────────────────────────────────────────────

class BaseInjector:
    """注入器基类。每个来源继承此类实现自己的解析逻辑。"""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.count = {"injected": 0, "skipped": 0}

    def log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    def inject(self, db: FeedbackDB):
        """子类实现此方法。"""
        raise NotImplementedError


# ── 注入器1: h1-brain (SQLite, 3600+ 报告) ───────────────────────────────

class H1BrainInjector(BaseInjector):
    """从 h1-brain SQLite 数据库注入 3600+ 条已验证 H1 报告。"""

    # 弱点类型 → 漏洞类映射
    WEAKNESS_MAP = {
        "xss": "xss", "cross-site": "xss",
        "sql injection": "sqli", "sqli": "sqli",
        "ssrf": "ssrf", "server-side request": "ssrf",
        "idor": "idor", "insecure direct": "idor", "broken object": "idor", "bola": "idor",
        "rce": "rce", "remote code": "rce", "command injection": "cmdi",
        "xxe": "xxe", "xml external": "xxe",
        "csrf": "csrf", "cross-site request": "csrf",
        "ssti": "ssti", "template injection": "ssti",
        "lfi": "lfi", "path traversal": "lfi", "file inclusion": "lfi",
        "open redirect": "open redirect",
        "authentication bypass": "auth bypass", "auth bypass": "auth bypass",
        "privilege escalation": "privilege escalation",
        "information disclosure": "information disclosure",
        "business logic": "business logic",
        "race condition": "race condition",
        "jwt": "jwt",
        "oauth": "oauth",
        "graphql": "graphql",
        "cors": "cors",
        "subdomain takeover": "subdomain takeover",
        "clickjacking": "clickjacking",
        "crlf": "crlf", "http response splitting": "crlf",
        "smuggling": "smuggling", "request smuggling": "smuggling",
        "cache poisoning": "cache poisoning",
        "prototype pollution": "prototype pollution",
        "file upload": "file upload",
        "account takeover": "account takeover", "ato": "account takeover",
        "denial of service": "denial of service", "dos": "denial of service",
        "mfa bypass": "mfa bypass",
        "saml": "saml",
        "deserialization": "deserialization",
    }

    def inject(self, db: FeedbackDB):
        dst = REPOS["h1-brain"]["dest"]
        db_path = dst / "disclosed_reports.db"
        if not db_path.exists():
            self.log(f"[!] h1-brain DB 不存在: {db_path}")
            return

        conn = sqlite3.connect(str(db_path))
        try:
            rows = conn.execute(
                "SELECT title, vulnerability_type, bounty_amount, report_url, "
                "cve_id, weakness_id, severity, report_body "
                "FROM disclosed_reports"
            ).fetchall()
        except sqlite3.OperationalError:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            self.log(f"[!] 未知表结构, 可用表: {[r[0] for r in rows]}")
            conn.close()
            return

        self.log(f"[h1-brain] 读取到 {len(rows)} 条报告")

        for row in rows:
            title, vtype, bounty, url, cve, wid, severity, body = row
            if not title:
                self.count["skipped"] += 1
                continue

            # 映射漏洞类
            vuln_class = self._map_class(vtype or title or "")
            if not vuln_class:
                self.count["skipped"] += 1
                continue

            # 取标题前100字作技法描述
            technique = title[:120]

            # 检查去重
            existing = db._conn.execute(
                "SELECT id FROM reports WHERE technique=? AND vuln_class=?",
                (technique, vuln_class),
            ).fetchone()
            if existing:
                self.count["skipped"] += 1
                continue

            # 赏金权重
            bounty_val = float(bounty or 0)
            if bounty_val <= 0:
                bounty_val = self._default_bounty(severity)

            # 注入
            db.record(
                technique=technique,
                vuln_class=vuln_class,
                report_id=url.split("/")[-1] if url else "",
                target_type="external:h1-brain",
                outcome="accepted",
                severity=severity.lower() if severity else "medium",
                bounty=bounty_val,
            )
            self.count["injected"] += 1

        conn.close()
        self.log(f"[h1-brain] 注入: {self.count['injected']}, 跳过: {self.count['skipped']}")

    def _map_class(self, text: str) -> str:
        t = text.lower().replace("_", " ").replace("-", " ")
        for key, cls in self.WEAKNESS_MAP.items():
            if key in t:
                return cls
        # Extract first word as fallback
        words = t.split()
        return words[0][:20] if words else ""

    def _default_bounty(self, severity: str) -> float:
        s = severity.lower() if severity else ""
        return {"critical": 5000, "high": 2500, "medium": 1000, "low": 300}.get(s, 500)


# ── 注入器2: low-hanging-vulns (JSON, 全量H1报告) ──────────────────────

class LowHangingVulnsInjector(BaseInjector):
    """从 low-hanging-vulns JSON 文件注入 H1 报告。"""

    SEVERITY_MAP = {
        "critical": ("critical", 5000),
        "high": ("high", 2500),
        "medium": ("medium", 1000),
        "low": ("low", 300),
        "none": ("informative", 0),
    }

    def inject(self, db: FeedbackDB):
        dst = REPOS["low-hanging-vulns"]["dest"]
        reports_dir = dst / "bugbounty" / "H1" / "reports"
        if not reports_dir.exists():
            self.log(f"[!] low-hanging-vulns 目录不存在: {reports_dir}")
            # 尝试找其他路径
            alt = dst / "reports"
            if alt.exists():
                reports_dir = alt
            else:
                return

        count = 0
        for f in sorted(reports_dir.rglob("*.json")):
            if count >= 2000:  # 上限防太多
                break
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue

            title = data.get("title", data.get("vulnerability_information", ""))
            if not title:
                continue
            title = title[:150]

            vtype = data.get("weakness", data.get("vulnerability_type", ""))
            vuln_class = self._map_class(vtype or title)
            if not vuln_class:
                continue

            sev = (data.get("severity") or "").lower()
            severity, bounty = self.SEVERITY_MAP.get(
                sev, ("medium", 1000)
            )

            # 取 report_id
            report_id = data.get("report_id", data.get("id", ""))
            url = f"https://hackerone.com/reports/{report_id}" if report_id else ""

            # 去重
            existing = db._conn.execute(
                "SELECT id FROM reports WHERE technique=? AND vuln_class=?",
                (title, vuln_class),
            ).fetchone()
            if existing:
                continue

            # 注入
            db.record(
                technique=title,
                vuln_class=vuln_class,
                report_id=str(report_id),
                target_type="external:low-hanging-vulns",
                outcome="accepted",
                severity=severity,
                bounty=bounty,
            )
            count += 1

        self.count["injected"] = count
        self.log(f"[low-hanging-vulns] 注入: {count} 条")

    def _map_class(self, text: str) -> str:
        t = text.lower().replace("_", " ").replace("-", " ")
        # 常见弱点名映射
        for key, cls in [
            ("xss", "xss"), ("cross-site script", "xss"),
            ("sql injection", "sqli"), ("sqli", "sqli"),
            ("ssrf", "ssrf"), ("server side request", "ssrf"),
            ("idor", "idor"), ("insecure direct", "idor"),
            ("rce", "rce"), ("remote code", "rce"), ("command injection", "cmdi"),
            ("xxe", "xxe"),
            ("csrf", "csrf"),
            ("ssti", "ssti"), ("template injection", "ssti"),
            ("lfi", "lfi"), ("path traversal", "lfi"), ("file inclusion", "lfi"),
            ("open redirect", "open redirect"),
            ("auth bypass", "auth bypass"), ("authentication bypass", "auth bypass"),
            ("privilege escalation", "privilege escalation"),
            ("information disclosure", "information disclosure"),
            ("business logic", "business logic"),
            ("race condition", "race condition"),
            ("jwt", "jwt"),
            ("graphql", "graphql"),
            ("smuggling", "smuggling"),
            ("cache", "cache poisoning"),
        ]:
            if key in t:
                return cls
        return ""


# ── 注入器3: hackerone-reports (CSV) ───────────────────────────────────

class HackeroneReportsInjector(BaseInjector):
    """从 reddelexc/hackerone-reports CSV 注入。"""

    def inject(self, db: FeedbackDB):
        dst = REPOS["hackerone-reports"]["dest"]
        csv_path = dst / "data.csv"
        if not csv_path.exists():
            self.log(f"[!] hackerone-reports CSV 不存在: {csv_path}")
            return

        count = 0
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                title = (row.get("title") or row.get("Title") or "").strip()
                if not title:
                    continue

                vuln_type = (row.get("type") or row.get("Type") or "").lower()
                bounty_str = (row.get("bounty") or row.get("Bounty") or "0").replace("$", "").replace(",", "")
                severity = (row.get("severity") or row.get("Severity") or "").lower()

                # 映射漏洞类
                vuln_class = self._map_class(vuln_type or title)
                if not vuln_class:
                    continue

                bounty_val = float(bounty_str) if bounty_str.replace(".", "").isdigit() else 500

                # 去重
                existing = db._conn.execute(
                    "SELECT id FROM reports WHERE technique=?",
                    (title[:120],),
                ).fetchone()
                if existing:
                    continue

                db.record(
                    technique=title[:120],
                    vuln_class=vuln_class,
                    report_id=row.get("id", ""),
                    target_type="external:hackerone-reports",
                    outcome="accepted",
                    severity=severity or "medium",
                    bounty=bounty_val,
                )
                count += 1
                if count >= 1500:
                    break

        self.count["injected"] = count
        self.log(f"[hackerone-reports] 注入: {count} 条")

    def _map_class(self, text: str) -> str:
        t = text.lower()
        m = {
            "xss": "xss", "cross site script": "xss",
            "sqli": "sqli", "sql injection": "sqli",
            "ssrf": "ssrf",
            "idor": "idor",
            "rce": "rce", "remote code": "rce",
            "xxe": "xxe",
            "csrf": "csrf",
            "ssti": "ssti",
            "lfi": "lfi", "path traversal": "lfi",
            "open redirect": "open redirect",
            "auth bypass": "auth bypass",
            "privilege": "privilege escalation",
            "info": "information disclosure",
            "business": "business logic",
            "race": "race condition",
            "jwt": "jwt",
            "graphql": "graphql",
            "smuggling": "smuggling",
        }
        for key, cls in m.items():
            if key in t:
                return cls
        return ""


# ── 注入器4: 本地 data.csv (14,553 条，已有) ──────────────────────────

class LocalCSVInjector(BaseInjector):
    """从本地已存在的 data.csv 注入 14,553 条 H1 报告。"""

    VULN_MAP = {
        "xss": "xss", "cross site script": "xss",
        "sqli": "sqli", "sql injection": "sqli",
        "ssrf": "ssrf",
        "idor": "idor",
        "rce": "rce", "remote code": "rce", "command injection": "cmdi",
        "xxe": "xxe",
        "csrf": "csrf",
        "ssti": "ssti", "template injection": "ssti",
        "lfi": "lfi", "path traversal": "lfi", "file inclusion": "lfi",
        "open redirect": "open redirect",
        "auth bypass": "auth bypass", "auth": "auth bypass",
        "privilege": "privilege escalation",
        "information disclosure": "information disclosure",
        "info disclosure": "information disclosure",
        "business logic": "business logic", "logic": "business logic",
        "race": "race condition",
        "jwt": "jwt",
        "graphql": "graphql",
        "cors": "cors",
        "subdomain takeover": "subdomain takeover",
        "clickjack": "clickjacking",
        "crlf": "crlf",
        "smuggling": "smuggling",
        "cache": "cache poisoning",
        "prototype": "prototype pollution",
        "upload": "file upload",
        "account takeover": "account takeover", "ato": "account takeover",
        "denial": "denial of service", "dos": "denial of service",
        "mfa": "mfa bypass",
        "deserialization": "deserialization",
        "saml": "saml",
        "oauth": "oauth",
    }

    def inject(self, db: FeedbackDB):
        if not LOCAL_CSV.exists():
            self.log(f"[!] 本地 CSV 不存在: {LOCAL_CSV}")
            return

        count = 0
        with open(LOCAL_CSV, "r", encoding="utf-8", errors="ignore") as f:
            for row in csv.DictReader(f):
                title = (row.get("title") or "").strip()
                if not title or len(title) < 10:
                    continue

                vuln_type = (row.get("vuln_type") or "").lower()
                bounty_str = (row.get("bounty") or "0").replace("$", "").replace(",", "")
                upvotes = (row.get("upvotes") or "0")
                link = (row.get("link") or "")

                vuln_class = self._map_class(vuln_type or title)
                if not vuln_class:
                    continue

                bounty_val = float(bounty_str) if bounty_str.replace(".", "").isdigit() else 0
                if bounty_val <= 0:
                    try:
                        bounty_val = int(upvotes) * 10
                    except ValueError:
                        bounty_val = 200

                existing = db._conn.execute(
                    "SELECT id FROM reports WHERE technique=? AND vuln_class=?",
                    (title[:120], vuln_class),
                ).fetchone()
                if existing:
                    continue

                report_id = ""
                if link:
                    m = re.search(r'reports/(\d+)', link)
                    if m:
                        report_id = m.group(1)

                db.record(
                    technique=title[:120],
                    vuln_class=vuln_class,
                    report_id=report_id,
                    target_type="external:local-csv",
                    outcome="accepted",
                    severity="medium",
                    bounty=bounty_val,
                )
                count += 1

        self.count["injected"] = count
        self.log(f"[local-csv] 注入: {count} 条")

    def _map_class(self, text: str) -> str:
        t = text.lower()
        for key, cls in self.VULN_MAP.items():
            if key in t:
                return cls
        return ""


# =========================================================================
#  一键注入全流程
# =========================================================================

def sync_all(
    clone: bool = True,
    inject: bool = True,
    upgrade: bool = True,
    prune: bool = True,
    max_per_source: int = 2000,
    verbose: bool = True,
) -> dict:
    """全流程: 克隆 → 注入 → 升级 → 淘汰。

    1. 克隆/更新 3 个 H1 报告仓库
    2. 解析报告注入 FeedbackDB (标记为 external:h1-dataset)
    3. 飞轮升级技能文件 (FLYWHEEL_APPEND)
    4. 淘汰低排名的 (保留每类前5)
    """
    result = {}

    if clone:
        for name in REPOS:
            _clone(name, verbose=verbose)

    if inject:
        db = FeedbackDB()
        total = {"injected": 0, "skipped": 0}

        for name, injector_cls in [
            ("local-csv", LocalCSVInjector),
            ("h1-brain", H1BrainInjector),
            ("low-hanging-vulns", LowHangingVulnsInjector),
            ("hackerone-reports", HackeroneReportsInjector),
        ]:
            if name == "local-csv":
                inj = injector_cls(verbose=verbose)
                inj.inject(db)
                total["injected"] += inj.count["injected"]
                total["skipped"] += inj.count["skipped"]
            elif REPOS.get(name) and REPOS[name]["dest"].exists():
                inj = injector_cls(verbose=verbose)
                inj.inject(db)
                total["injected"] += inj.count["injected"]
                total["skipped"] += inj.count["skipped"]
            else:
                if verbose:
                    print(f"  [~] {name} 未克隆, 跳过")
            total["injected"] += inj.count["injected"]
            total["skipped"] += inj.count["skipped"]

        db.close()
        result["inject"] = total
        if verbose:
            print(f"\n  [+] 总计注入: {total['injected']} 条 H1 报告技法")

    if upgrade:
        try:
            from aimy.memory.skill_upgrader import upgrade_skills
            u = upgrade_skills(min_accepted=1, verbose=verbose)
            result["upgrade"] = u
            if verbose:
                print(f"  [+] 升级技能文件: {u.get('upgraded', 0)} 个")
        except Exception as e:
            result["upgrade_error"] = str(e)

    if prune:
        try:
            from aimy.memory.external_sync import prune_low_rank_external
            p = prune_low_rank_external(keep_top_n=5, dry_run=False, verbose=verbose)
            result["prune"] = p
        except Exception as e:
            result["prune_error"] = str(e)

    return result


# =========================================================================
#  CLI
# =========================================================================

def main():
    import argparse
    ap = argparse.ArgumentParser(description="MassInject — 批量注入 H1 报告技法到飞轮")
    ap.add_argument("--clone-only", action="store_true", help="只克隆不注入")
    ap.add_argument("--no-clone", action="store_true", help="跳过克隆")
    ap.add_argument("--no-inject", action="store_true", help="跳过注入")
    ap.add_argument("--no-upgrade", action="store_true", help="跳过技能升级")
    ap.add_argument("--no-prune", action="store_true", help="跳过淘汰")
    ap.add_argument("--verbose", action="store_true", default=True)
    args = ap.parse_args()

    if args.clone_only:
        for name in REPOS:
            _clone(name, verbose=True)
        print("done")
        return

    result = sync_all(
        clone=not args.no_clone,
        inject=not args.no_inject,
        upgrade=not args.no_upgrade,
        prune=not args.no_prune,
        verbose=args.verbose,
    )

    i = result.get("inject", {})
    print(f"\ninjected={i.get('injected', 0)}")


if __name__ == "__main__":
    main()
