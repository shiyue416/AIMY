#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dedup — 自动去重引擎 (类似XBOW的SimHash+ImageHash)。

三级去重:
  1. 精确去重 — 完全相同的 technique+endpoint → 跳过
  2. 模糊去重 — SimHash 内容相似度 → 标记潜在重复
  3. H1 报告去重 — 提交前查已公开报告 → 避免撞车

用法:
    from aimy.tools.dedup import DedupEngine
    d = DedupEngine()
    d.check("SQLi in /api/users", "/api/users?id=1")  # 返回去重建议
"""

from __future__ import annotations

import json
import re
import sqlite3
import xxhash
from pathlib import Path
from datetime import datetime
from difflib import SequenceMatcher
from typing import Optional

# ── SimHash 实现 ────────────────────────────────────────────────────────────

def simhash(text: str, bits: int = 64) -> int:
    """文本 → SimHash指纹。相似文本的指纹汉明距离近。"""
    tokens = re.findall(r'\w+', text.lower())
    v = [0] * bits
    for t in tokens:
        h = xxhash.xxh64(t).intdigest()
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    fp = 0
    for i in range(bits):
        if v[i] > 0:
            fp |= (1 << i)
    return fp


def hamming_distance(a: int, b: int) -> int:
    """两个 SimHash 的汉明距离。越小越相似。"""
    return (a ^ b).bit_count()


def text_similarity(a: str, b: str) -> float:
    """文本相似度 0.0-1.0。"""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


# ── 去重引擎 ────────────────────────────────────────────────────────────────

DEFAULT_DB = Path.home() / ".aimy" / "dedup.db"


class DedupEngine:
    """去重引擎。

    存所有已记录的发现，支持精确匹配/SimHash模糊匹配/H1报告查重。
    """

    def __init__(self, db_path: str = ""):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                technique   TEXT NOT NULL,
                endpoint    TEXT,
                vuln_class  TEXT,
                simhash_val INTEGER,
                source      TEXT DEFAULT 'self',
                created_at  TEXT
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tech ON findings(technique)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_simhash ON findings(simhash_val)")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS h1_reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT NOT NULL,
                report_url  TEXT UNIQUE,
                vuln_class  TEXT,
                endpoint    TEXT,
                simhash_val INTEGER,
                created_at  TEXT
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_h1_sim ON h1_reports(simhash_val)")
        self._conn.commit()

    # ── 写入 ────────────────────────────────────────────────────────

    def record(self, technique: str, endpoint: str = "", vuln_class: str = "",
               source: str = "self") -> int:
        """记录一条发现（用于后续去重）。"""
        sh = simhash(technique)
        self._conn.execute(
            "INSERT INTO findings (technique, endpoint, vuln_class, simhash_val, source, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (technique, endpoint, vuln_class, sh, source, datetime.now().isoformat()),
        )
        self._conn.commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def record_h1(self, title: str, report_url: str, vuln_class: str = "",
                  endpoint: str = "") -> None:
        """记录一条 H1 公开报告（用于提交前去重）。"""
        sh = simhash(f"{title} {endpoint} {vuln_class}")
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO h1_reports (title, report_url, vuln_class, endpoint, simhash_val, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (title, report_url, vuln_class, endpoint, sh, datetime.now().isoformat()),
            )
            self._conn.commit()
        except Exception:
            pass

    # ── 检查去重 ────────────────────────────────────────────────────

    def check(self, technique: str, endpoint: str = "", vuln_class: str = "",
              simhash_threshold: int = 20) -> dict:
        """三级去重检查。

        返回:
          dedup:   True/False  → 是否建议跳过
          level:   "exact" | "fuzzy" | "h1_dedup" | "none"
          match:   匹配到的记录
          similar: 相似度详情
        """
        result = {
            "dedup": False,
            "level": "none",
            "match": None,
            "similar": [],
        }

        tec_lower = technique.lower().strip()
        ep_lower = endpoint.lower().strip() if endpoint else ""

        # 级别1: 精确去重
        rows = self._conn.execute(
            "SELECT technique, endpoint, vuln_class, source FROM findings WHERE technique=?",
            (technique,),
        ).fetchall()
        for r in rows:
            if ep_lower in r[1].lower() if r[1] else True:
                result["dedup"] = True
                result["level"] = "exact"
                result["match"] = {"technique": r[0], "endpoint": r[1], "source": r[3]}
                return result

        # 级别2: SimHash 模糊去重 (用 technique 单独算,不受 endpoint 干扰)
        sh = simhash(technique)
        rows = self._conn.execute(
            "SELECT technique, endpoint, vuln_class, simhash_val, source FROM findings",
        ).fetchall()
        for r in rows:
            # 计算 technique 层面的 SimHash 距离
            tech_sh = simhash(r[0])
            dist = hamming_distance(sh, tech_sh)
            if dist < simhash_threshold:
                sim = text_similarity(technique, r[0])
                result["similar"].append({
                    "technique": r[0],
                    "endpoint": r[1],
                    "source": r[4],
                    "hamming": dist,
                    "similarity": round(sim, 2),
                })

        # 如果有多条相似且文本相似度 > 0.6 → 判定为模糊重复
        high_sim = [s for s in result["similar"] if s["similarity"] > 0.6]
        if high_sim:
            result["dedup"] = True
            result["level"] = "fuzzy"
            result["match"] = high_sim[0]

        # 级别3: H1 报告去重
        h1_rows = self._conn.execute(
            "SELECT title, report_url, vuln_class, simhash_val FROM h1_reports",
        ).fetchall()
        h1_similar = []
        for r in h1_rows:
            dist = hamming_distance(sh, r[3])
            if dist < simhash_threshold:
                h1_similar.append({
                    "title": r[0],
                    "url": r[1],
                    "hamming": dist,
                })
        if h1_similar:
            result["h1_matches"] = sorted(h1_similar, key=lambda x: x["hamming"])[:5]

        return result

    # ── 批量导入 H1 报告 ────────────────────────────────────────────

    def import_h1_reports(self, h1_dir: str = "", verbose: bool = True) -> int:
        """从 references/h1-reports 导入已公开报告用于去重。"""
        if not h1_dir:
            candidates = [
                Path.home() / "Desktop/彦/references/h1-reports",
                Path.home() / "Desktop/小十月skill/references/h1-reports",
                Path.home() / ".aimy/references/h1-reports",
            ]
            for c in candidates:
                if c.exists():
                    h1_dir = str(c)
                    break

        if not h1_dir:
            return 0

        count = 0
        for f in Path(h1_dir).rglob("*.md"):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
                # 提取 H1 报告链接
                urls = re.findall(r'https://hackerone\.com/reports/\d+', text)
                titles = re.findall(r'\[([^\]]+)\]\(https://hackerone\.com/reports/\d+\)', text)
                for title, url in zip(titles, urls):
                    self.record_h1(title=title, report_url=url)
                    count += 1
            except Exception:
                continue

        if verbose:
            print(f"  [Dedup] 导入 {count} 条 H1 报告用于去重")
        return count

    # ── 集成进 record_finding ───────────────────────────────────────

    def check_and_record(self, technique: str, endpoint: str = "",
                         vuln_class: str = "", auto_record: bool = True) -> dict:
        """检查去重 + 自动记录（一体化）。"""
        result = self.check(technique, endpoint, vuln_class)

        # 如果未重复或只命中模糊 → 也记录（模糊重复只标记不阻止）
        if auto_record and result["level"] != "exact":
            self.record(technique, endpoint, vuln_class)

        return result

    def close(self):
        self._conn.close()


# =========================================================================
#  快捷函数 — 直接给 record_finding() 调用
# =========================================================================

_engine: Optional[DedupEngine] = None


def get_engine() -> DedupEngine:
    global _engine
    if _engine is None:
        _engine = DedupEngine()
        # 首次使用时自动导入 H1 报告
        count = _engine.import_h1_reports(verbose=False)
        if count > 0:
            print(f"  [Dedup] 已加载 {count} 条 H1 报告用于去重")
    return _engine


def check_dedup(technique: str, endpoint: str = "", vuln_class: str = "") -> dict:
    """快捷去重检查。"""
    return get_engine().check_and_record(technique, endpoint, vuln_class)


# =========================================================================
#  集成进 record_finding 的适配器 — 在 flywheel.py 里调用
# =========================================================================

def dedup_filter(technique: str, endpoint: str, vuln_class: str,
                 action: str = "warn") -> bool:
    """去重过滤器。在 record_finding() 开头调用。

    action:
      "warn"   → 发现重复时打印警告, 但继续记录 (默认)
      "block"  → 发现精确重复时返回 False, 不记录
      "auto"   → 精确重复拦截, 模糊重复只警告

    Returns: True=继续记录, False=跳过
    """
    result = check_dedup(technique, endpoint, vuln_class)

    if result["level"] == "exact":
        if action == "block" or action == "auto":
            print(f"  [Dedup] ⛔ 精确重复: {technique[:50]} → 跳过")
            return False
        print(f"  [Dedup] ⚠️  精确重复: {technique[:50]}")

    elif result["level"] == "fuzzy":
        sim = result["similar"][0]["similarity"] if result.get("similar") else 0
        if action == "block":
            print(f"  [Dedup] ⚠️  模糊重复(sim={sim}): {technique[:50]}")
        else:
            print(f"  [Dedup] 📝 模糊重复(sim={sim}): {technique[:50]}")

    if result.get("h1_matches"):
        for m in result["h1_matches"][:2]:
            print(f"  [Dedup] 🔍 H1已有类似报告: {m['title'][:50]}")

    return True


# =========================================================================
#  CLI
# =========================================================================

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Dedup — 自动去重引擎")
    ap.add_argument("--check", help="检查一条发现的去重情况")
    ap.add_argument("--endpoint", default="", help="端点URL")
    ap.add_argument("--vuln", default="", help="漏洞类型")
    ap.add_argument("--import-h1", action="store_true", help="导入 H1 报告")
    ap.add_argument("--stats", action="store_true", help="统计信息")
    ap.add_argument("--action", default="warn", choices=["warn", "block", "auto"])
    args = ap.parse_args()

    if args.import_h1:
        eng = DedupEngine()
        c = eng.import_h1_reports(verbose=True)
        print(f"  导入完成: {c} 条")
        eng.close()
    elif args.stats:
        eng = DedupEngine()
        rows = eng._conn.execute("SELECT COUNT(*) FROM findings").fetchone()
        h1 = eng._conn.execute("SELECT COUNT(*) FROM h1_reports").fetchone()
        print(f"  本地发现: {rows[0]} 条")
        print(f"  H1 报告:  {h1[0]} 条")
        eng.close()
    elif args.check:
        r = check_dedup(args.check, args.endpoint, args.vuln)
        print(json.dumps(r, ensure_ascii=False, indent=2))
