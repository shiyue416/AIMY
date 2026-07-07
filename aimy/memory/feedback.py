"""FeedbackDB — H1 report outcome tracker → technique scoring flywheel."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path


class FeedbackDB:
    """Record H1 report outcomes and score techniques by acceptance rate."""

    OUTCOMES = {"accepted", "rejected", "informative", "duplicate", "na"}

    def __init__(self, db_path: str = "") -> None:
        self.db_path = Path(db_path) if db_path else Path.home() / ".aimy/feedback.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id   TEXT,
                technique   TEXT NOT NULL,
                vuln_class  TEXT NOT NULL,
                target_type TEXT,
                outcome     TEXT,
                severity    TEXT,
                bounty      REAL DEFAULT 0,
                submitted_at TEXT,
                resolved_at  TEXT
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tech ON reports(technique)")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS resources (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword      TEXT NOT NULL,
                path         TEXT NOT NULL UNIQUE,
                resource_type TEXT,
                indexed_at   TEXT
            )
        """)
        self._conn.commit()

    # ── Write ──────────────────────────────────────────────────────

    def record(self, technique: str, vuln_class: str, *,
               report_id: str = "", target_type: str = "",
               outcome: str = "", severity: str = "",
               bounty: float = 0.0) -> int:
        """Log a submitted report. outcome can be set later via resolve()."""
        row = self._conn.execute(
            """INSERT INTO reports
               (report_id, technique, vuln_class, target_type, outcome, severity, bounty, submitted_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (report_id, technique, vuln_class, target_type,
             outcome.lower(), severity.lower(), bounty,
             datetime.now().isoformat()),
        )
        self._conn.commit()
        return row.lastrowid  # type: ignore[return-value]

    def resolve(self, row_id: int, outcome: str, severity: str = "", bounty: float = 0.0) -> None:
        """Update outcome after H1 triage."""
        if outcome.lower() not in self.OUTCOMES:
            raise ValueError(f"outcome must be one of {self.OUTCOMES}")
        self._conn.execute(
            "UPDATE reports SET outcome=?, severity=?, bounty=?, resolved_at=? WHERE id=?",
            (outcome.lower(), severity.lower(), bounty, datetime.now().isoformat(), row_id),
        )
        self._conn.commit()

    # ── Score ──────────────────────────────────────────────────────

    def scores(self, min_submissions: int = 2) -> list[dict]:
        """Return techniques ranked by recency-weighted acceptance rate × avg_bounty.

        Actual acceptance rate is capped at 1.0. The recency_weight column is a separate
        ranking boost multiplier, not an acceptance rate inflator.
        """
        rows = self._conn.execute("""
            SELECT technique, vuln_class,
                   COUNT(*) AS total,
                   SUM(CASE WHEN outcome='accepted' THEN 1 ELSE 0 END) AS accepted,
                   COUNT(*) AS denom,
                   AVG(CASE WHEN outcome='accepted' THEN
                       CASE
                           WHEN julianday('now') - julianday(COALESCE(resolved_at, submitted_at)) < 30 THEN 2.0
                           WHEN julianday('now') - julianday(COALESCE(resolved_at, submitted_at)) < 90 THEN 1.5
                           ELSE 1.0
                       END ELSE 0 END) AS recency_score,
                   AVG(CASE WHEN outcome='accepted' THEN bounty ELSE 0 END) AS avg_bounty
            FROM reports
            WHERE outcome != ''
            GROUP BY technique, vuln_class
            HAVING total >= ?
            ORDER BY (1.0 * SUM(CASE WHEN outcome='accepted' THEN 1 ELSE 0 END) / COUNT(*))
                     * (1 + AVG(CASE WHEN outcome='accepted' THEN bounty ELSE 0 END) / 1000)
                     * AVG(CASE WHEN outcome='accepted' THEN
                         CASE
                             WHEN julianday('now') - julianday(COALESCE(resolved_at, submitted_at)) < 30 THEN 2.0
                             WHEN julianday('now') - julianday(COALESCE(resolved_at, submitted_at)) < 90 THEN 1.5
                             ELSE 1.0
                         END ELSE 0 END) DESC
        """, (min_submissions,)).fetchall()

        return [
            {
                "technique": r[0],
                "vuln_class": r[1],
                "total": r[2],
                "accepted": r[3],
                "rate": round(min(r[3] / r[2], 1.0), 2) if r[2] else 0.0,   # capped at 1.0
                "avg_bounty": round(r[5] or 0, 2),
                "recency_score": round(r[4] or 0, 2),
                "score": round((min(r[3]/r[2], 1.0) if r[2] else 0.0) * (1 + (r[5] or 0)/1000) * (r[4] or 1.0), 4),
            }
            for r in rows
        ]

    def top_techniques(self, vuln_class: str = "", n: int = 5) -> list[str]:
        """Return top-N technique names, optionally filtered by vuln_class."""
        all_scores = self.scores()
        if vuln_class:
            all_scores = [s for s in all_scores if vuln_class.lower() in s["vuln_class"].lower()]
        return [s["technique"] for s in all_scores[:n]]

    def stats(self) -> dict:
        r = self._conn.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN outcome='accepted' THEN 1 ELSE 0 END),
                   SUM(bounty)
            FROM reports WHERE outcome != ''
        """).fetchone()
        total, accepted, bounty = r[0] or 0, r[1] or 0, r[2] or 0.0
        return {
            "total": total,
            "accepted": accepted,
            "rate": round(accepted / total, 2) if total else 0.0,
            "total_bounty": round(bounty, 2),
        }

    # ── Resource index ─────────────────────────────────────────────

    def index_resources(self, references_dir: str) -> int:
        """Scan playbooks/ payloader/ methodology/ and write entries into DB.

        Returns count of newly indexed resources.
        """
        from pathlib import Path as P
        root = P(references_dir)
        KEYWORD_HINTS = {
            "oauth": "oauth", "jwt": "jwt", "saml": "saml",
            "xss": "xss", "ssrf": "ssrf", "rce": "rce",
            "sqli": "sqli", "sql": "sqli", "lfi": "lfi", "rfi": "lfi",
            "xxe": "xxe", "csrf": "csrf", "idor": "idor",
            "path": "path traversal", "traversal": "path traversal",
            "upload": "file upload", "file": "file upload",
            "logic": "logic", "api": "api",
            "intranet": "intranet", "llm": "llm", "ai": "llm",
            "ssti": "ssti", "smuggling": "smuggling",
            "auth": "authentication", "privilege": "privilege escalation",
            "methodology": "general", "priority": "general", "bypass": "general",
        }

        added = 0
        for subdir in ("playbooks", "payloader", "methodology"):
            for f in root.glob(f"{subdir}/**/*"):
                if not (f.is_file() or f.is_dir()):
                    continue
                rel = str(f.relative_to(root)).replace("\\", "/")
                # Infer keyword from path name
                name_lower = f.name.lower().replace("-", " ").replace("_", " ")
                keyword = next((v for k, v in KEYWORD_HINTS.items() if k in name_lower), "general")
                rtype = subdir.rstrip("s")  # playbook / payloader / methodology
                try:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO resources (keyword, path, resource_type, indexed_at) VALUES (?,?,?,?)",
                        (keyword, rel, rtype, datetime.now().isoformat()),
                    )
                    added += self._conn.execute("SELECT changes()").fetchone()[0]
                except Exception:
                    pass
        self._conn.commit()
        return added

    # ── Resource scoring ───────────────────────────────────────────

    def resource_scores(self) -> list[dict]:
        """Rank resources by H1 acceptance rate of their matched vuln_class."""
        rows = self._conn.execute("""
            SELECT r.path, r.resource_type, r.keyword,
                   SUM(CASE WHEN p.outcome='accepted' THEN 1 ELSE 0 END) AS accepted,
                   COUNT(p.id) AS total
            FROM resources r
            LEFT JOIN reports p ON (
                p.outcome != '' AND
                (LOWER(p.vuln_class) LIKE '%' || r.keyword || '%'
                 OR r.keyword = 'general')
            )
            GROUP BY r.path
            ORDER BY (CASE WHEN COUNT(p.id) > 0
                      THEN SUM(CASE WHEN p.outcome='accepted' THEN 1 ELSE 0 END) * 1.0 / COUNT(p.id)
                      ELSE 0 END) DESC
        """).fetchall()

        return [
            {"path": r[0], "type": r[1], "keyword": r[2],
             "accepted": int(r[3] or 0), "total": int(r[4] or 0),
             "rate": round(r[3] / r[4], 2) if r[4] else 0.0}
            for r in rows
        ]

    def export_jsonl(self, path: str) -> None:
        rows = self._conn.execute("SELECT * FROM reports").fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM reports LIMIT 0").description]
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(dict(zip(cols, row)), ensure_ascii=False) + "\n")

    def close(self) -> None:
        self._conn.close()
