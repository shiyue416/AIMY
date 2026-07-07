"""PatternDB — cross-target pattern learning with optional SQLite index."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path


class PatternDB:
    """Stores and retrieves hunt patterns across targets.

    Uses JSONL as the source of truth with an optional SQLite index
    for fast queries.
    """

    def __init__(self, db_path: str = ""):
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path(os.path.expanduser("~/.aimy/patterns.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.jsonl_path = self.db_path.with_suffix(".jsonl")
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        try:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    vuln_class TEXT,
                    severity TEXT,
                    technique TEXT,
                    endpoint TEXT,
                    created_at TEXT,
                    tags TEXT
                )
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_vuln_class ON patterns(vuln_class)
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target ON patterns(target)
            """)
            self._conn.commit()
        except Exception:
            self._conn = None

    # ── Write ─────────────────────────────────────────────────────

    def add(self, target: str, vuln_class: str, severity: str,
            technique: str, endpoint: str = "", tags: list[str] | None = None) -> None:
        """Record a successful technique."""
        entry = {
            "target": target,
            "vuln_class": vuln_class,
            "severity": severity,
            "technique": technique,
            "endpoint": endpoint,
            "tags": tags or [],
            "created_at": datetime.now().isoformat(),
        }

        # Write to JSONL
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

        # Write to SQLite
        if self._conn:
            try:
                self._conn.execute(
                    "INSERT INTO patterns (target, vuln_class, severity, technique, endpoint, created_at, tags) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (target, vuln_class, severity, technique, endpoint,
                     entry["created_at"], ",".join(tags or [])),
                )
                self._conn.commit()
            except Exception:
                pass

    # ── Query ─────────────────────────────────────────────────────

    def find_by_class(self, vuln_class: str, limit: int = 20) -> list[dict]:
        """Find patterns for a vulnerability class."""
        if not self._conn:
            return self._jsonl_find("vuln_class", vuln_class, limit)

        rows = self._conn.execute(
            "SELECT target, vuln_class, severity, technique, endpoint, created_at, tags FROM patterns WHERE vuln_class LIKE ? ORDER BY created_at DESC LIMIT ?",
            (f"%{vuln_class}%", limit),
        ).fetchall()

        return [
            {
                "target": r[0], "vuln_class": r[1], "severity": r[2],
                "technique": r[3], "endpoint": r[4], "created_at": r[5],
                "tags": (r[6] or "").split(","),
            }
            for r in rows
        ]

    def find_by_target(self, target: str, limit: int = 20) -> list[dict]:
        """Find patterns for a specific target."""
        if not self._conn:
            return self._jsonl_find("target", target, limit)

        rows = self._conn.execute(
            "SELECT target, vuln_class, severity, technique, endpoint, created_at, tags FROM patterns WHERE target LIKE ? ORDER BY created_at DESC LIMIT ?",
            (f"%{target}%", limit),
        ).fetchall()

        return [
            {
                "target": r[0], "vuln_class": r[1], "severity": r[2],
                "technique": r[3], "endpoint": r[4], "created_at": r[5],
                "tags": (r[6] or "").split(","),
            }
            for r in rows
        ]

    def stats(self) -> dict:
        """Return summary statistics."""
        if not self._conn:
            return {"total": 0, "by_class": {}, "by_severity": {}}

        total = self._conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        by_class = {
            r[0]: r[1]
            for r in self._conn.execute(
                "SELECT vuln_class, COUNT(*) FROM patterns GROUP BY vuln_class ORDER BY COUNT(*) DESC LIMIT 20"
            ).fetchall()
        }
        by_sev = {
            r[0]: r[1]
            for r in self._conn.execute(
                "SELECT severity, COUNT(*) FROM patterns GROUP BY severity"
            ).fetchall()
        }
        return {"total": total, "by_class": by_class, "by_severity": by_sev}

    # ── Fallback ──────────────────────────────────────────────────

    def _jsonl_find(self, key: str, value: str, limit: int) -> list[dict]:
        """Fallback: grep JSONL file."""
        results = []
        if not self.jsonl_path.exists():
            return results
        try:
            with open(self.jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                        if value.lower() in str(e.get(key, "")).lower():
                            results.append(e)
                            if len(results) >= limit:
                                break
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
        return results

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
