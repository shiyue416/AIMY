"""HuntJournal — JSONL append-only hunt log with rotation."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path


class HuntJournal:
    """Append-only JSONL journal for recording hunt activities.

    Each line is a JSON object with: timestamp, event_type, target, data.
    Automatic rotation at 10MB, keeps 3 backups.
    """

    MAX_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_BACKUPS = 3

    def __init__(self, journal_path: str = ""):
        if journal_path:
            self.path = Path(journal_path)
        else:
            self.path = Path(os.path.expanduser("~/.aimy/journal.jsonl"))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ── Write ─────────────────────────────────────────────────────

    def record(self, event_type: str, target: str = "",
               data: dict | None = None) -> None:
        """Append an event to the journal."""
        self._rotate_if_needed()

        entry = {
            "ts": datetime.now().isoformat(),
            "type": event_type,
            "target": target,
            "data": data or {},
        }
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def record_finding(self, target: str, vuln_class: str, severity: str,
                       endpoint: str, summary: str) -> None:
        """Record a vulnerability finding."""
        self.record("finding", target, {
            "vuln_class": vuln_class,
            "severity": severity,
            "endpoint": endpoint,
            "summary": summary,
        })

    def record_tool_call(self, target: str, tool_name: str,
                         args: dict, result_preview: str = "",
                         success: bool = True) -> None:
        self.record("tool_call", target, {
            "tool": tool_name,
            "args": {k: str(v)[:100] for k, v in args.items()},
            "preview": result_preview[:200],
            "ok": success,
        })

    # ── Read ──────────────────────────────────────────────────────

    def tail(self, n: int = 50) -> list[dict]:
        """Return the last N entries."""
        if not self.path.exists():
            return []
        entries = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass
        return entries[-n:]

    def query(self, event_type: str | None = None, target: str | None = None,
              limit: int = 100) -> list[dict]:
        """Query entries by type and/or target."""
        results = []
        if not self.path.exists():
            return results
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        if event_type and e.get("type") != event_type:
                            continue
                        if target and target.lower() not in e.get("target", "").lower():
                            continue
                        results.append(e)
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
        return results[-limit:]

    # ── Maintenance ───────────────────────────────────────────────

    def _rotate_if_needed(self) -> None:
        """Rotate journal if it exceeds max size."""
        if not self.path.exists():
            return
        try:
            size = self.path.stat().st_size
            if size > self.MAX_SIZE:
                self._rotate()
        except Exception:
            pass

    def _rotate(self) -> None:
        """Shift journal.1 → journal.2 → journal.3, create new journal."""
        for i in range(self.MAX_BACKUPS, 0, -1):
            old = self.path.with_suffix(f".{i}")
            new = self.path.with_suffix(f".{i + 1}")
            if i >= self.MAX_BACKUPS and new.exists():
                new.unlink()
            if old.exists():
                old.rename(new)
        if self.path.exists():
            self.path.rename(self.path.with_suffix(".1"))

    @property
    def size_mb(self) -> float:
        if not self.path.exists():
            return 0.0
        return self.path.stat().st_size / (1024 * 1024)
