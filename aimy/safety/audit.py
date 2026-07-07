"""Audit trail — logs every request for accountability."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path


class AuditTrail:
    """Records every outbound request for post-hunt review."""

    def __init__(self, audit_path: str = ""):
        if audit_path:
            self.path = Path(audit_path)
        else:
            self.path = Path(os.path.expanduser("~/.aimy/audit.jsonl"))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, url: str, method: str = "GET", status: str = "",
            scope_ok: bool = True, tool: str = "",
            target: str = "") -> None:
        entry = {
            "ts": datetime.now().isoformat(),
            "url": url,
            "method": method,
            "status": status,
            "scope_ok": scope_ok,
            "tool": tool,
            "target": target,
        }
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def tail(self, n: int = 50) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))
        except Exception:
            pass
        return entries[-n:]
