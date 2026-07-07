"""H1Sync — poll HackerOne API and auto-update FeedbackDB."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Iterator

import urllib.request
import urllib.error
import json
import base64

from aimy.memory.feedback import FeedbackDB

# H1 state → FeedbackDB outcome
_STATE_MAP = {
    "resolved": "accepted",
    "informative": "informative",
    "not-applicable": "na",
    "duplicate": "duplicate",
    "spam": "rejected",
}
_PENDING = {"new", "triaged", "needs-more-info"}

_API = "https://api.hackerone.com/v1"


class H1Client:
    def __init__(self, username: str, token: str) -> None:
        creds = base64.b64encode(f"{username}:{token}".encode()).decode()
        self._headers = {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(f"{_API}{path}", headers=self._headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())

    def reports(self, page: int = 1) -> Iterator[dict]:
        """Yield all reports (paginated)."""
        while True:
            data = self._get(f"/me/reports?page[number]={page}&page[size]=25")
            for r in data.get("data", []):
                yield r
            if not data.get("links", {}).get("next"):
                break
            page += 1
            time.sleep(0.5)  # ≤1 req/s


def sync(username: str, token: str, db: FeedbackDB | None = None,
         verbose: bool = True) -> dict:
    """Pull all resolved reports and upsert into FeedbackDB.

    Matches by report_id; skips pending reports and already-resolved rows.
    Returns counts: {synced, skipped, pending}.
    """
    close_db = db is None
    if db is None:
        db = FeedbackDB()

    client = H1Client(username, token)
    counts = {"synced": 0, "skipped": 0, "pending": 0}

    for report in client.reports():
        attrs = report.get("attributes", {})
        state = attrs.get("state", "")
        report_id = str(report.get("id", ""))
        title = attrs.get("title", "")
        severity = (attrs.get("severity") or {}).get("rating", "")
        bounty_amount = 0.0
        for tx in attrs.get("bounties", []):
            bounty_amount += float(tx.get("amount", 0))

        if state in _PENDING:
            counts["pending"] += 1
            continue

        outcome = _STATE_MAP.get(state)
        if not outcome:
            counts["skipped"] += 1
            continue

        # Check if already recorded
        existing = db._conn.execute(
            "SELECT id, outcome FROM reports WHERE report_id=?", (report_id,)
        ).fetchone()

        if existing:
            if existing[1] == outcome:
                counts["skipped"] += 1
                continue
            # Update existing row
            db.resolve(existing[0], outcome, severity=severity, bounty=bounty_amount)
        else:
            # Infer technique from title (best-effort)
            technique = _infer_technique(title)
            vuln_class = _infer_vuln_class(title)
            row_id = db.record(technique, vuln_class, report_id=report_id,
                               outcome=outcome, severity=severity, bounty=bounty_amount)

        counts["synced"] += 1
        if verbose:
            print(f"  [{outcome:12}] #{report_id} {title[:60]}")

    if close_db:
        db.close()

    return counts


def _infer_technique(title: str) -> str:
    """Extract technique hint from report title."""
    t = title.lower()
    for kw in ("ssrf", "rce", "idor", "sqli", "xss", "ssti", "lfi",
               "xxe", "csrf", "oauth", "jwt", "aci", "race condition"):
        if kw in t:
            return kw
    return "unknown"


def _infer_vuln_class(title: str) -> str:
    return _infer_technique(title)
