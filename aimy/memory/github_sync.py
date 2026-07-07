"""GitHub Sync — import dmore/h1-reports + payload-kit into FeedbackDB + references.

Pulls the freshest H1 reports and payload collections from GitHub into the EVX flywheel.
"""

from __future__ import annotations

import re
import json
from datetime import datetime
from pathlib import Path

from aimy.memory.feedback import FeedbackDB

REFS = Path(__file__).parent.parent.parent / "references"
H1_REPORTS_DIR = REFS / "hackerone-reports-bug-bounty"
PAYLOAD_KIT_DIR = REFS / "payload-kit"

# Map H1 report filenames → vuln_class
TOP_FILE_MAP = {
    "TOPSQLI.md":         "sql injection",
    "TOPSSRF.md":         "ssrf",
    "TOPXSS.md":          "xss",
    "TOPRCE.md":          "rce",
    "TOPIDOR.md":         "idor",
    "TOPCSRF.md":         "csrf",
    "TOPXXE.md":          "xxe",
    "TOPAUTH.md":         "authentication bypass",
    "TOPOAUTH.md":        "oauth",
    "TOPOPENREDIRECT.md": "open redirect",
    "TOPRACECONDITION.md":"race condition",
    "TOPREQUESTSMUGGLING.md": "http request smuggling",
    "TOPGRAPHQL.md":      "graphql",
    "TOPBUSINESSLOGIC.md": "business logic errors",
    "TOPINFODISCLOSURE.md":"information disclosure",
    "TOPCLICKJACKING.md": "clickjacking",
    "TOPFILEREADING.md":  "path traversal",
    "TOPACCOUNTTAKEOVER.md":"account takeover",
    "TOPAPI.md":          "api security",
    "TOPAUTHORIZATION.md":"improper access control - generic",
    "TOPDOS.md":          "denial of service",
    "TOPMFA.md":          "mfa bypass",
    "TOPMOBILE.md":       "mobile security",
    "TOPOPENID.md":       "openid",
}


def _parse_report_line(line: str) -> dict | None:
    """Parse a H1 report line like:
    '1. [SQL Injection Extracts...](https://hackerone.com/reports/531051) to Starbucks - 787 upvotes, $0'
    """
    m = re.match(
        r'\d+\.\s*\[([^\]]+)\]\(https://hackerone\.com/reports/(\d+)\)\s+to\s+(.+?)\s*-\s*(\d+)\s*upvotes?,\s*\$?([\d,]+)',
        line
    )
    if not m:
        return None
    title = m.group(1).strip()
    report_id = m.group(2).strip()
    program = m.group(3).strip()
    upvotes = int(m.group(4))
    bounty_str = m.group(5).replace(",", "")
    bounty = float(bounty_str) if bounty_str.isdigit() else 0.0

    return {
        "title": title,
        "report_id": report_id,
        "program": program,
        "upvotes": upvotes,
        "bounty": bounty,
    }


def _infer_vuln_class_from_title(title: str) -> str:
    """Infer a more specific vuln_class from the report title."""
    t = title.lower()
    if "blind sql" in t or "blind sqli" in t:
        return "blind sqli"
    if "time-based" in t:
        return "time-based sqli"
    if "rce" in t or "remote code" in t:
        return "rce"
    if "ssrf" in t:
        return "ssrf"
    if "xss" in t or "cross-site" in t:
        return "xss"
    if "idor" in t:
        return "idor"
    if "xxe" in t:
        return "xxe"
    if "csrf" in t:
        return "csrf"
    return ""


def sync_h1_reports(min_upvotes: int = 50, verbose: bool = True) -> dict:
    """Import dmore/h1-reports into FeedbackDB.

    Each report becomes a technique record with outcome='accepted' (they're all
    validated, disclosed H1 reports) and bounty/upvote data.
    """
    if not H1_REPORTS_DIR.exists():
        return {"error": "h1-reports not cloned. Run: git clone https://github.com/dmore/hackerone-reports-bug-bounty references/hackerone-reports-bug-bounty"}

    tops_dir = H1_REPORTS_DIR / "tops_by_bug_type"
    if not tops_dir.exists():
        return {"error": "tops_by_bug_type directory not found"}

    db = FeedbackDB()
    imported = 0
    skipped = 0

    for filename, vuln_class in TOP_FILE_MAP.items():
        filepath = tops_dir / filename
        if not filepath.exists():
            continue

        content = filepath.read_text(encoding="utf-8", errors="ignore")
        for line in content.split("\n"):
            if not line.strip().startswith(tuple("0123456789")):
                continue

            report = _parse_report_line(line)
            if not report or report["upvotes"] < min_upvotes:
                skipped += 1
                continue

            # Deduplicate: check if this report_id already exists
            existing = db._conn.execute(
                "SELECT id FROM reports WHERE report_id=?",
                (report["report_id"],)
            ).fetchone()
            if existing:
                skipped += 1
                continue

            # Refine vuln_class from title if possible
            refined_vc = _infer_vuln_class_from_title(report["title"]) or vuln_class
            technique = report["title"][:80]

            db.record(
                technique=technique,
                vuln_class=refined_vc,
                report_id=report["report_id"],
                target_type=report["program"],
                outcome="accepted",
                severity="high" if report["bounty"] >= 1000 else "medium",
                bounty=report["bounty"],
            )
            imported += 1

    db.close()
    result = {"imported": imported, "skipped": skipped}

    if verbose:
        print(f"  [+] GitHub H1 Sync: {imported} new reports imported, {skipped} skipped/dup")
        # Show top program sources
        db2 = FeedbackDB()
        rows = db2._conn.execute(
            "SELECT target_type, COUNT(*) as cnt FROM reports WHERE outcome='accepted' "
            "GROUP BY target_type ORDER BY cnt DESC LIMIT 5"
        ).fetchall()
        db2.close()
        for prog, cnt in rows:
            if prog:
                print(f"      {prog[:30]}: {cnt} reports")

    return result


def register_payload_kit(verbose: bool = True) -> dict:
    """Register payload-kit as a reference source in FeedbackDB resources table."""
    if not PAYLOAD_KIT_DIR.exists():
        return {"error": "payload-kit not cloned"}

    db = FeedbackDB()
    added = 0
    for f in PAYLOAD_KIT_DIR.rglob("*.md"):
        rel = str(f.relative_to(REFS)).replace("\\", "/")
        name_lower = f.name.lower().replace("-", " ").replace("_", " ")
        # Infer keyword
        keyword_hints = {
            "sql": "sqli", "xss": "xss", "ssrf": "ssrf",
            "ssti": "ssti", "cmdi": "cmdi", "lfi": "lfi",
            "xxe": "xxe", "auth": "auth",
        }
        keyword = next((v for k, v in keyword_hints.items() if k in name_lower), "general")
        try:
            db._conn.execute(
                "INSERT OR IGNORE INTO resources (keyword, path, resource_type, indexed_at) VALUES (?,?,?,?)",
                (keyword, rel, "payload-kit", datetime.now().isoformat()),
            )
            added += db._conn.execute("SELECT changes()").fetchone()[0]
        except Exception:
            pass
    db._conn.commit()
    db.close()

    if verbose:
        print(f"  [+] payload-kit: {added} payload files registered")

    return {"registered": added}


# ── 外部顶级仓库配置 ─────────────────────────────────────────────────

EXTERNAL_REPOS = {
    "PayloadsAllTheThings": {
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "refs_dir": REFS / "repos" / "PayloadsAllTheThings",
        "default_dest": str(Path.home() / ".aimy/repos/PayloadsAllTheThings"),
    },
    "HowToHunt": {
        "url": "https://github.com/KathanP19/HowToHunt",
        "refs_dir": REFS / "repos" / "HowToHunt",
        "default_dest": str(Path.home() / ".aimy/repos/HowToHunt"),
    },
    "bugbounty-cheatsheet": {
        "url": "https://github.com/EdOverflow/bugbounty-cheatsheet",
        "refs_dir": REFS / "repos" / "bugbounty-cheatsheet",
        "default_dest": str(Path.home() / ".aimy/repos/bugbounty-cheatsheet"),
    },
    "reconftw": {
        "url": "https://github.com/six2dez/reconftw",
        "refs_dir": REFS / "repos" / "reconftw",
        "default_dest": str(Path.home() / ".aimy/repos/reconftw"),
    },
}


def clone_external_repo(name: str, dest: str = "", verbose: bool = True) -> dict:
    """Clone one external repo for technique extraction.

    Returns {"cloned": bool, "path": str, "error": str|None}
    """
    if name not in EXTERNAL_REPOS:
        return {"cloned": False, "error": f"Unknown repo: {name}"}

    cfg = EXTERNAL_REPOS[name]
    path = Path(dest or cfg["default_dest"])
    if path.exists():
        if verbose:
            print(f"  [~] {name} 已存在: {path}")
        return {"cloned": False, "path": str(path), "error": None}

    path.parent.mkdir(parents=True, exist_ok=True)
    import subprocess
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", cfg["url"], str(path)],
            check=True, capture_output=True, timeout=180,
        )
        if verbose:
            print(f"  [+] 克隆 {name} → {path}")
        return {"cloned": True, "path": str(path), "error": None}
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode() if e.stderr else str(e)
        if verbose:
            print(f"  [!] 克隆 {name} 失败: {err[:120]}")
        return {"cloned": False, "error": err}
    except Exception as e:
        return {"cloned": False, "error": str(e)}


def register_external_repo(name: str, path: str, verbose: bool = True) -> dict:
    """Register an external repo's references into FeedbackDB resources table.

    Scans for .md files and indexes them by keyword.
    """
    repo_path = Path(path)
    if not repo_path.exists():
        return {"registered": 0, "error": "path not found"}

    db = FeedbackDB()
    added = 0
    for f in repo_path.rglob("*.md"):
        rel = str(f.relative_to(REFS)).replace("\\", "/")
        name_lower = f.name.lower().replace("-", " ").replace("_", " ")
        keyword_hints = {
            "xss": "xss", "sqli": "sqli", "ssrf": "ssrf", "sql": "sqli",
            "ssti": "ssti", "idor": "idor", "xxe": "xxe", "csrf": "csrf",
            "rce": "rce", "cmdi": "cmdi", "lfi": "lfi",
            "jwt": "jwt", "oauth": "oauth", "saml": "saml",
            "auth": "auth", "bypass": "auth bypass",
            "graphql": "graphql", "cors": "cors",
            "smuggling": "smuggling", "cache": "cache",
            "upload": "file upload", "race": "race condition",
            "payload": "general", "methodology": "general",
            "recon": "recon", "nuclei": "recon",
        }
        keyword = next((v for k, v in keyword_hints.items() if k in name_lower), "general")
        try:
            db._conn.execute(
                "INSERT OR IGNORE INTO resources (keyword, path, resource_type, indexed_at) VALUES (?,?,?,?)",
                (keyword, rel, f"external:{name}", datetime.now().isoformat()),
            )
            added += db._conn.execute("SELECT changes()").fetchone()[0]
        except Exception:
            pass
    db._conn.commit()
    db.close()

    if verbose:
        print(f"  [+] {name}: {added} .md files registered as resources")
    return {"registered": added}


def sync_all(verbose: bool = True) -> dict:
    """Run all GitHub sync operations."""
    result = {}
    # 1. H1 reports
    result["h1_reports"] = sync_h1_reports(verbose=verbose)
    # 2. payload-kit
    try:
        result["payload_kit"] = register_payload_kit(verbose=verbose)
    except Exception as e:
        result["payload_kit"] = {"error": str(e)}

    # 3. External top-tier repos (clone + register)
    for name in EXTERNAL_REPOS:
        try:
            clone_result = clone_external_repo(name, verbose=verbose)
            if clone_result.get("cloned") or Path(clone_result.get("path", "")).exists():
                reg = register_external_repo(name, clone_result["path"], verbose=verbose)
                result[f"repo:{name}"] = reg
        except Exception as e:
            result[f"repo:{name}"] = {"error": str(e)}

    # 4. Inject external techniques into FeedbackDB
    try:
        from aimy.memory.external_sync import (
            inject_techniques, prune_low_rank_external, upgrade_from_external
        )
        inj = inject_techniques(verbose=verbose)
        result["external_inject"] = inj
        # 4.5 Prune low-rank external techniques (survival of the fittest)
        prn = prune_low_rank_external(keep_top_n=5, verbose=verbose)
        result["external_prune"] = prn
        upg = upgrade_from_external(verbose=verbose)
        result["external_upgrade"] = upg
    except ImportError:
        if verbose:
            print("  [!] external_sync.py not yet created, skipping technique injection")
    except Exception as e:
        result["external_error"] = str(e)

    # 5. Refresh session_brief after sync
    try:
        from aimy.memory.session_brief import generate as gen_brief
        brief = gen_brief()
        (Path.home() / ".aimy" / "session_brief.md").write_text(brief, encoding="utf-8")
        if verbose:
            print(f"  [+] session_brief refreshed")
    except Exception as e:
        result["brief_error"] = str(e)

    return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="GitHub Sync — import fresh data into EVX")
    ap.add_argument("--min-upvotes", type=int, default=50, help="Minimum upvotes (default: 50)")
    ap.add_argument("--no-external", action="store_true", help="Skip external repo sync")
    ap.add_argument("--clone-only", type=str, default="", help="Clone a specific external repo only")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.clone_only:
        r = clone_external_repo(args.clone_only, verbose=not args.quiet)
        if r.get("path"):
            register_external_repo(args.clone_only, r["path"], verbose=not args.quiet)
        print(f"done={r.get('cloned', False)}  path={r.get('path', '')}")
    else:
        result = sync_all(verbose=not args.quiet)
        print(f"\nimported={result.get('h1_reports',{}).get('imported',0)}  "
              f"external_inject={result.get('external_inject',{}).get('injected',0)}")
