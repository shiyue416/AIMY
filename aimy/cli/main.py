"""AIMY CLI — Click-based command-line interface."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import click

from aimy.llm.client import LLMClient
from aimy.llm.providers import get_available_providers, PROVIDERS, PROVIDER_PRIORITY


def _load_env() -> None:
    """Load .env from project root (no extra deps)."""
    import os
    from pathlib import Path
    env_file = Path(__file__).parent.parent.parent / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k and v and k not in os.environ:
            os.environ[k] = v

_load_env()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """AIMY — AI Bug Bounty Agent Framework."""
    # Auto-start flywheel watch if H1 credentials are set
    import os, threading
    username = os.environ.get("H1_USERNAME")
    token = os.environ.get("H1_TOKEN")
    if username and token:
        def _watch():
            import time
            from aimy.memory.h1_sync import sync
            from aimy.memory.feedback import FeedbackDB
            while True:
                try:
                    db = FeedbackDB()
                    sync(username, token, db=db, verbose=False)
                    db.close()
                except Exception:
                    pass
                time.sleep(1800)
        t = threading.Thread(target=_watch, daemon=True)
        t.start()

    # Auto-index new playbooks/payloaders on every startup
    import os
    refs = os.environ.get("AIMY_REFS_DIR", "C:/Users/PC/Desktop/彦/references")
    if os.path.isdir(refs):
        try:
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            db.index_resources(refs)
            db.close()
        except Exception:
            pass
        t.start()


@main.command()
@click.argument("task")
@click.option("-t", "--target", help="Target domain")
@click.option("-p", "--provider", help="LLM provider")
@click.option("-m", "--model", help="Model name")
@click.option("--skills-dir", default="", help="Skills directory")
@click.option("--tools-dir", default="", help="Tools directory")
@click.option("--refs-dir", default="", help="References directory (H1 reports, payloads, etc.)")
@click.option("--max-turns", default=30, help="Max agent turns")
@click.option("--quiet", is_flag=True, help="Less output")
def hunt(task, target, provider, model, skills_dir, tools_dir, refs_dir, max_turns, quiet):
    """Run a bug bounty hunt with the given TASK."""
    from aimy.core.orchestrator import Orchestrator

    # Collect ALL skill sources for maximum coverage
    skill_sources = _all_skills_dirs() if not skills_dir else [skills_dir]

    orch = Orchestrator(
        skills_dir=skill_sources[0] if skill_sources else "",
        tools_dir=tools_dir or _default_tools_dir(),
        references_dir=refs_dir or _default_refs_dir(),
        provider=provider,
        model=model,
        max_turns=max_turns,
        verbose=not quiet,
    )
    # Add remaining skill sources
    for sd in skill_sources[1:]:
        orch.add_skill_source(sd, "external")

    if not orch.client.available:
        click.secho("No LLM provider available. Set at least one API key.", fg="red")
        sys.exit(1)

    result = orch.run(task, target=target or "")
    click.secho(f"\nVerdict: {result['verdict']}", fg="green")
    click.secho(f"Turns: {result['stats']['turns']} | Tools: {result['stats']['tool_calls']} | "
                f"Skills: {result['stats']['skills_loaded']}", fg="cyan")

    # Auto-sync H1 outcomes after hunt (if credentials set)
    import os
    if os.environ.get("H1_USERNAME") and os.environ.get("H1_TOKEN"):
        try:
            from aimy.memory.h1_sync import sync
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            counts = sync(os.environ["H1_USERNAME"], os.environ["H1_TOKEN"], db=db, verbose=False)
            db.close()
            if counts["synced"]:
                click.secho(f"[flywheel] +{counts['synced']} outcomes synced", fg="yellow")
                # New outcomes → compare vs payloaders → auto-upgrade gaps
                try:
                    from aimy.memory.flywheel_learner import compare_and_upgrade
                    c = compare_and_upgrade(verbose=False)
                    if c["upgraded"]:
                        click.secho(f"[flywheel] +{c['upgraded']} payloader gaps filled", fg="yellow")
                except Exception:
                    pass
        except Exception:
            pass


@main.command()
@click.option("-p", "--provider", help="LLM provider")
def repl(provider):
    """Start interactive REPL mode."""
    client = LLMClient(provider) if provider else LLMClient.detect_best()
    if not client.available:
        click.secho("No LLM provider available.", fg="red")
        sys.exit(1)

    click.secho(f"AIMY v0.1.0 — {client.description}", fg="cyan")
    click.secho("Type /help for commands, /quit to exit.\n")

    from aimy.core.state import AgentState
    state = AgentState()

    while True:
        try:
            user_input = input(click.style("aimy> ", fg="cyan", bold=True)).strip()
        except (EOFError, KeyboardInterrupt):
            click.secho("\nGoodbye.", fg="yellow")
            break

        if not user_input:
            continue

        if user_input.startswith("/quit"):
            break
        elif user_input.startswith("/help"):
            _print_help()
        elif user_input.startswith("/status"):
            click.echo(f"  Target: {state.target or 'not set'}")
            click.echo(f"  Turns: {state.turn}")
            click.echo(f"  Provider: {client.description}")
        elif user_input.startswith("/providers"):
            available = get_available_providers()
            for p in PROVIDER_PRIORITY:
                cfg = PROVIDERS.get(p, {})
                status = "[+]" if p in available else "[x]"
                click.echo(f"  {status} {p}: {cfg.get('label','?')}")
        elif user_input.startswith("/"):
            click.secho(f"Unknown command: {user_input}", fg="yellow")
        else:
            # Run agent loop for this input
            from aimy.core.loop import ReActLoop
            from aimy.tools.schema import get_all_tools
            from aimy.tools.runner import create_default_runner

            runner = create_default_runner()
            loop = ReActLoop(
                client=client,
                state=state,
                system_prompt=DEFAULT_SYSTEM,
                tools=get_all_tools(),
                tool_executor=runner.dispatch,
                max_turns=10,
                time_budget=300,
            )
            reply = loop.run(user_input)
            click.secho(f"\n{reply}\n", fg="green")


@main.group()
def feedback():
    """H1 report outcome tracker — flywheel learning."""
    pass


@feedback.command("index-resources")
@click.option("--refs-dir", default="C:/Users/PC/Desktop/彦/references", show_default=True)
def feedback_index_resources(refs_dir):
    """Scan playbooks/payloader/methodology and write into flywheel DB."""
    from aimy.memory.feedback import FeedbackDB
    db = FeedbackDB()
    added = db.index_resources(refs_dir)
    click.secho(f"[+] Indexed {added} resources into flywheel.", fg="green")
    db.close()


@feedback.command("resources")
def feedback_resources():
    """Show playbooks/payloaders ranked by H1 acceptance rate."""
    from aimy.memory.feedback import FeedbackDB
    db = FeedbackDB()
    for r in db.resource_scores():
        click.echo(f"  {r['rate']:.0%}  {r['path']:<55} ({r['accepted']}/{r['total']})")
    db.close()


@feedback.command("record")
@click.argument("technique")
@click.argument("vuln_class")
@click.option("--report-id", default="")
@click.option("--target-type", default="")
@click.option("--outcome", default="")
@click.option("--bounty", default=0.0, type=float)
def feedback_record(technique, vuln_class, report_id, target_type, outcome, bounty):
    """Record a submitted H1 report."""
    from aimy.memory.feedback import FeedbackDB
    db = FeedbackDB()
    row_id = db.record(technique, vuln_class, report_id=report_id,
                       target_type=target_type, outcome=outcome, bounty=bounty)
    click.secho(f"[+] Recorded id={row_id}  {technique} / {vuln_class}", fg="green")
    db.close()


@feedback.command("resolve")
@click.argument("row_id", type=int)
@click.argument("outcome")
@click.option("--severity", default="")
@click.option("--bounty", default=0.0, type=float)
def feedback_resolve(row_id, outcome, severity, bounty):
    """Set H1 triage outcome for a report (accepted/rejected/informative/duplicate/na)."""
    from aimy.memory.feedback import FeedbackDB
    db = FeedbackDB()
    db.resolve(row_id, outcome, severity=severity, bounty=bounty)
    click.secho(f"[+] id={row_id} → {outcome}  bounty=${bounty}", fg="green")
    db.close()


@feedback.command("watch")
@click.option("--username", envvar="H1_USERNAME", required=True)
@click.option("--token", envvar="H1_TOKEN", required=True)
@click.option("--interval", default=1800, help="Sync interval in seconds (default 30min)")
def feedback_watch(username, token, interval):
    """Background flywheel: auto-sync H1 outcomes every N seconds."""
    import time
    from aimy.memory.h1_sync import sync
    from aimy.memory.feedback import FeedbackDB
    click.secho(f"[*] Flywheel started — syncing every {interval//60}min. Ctrl-C to stop.", fg="cyan")
    while True:
        db = FeedbackDB()
        counts = sync(username, token, db=db, verbose=False)
        db.close()
        click.secho(f"[{datetime.now().strftime('%H:%M:%S')}] synced={counts['synced']} pending={counts['pending']}", fg="green")
        time.sleep(interval)



@click.option("--username", envvar="H1_USERNAME", required=True, help="H1 username (or set H1_USERNAME)")
@click.option("--token", envvar="H1_TOKEN", required=True, help="H1 API token (or set H1_TOKEN)")
def feedback_sync(username, token):
    """Pull HackerOne report outcomes and auto-update flywheel."""
    from aimy.memory.h1_sync import sync
    from aimy.memory.feedback import FeedbackDB
    click.secho("[*] Syncing from HackerOne...", fg="cyan")
    db = FeedbackDB()
    counts = sync(username, token, db=db, verbose=True)
    db.close()
    click.secho(f"\n[+] synced={counts['synced']}  skipped={counts['skipped']}  pending={counts['pending']}", fg="green")


@feedback.command("stats")
@click.option("--top", default=10, help="Show top N techniques")
def feedback_stats(top):
    """Show flywheel stats and top techniques by acceptance rate."""
    from aimy.memory.feedback import FeedbackDB
    db = FeedbackDB()
    s = db.stats()
    click.secho(f"\nTotal: {s['total']}  Accepted: {s['accepted']}  "
                f"Rate: {s['rate']:.0%}  Bounty: ${s['total_bounty']}", fg="cyan")
    click.echo("\nTop techniques:")
    for i, sc in enumerate(db.scores()[:top], 1):
        click.echo(f"  {i:2}. {sc['technique']:<40} {sc['rate']:.0%} ({sc['accepted']}/{sc['total']})  ${sc['avg_bounty']}")
    db.close()


@feedback.command("push")
@click.option("--message", "-m", default="", help="Commit message")
def feedback_push(message):
    """Push local accepted techniques to GitHub (shared techniques.jsonl).

    Exports accepted techniques from local DB → commits to repo → pushes to origin.
    Other users' 'aimy feedback pull' will pick up your techniques.
    """
    import subprocess, sys
    from aimy.memory.feedback import FeedbackDB

    db = FeedbackDB()
    repo_root = _find_repo_root()

    if not repo_root:
        click.secho("[!] Not inside AIMY repo. Run from the cloned directory.", fg="red")
        db.close()
        sys.exit(1)

    # Get accepted techniques from local DB
    accepted = db.get_accepted_techniques()
    if not accepted:
        click.secho("[!] No accepted techniques to push. Find some bugs first!", fg="yellow")
        db.close()
        return

    # Load existing shared techniques
    shared_path = Path(repo_root) / "techniques.jsonl"
    existing = set()
    if shared_path.exists():
        with open(shared_path, encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    existing.add(entry.get("technique", ""))
                except Exception:
                    pass

    # Append new techniques (dedup by technique name)
    new_count = 0
    with open(shared_path, "a", encoding="utf-8") as f:
        for t in accepted:
            if t["technique"] not in existing:
                entry = {
                    "technique": t["technique"],
                    "vuln_class": t.get("vuln_class", ""),
                    "target_type": t.get("target_type", ""),
                    "severity": t.get("severity", ""),
                    "accepted_count": t.get("accepted", 0),
                    "total_count": t.get("total", 0),
                    "avg_bounty": t.get("avg_bounty", 0),
                    "author": os.environ.get("H1_USERNAME", os.environ.get("USER", "anonymous")),
                    "pushed_at": datetime.now().isoformat(),
                }
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                new_count += 1
                existing.add(t["technique"])

    if new_count == 0:
        click.secho("[*] No new techniques to push (all already shared).", fg="yellow")
        db.close()
        return

    # Commit and push
    os.chdir(repo_root)
    msg = message or f"flywheel: share {new_count} technique(s)"
    subprocess.run(["git", "add", "techniques.jsonl"], check=False)
    subprocess.run(["git", "commit", "-m", msg], check=False)
    subprocess.run(["git", "push", "origin", "master"], check=False)

    click.secho(f"[+] Pushed {new_count} technique(s) to GitHub. Other users can 'aimy feedback pull'.", fg="green")
    db.close()


@feedback.command("pull")
def feedback_pull():
    """Pull shared techniques from GitHub and merge into local flywheel DB.

    git pull → read techniques.jsonl → import into local FeedbackDB → regenerate session_brief.
    """
    import subprocess, sys
    from aimy.memory.feedback import FeedbackDB

    db = FeedbackDB()
    repo_root = _find_repo_root()

    if not repo_root:
        click.secho("[!] Not inside AIMY repo.", fg="red")
        db.close()
        sys.exit(1)

    # Pull latest
    os.chdir(repo_root)
    result = subprocess.run(["git", "pull", "origin", "master"], capture_output=True, text=True)
    click.echo(result.stdout.strip())

    # Read shared techniques
    shared_path = Path(repo_root) / "techniques.jsonl"
    if not shared_path.exists():
        click.secho("[!] No shared techniques.jsonl found.", fg="yellow")
        db.close()
        return

    imported = 0
    with open(shared_path, encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
                # Import into local DB (dedup by technique name)
                db.record(
                    technique=entry["technique"],
                    vuln_class=entry.get("vuln_class", ""),
                    target_type=entry.get("target_type", ""),
                    outcome="accepted",
                    severity=entry.get("severity", ""),
                    bounty=float(entry.get("avg_bounty", 0)),
                    report_id=f"shared:{entry.get('author', 'unknown')}:{entry.get('pushed_at', '')}",
                )
                imported += 1
            except Exception:
                pass

    db.close()

    # Regenerate session_brief
    try:
        subprocess.run([sys.executable, "-m", "aimy.memory.session_brief"], check=False)
    except Exception:
        pass

    click.secho(f"[+] Pulled {imported} shared technique(s) into local flywheel.", fg="green")
    click.secho("[*] Run 'python -m aimy.memory.session_brief' to see merged rankings.", fg="cyan")


def _find_repo_root() -> str:
    """Walk up from cwd to find AIMY git repo root."""
    import subprocess
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return ""


@main.command()
def providers():
    """List available LLM providers."""
    available = get_available_providers()
    for p in PROVIDER_PRIORITY:
        cfg = PROVIDERS.get(p, {})
        status = click.style("[+]", fg="green") if p in available else click.style("[x]", fg="yellow")
        click.echo(f"  {status} {p:<12} {cfg.get('label','?'):<30} [{cfg.get('cost','?')}]")


@main.command()
@click.option("--port", type=int, default=8000, help="Port for web UI")
def web(port):
    """Start AIMY Web client (browser-based chat UI)."""
    import uvicorn
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from aimy.web.app import app
    print(f"AIMY Web Client -> http://localhost:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port)


@main.command()
@click.option("--port", type=int, help="Port for SSE mode (default: stdio)")
def mcp_server(port):
    """Start AIMY as MCP server."""
    from aimy.mcp.server import run_stdio_server
    run_stdio_server()


def _default_skills_dir() -> str:
    candidates = [
        "C:/Users/PC/tools/claude-bug-bounty/skills",
        "C:/Users/PC/Desktop/小十月skill/skills",      # 102 attack skills
        "C:/Users/PC/Desktop/小十月skill/anthropic-skills",  # 818 defense/forensics
        os.path.expanduser("~/.aimy/skills"),
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return ""


def _all_skills_dirs() -> list[str]:
    """Return ALL available skill directories (not just the first found)."""
    candidates = [
        "C:/Users/PC/Desktop/小十月skill/skills",
        "C:/Users/PC/Desktop/小十月skill/anthropic-skills",
        "C:/Users/PC/tools/claude-bug-bounty/skills",
        os.path.expanduser("~/.aimy/skills"),
    ]
    return [d for d in candidates if os.path.isdir(d)]


def _default_tools_dir() -> str:
    candidates = [
        "C:/Users/PC/tools/claude-bug-bounty/tools",
        os.path.expanduser("~/.aimy/tools"),
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return ""


def _default_refs_dir() -> str:
    candidates = [
        "C:/Users/PC/Desktop/小十月skill/references",
        os.path.expanduser("~/.aimy/references"),
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return ""


def _print_help():
    click.echo("""
Commands:
  /help          Show this help
  /status        Show current state
  /providers     List available LLM providers
  /quit          Exit

Or just type your task and the agent will run.
""")


DEFAULT_SYSTEM = """You are AIMY — an AI bug bounty hunting agent.
You have access to security tools and can execute them to find vulnerabilities.
Be thorough, think critically, and report findings with clear impact assessment."""


if __name__ == "__main__":
    main()
