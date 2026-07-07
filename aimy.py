#!/usr/bin/env python3
"""AIMY — AI-powered bug bounty hunting agent framework.

Single-file entry point. No installation needed.
Works as: `python aimy.py` or `from aimy import ...`

Usage:
    python aimy.py                           # Interactive mode
    python aimy.py -q "hunt example.com"     # Single query
    python aimy.py --target example.com      # Targeted hunt
    python aimy.py --list-providers          # Show available providers
"""

from __future__ import annotations

import os
import sys

# Ensure parent is on path so `from aimy.llm.client import LLMClient` works
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, os.path.dirname(_here))

from aimy.llm.client import LLMClient
from aimy.llm.providers import PROVIDERS, get_available_providers, PROVIDER_PRIORITY
from aimy.core.state import AgentState
from aimy.core.loop import ReActLoop
from aimy.tools.safety_gate import install_hook, enable as _sg_enable, disable as _sg_disable

# ── Colours ───────────────────────────────────────────────────────
GREEN = "\033[0;32m"
RED   = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"


def banner():
    import os
    mode = os.environ.get("AIMY_MODE", "veteran").lower()
    if mode == "veteran":
        mode_str = f"{GREEN}老鸟 Veteran{NC}"
    else:
        mode_str = f"{YELLOW}菜鸟 Rookie{NC}"

    from aimy.tools.settings import settings
    safety_str = f"{GREEN}只读{NC}" if settings.read_only else f"{RED}直通{NC}"
    print(f"""
{CYAN}   ╔══════════════════════════════════════════════╗
   ║  {BOLD}AIMY v0.1.0 — AI Bug Bounty Agent{NC}{CYAN}           ║
   ║  {DIM}Mode: {mode_str}{DIM}  |  安全: {safety_str}{DIM}  |  114 skills · 78 tools · 2529模板{NC}{CYAN} ║
   ╚══════════════════════════════════════════════╝{NC}
""", flush=True)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="AIMY — AI Bug Bounty Agent")
    parser.add_argument("-q", "--query", help="Single query mode")
    parser.add_argument("-t", "--target", help="Target domain")
    parser.add_argument("-p", "--provider", help="Force provider (claude/openai/deepseek/...)")
    parser.add_argument("-m", "--model", help="Force model name")
    parser.add_argument("--list-providers", action="store_true", help="Show available providers")
    parser.add_argument("--list-models", action="store_true", help="Show models for current provider")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner")
    parser.add_argument("--verbose", action="store_true", default=True, help="Verbose output")
    parser.add_argument("--flywheel", action="store_true",
                        help="运行数据飞轮：H1同步→技术评分→Payload升级→推荐")
    parser.add_argument("--skip-h1", action="store_true",
                        help="飞轮模式：跳过 H1 API 同步（无token时用）")
    parser.add_argument("--autopilot", action="store_true",
                        help="半自主挖洞：recon→hunt→verify→record 全自动循环")
    parser.add_argument("--max-targets", type=int, default=5,
                        help="autopilot 最大目标数（默认5）")
    parser.add_argument("--budget", type=int, default=3600,
                        help="autopilot 时间预算秒数（默认3600）")
    parser.add_argument("--read-only", action="store_true", default=None,
                        help="只读模式：拦截写操作payload，禁止PUT/PATCH/DELETE")
    parser.add_argument("--no-read-only", action="store_true", default=None,
                        help="关闭只读模式（挖自己靶机时用）")
    parser.add_argument("--phase", default="",
                        help="起始阶段 (p0-p7)，与 -t 联用走 PhaseManager")

    args = parser.parse_args()

    # ── Safety Gate 初始化 ──────────────────────────────────────────
    # 优先级: CLI flag > 环境变量 > 默认(开启)
    read_only_flag = args.read_only if args.read_only is not None else (
        False if args.no_read_only else
        os.environ.get("AIMY_READ_ONLY", "1").lower() in ("1", "true", "yes")
    )
    from aimy.tools.settings import settings as _settings
    _settings.read_only = read_only_flag
    if read_only_flag:
        _sg_enable()
        install_hook()
    else:
        _sg_disable()

    # ── 数据飞轮（独立模式，无需 LLM）────────────────────────────
    if args.flywheel:
        from aimy.memory.flywheel import Flywheel
        _scene = os.environ.get("AIMY_SCENE", "bounty").lower()
        fw = Flywheel(verbose=not args.no_banner)
        result = fw.run(skip_h1_sync=args.skip_h1, scene=_scene)
        if _scene == "bounty":
            print(f"  {D}飞轮完成 (bounty 模式: 标准 7 步){NC}")
        elif _scene == "pentest":
            print(f"  {D}飞轮完成 (pentest 模式: 含后渗透进化){NC}")
        elif _scene == "redteam":
            print(f"  {D}飞轮完成 (redteam 模式: 含全攻击链进化){NC}")
        return

    # ── Autopilot 模式 ────────────────────────────────────────────
    if args.autopilot:
        if not args.target:
            print(f"{YELLOW}--autopilot requires --target <domain>{NC}")
            return
        if not args.no_banner:
            banner()
        client = LLMClient(args.provider) if args.provider else LLMClient.detect_best()
        from aimy.core.auto_verify import Autopilot
        ap = Autopilot(client, verbose=not args.no_banner)
        ap.run(args.target, max_targets=args.max_targets, time_budget=args.budget)
        return

    # ── Info commands (no agent needed) ───────────────────────────
    if args.list_providers:
        available = get_available_providers()
        print(f"{BOLD}Available providers:{NC}")
        for p in PROVIDER_PRIORITY:
            cfg = PROVIDERS.get(p, {})
            status = f"{GREEN}[+]{NC}" if p in available else f"{YELLOW}[x]{NC}"
            key = cfg.get("env_key", "?")
            print(f"  {status} {p:<12}  {cfg.get('label',''):<30}  [{key}]")
        return

    # ── Banner ─────────────────────────────────────────────────────
    if not args.no_banner:
        banner()

    # ── Detect provider ───────────────────────────────────────────
    if args.provider:
        client = LLMClient(args.provider)
    else:
        client = LLMClient.detect_best()

    if not client.available:
        print(f"{YELLOW}No provider available. Set at least one API key (ANTHROPIC_API_KEY / DEEPSEEK_API_KEY / ...).{NC}")
        sys.exit(1)

    if args.list_models:
        models = client.list_models()
        print(f"{BOLD}Models for {client.provider}:{NC}")
        for m in models:
            print(f"  {m}")
        return

    # ── PhaseManager 模式（按 SKILL.md 七阶段自动推进） ────────────
    if args.target and not args.query:
        from aimy.core.phase_manager import PhaseManager
        import os as _os
        _scene = _os.environ.get("AIMY_SCENE", "bounty").lower()
        pm = PhaseManager(target=args.target, provider=args.provider or "",
                          scene=_scene, verbose=not args.no_banner)
        if args.phase:
            pm.run(start_from=args.phase)
        else:
            pm.run()
        return

    # ── Interactive or query mode ──────────────────────────────────
    if args.query:
        _run_query(client, args.query, args.target, args.model)
    else:
        _run_interactive(client, args.target, args.model)


def _run_query(client: LLMClient, query: str, target: str | None, model: str | None):
    """Single-shot query mode (like MUNDO -q)."""
    state = AgentState(target=target or "unknown")
    loop = ReActLoop(
        client=client,
        state=state,
        system_prompt=DEFAULT_SYSTEM,
        tools=SIMPLE_TOOLS,
        max_turns=10,
        time_budget=300,
    )
    reply = loop.run(query)
    print(f"\n{GREEN}{reply}{NC}")


def _run_interactive(client: LLMClient, target: str | None, model: str | None):
    """Interactive REPL mode."""
    print(f"{DIM}Provider: {client.description}{NC}")
    print(f"{DIM}Type /help for commands, /quit to exit.{NC}\n")

    state = AgentState(target=target or "")

    while True:
        try:
            user_input = input(f"{BOLD}aimy> {NC}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}Goodbye.{NC}")
            break

        if not user_input:
            continue

        # ── Auto-detect: "开挖 target" or "http://target" triggers /dig ──
        if user_input.startswith("开挖") or user_input.startswith("http"):
            target = user_input
            if user_input.startswith("开挖"):
                target = user_input[2:].strip()
            state.messages = []
            state.turn = 0
            state.observation_buffer = []
            state.findings = []
            state.done = False
            state.verdict = ""
            state.target = target.replace("http://", "").replace("https://", "").rstrip("/")
            print(f"  {GREEN}Target: {state.target}{NC}")
            # 安全确认
            scope_f = os.environ.get("AIMY_SCOPE_FILE", "")
            if scope_f:
                from aimy.safety.guard import SafetyGuard
                g = SafetyGuard(scope_file=scope_f)
                ok, reason = g.check_request(f"https://{state.target}")
                if not ok:
                    print(f"  {RED}[SAFETY] {reason} — target not in scope. Aborted.{NC}")
                    continue
            print(f"  {DIM}[SAFETY] ≤1 req/s | max 3 records per endpoint | Read-only{NC}")
            user_input = f"对 {state.target} 做全面安全测试：先侦察端口和服务，再探测Web路径，最后扫描漏洞。用中文汇报发现。"

        # ── Slash commands ────────────────────────────────────────
        if user_input.startswith("/"):
            result = _handle_command(user_input, client, state)
            if result and str(result).startswith("DIG:"):
                # Auto-run recon
                target = str(result)[4:]
                user_input = f"对 {target} 做全面安全测试：先侦察端口和服务，再探测Web路径，最后扫描漏洞。用中文汇报发现。"
            else:
                continue

        # ── Run agent loop ────────────────────────────────────────
        from aimy.tools.schema import get_all_tools
        from aimy.tools.runner import create_default_runner
        from aimy.tools.registry import create_default_registry
        from aimy.tools.adapters.security_tools import register_all
        from aimy.skills.loader import SkillLoader
        from aimy.skills.registry import SkillRegistry
        from aimy.skills.router import SkillRouter
        from aimy.skills.formatter import SkillFormatter

        # Load skills from all sources (once, cached on state)
        if not hasattr(state, '_skills_loaded'):
            loader = SkillLoader()
            for d in [_here + "/skills",
                      _here + "/anthropic-skills"]:
                if os.path.isdir(d):
                    loader.add_source(d, "external")
            sk_reg = SkillRegistry()
            sk_reg.index(loader.load_all())
            sk_router = SkillRouter(sk_reg)
            sk_fmt = SkillFormatter()
            state._skills_loaded = True
            state._sk_reg = sk_reg
            state._sk_router = sk_router
            state._sk_fmt = sk_fmt

        # Route skills based on user input
        skills_text = ""
        if hasattr(state, '_sk_router'):
            relevant = state._sk_router.relevant_skills(user_input, max_skills=5)
            skills_text = state._sk_fmt.format(relevant, user_input)

        reg = create_default_registry()
        runner = create_default_runner(registry=reg)
        try:
            register_all(runner)
        except Exception:
            pass

        system = REPL_SYSTEM
        if skills_text:
            system += f"\n\n{skills_text}"

        loop = ReActLoop(
            client=client,
            state=state,
            system_prompt=system,
            tools=get_all_tools(),
            tool_executor=runner.dispatch,
            max_turns=15,
            time_budget=600,
        )
        reply = loop.run(user_input)
        print(f"\n{GREEN}{reply}{NC}\n")


def _handle_command(cmd: str, client: LLMClient, state: AgentState):
    """Handle slash commands."""
    parts = cmd.split()
    op = parts[0].lower()

    # ── "开挖" shorthand: /dig target → auto reset + recon
    if op in ("/dig", "/hunt", "/go") or (op.startswith("http") and len(parts) == 1):
        target_url = parts[1] if len(parts) > 1 else op
        state.messages = []
        state.turn = 0
        state.observation_buffer = []
        state.findings = []
        state.done = False
        state.verdict = ""
        state.target = target_url.replace("http://", "").replace("https://", "").rstrip("/")
        print(f"  {GREEN}Target: {state.target}{NC}")
        print(f"  {DIM}Running full recon + vuln scan...{NC}")
        return "DIG:" + target_url  # signal to run agent below

    if op in ("/quit", "/exit", "/q"):
        print(f"{YELLOW}Goodbye.{NC}")
        sys.exit(0)
    elif op in ("/help", "/h"):
        print(f"""
{BOLD}AIMY Commands (全自动融合):{NC}
  /hunt <target>  一键全流程: recon->12检测器->LLM挖洞->记录->飞轮升级
  /flywheel       手动运行飞轮（自动模式已包含）
  /benchmark      量化 vs XBOW 差距
  /bench-list     列出可用的 benchmark
  /status         当前状态
  /model <name>   切换模型
  /provider <p>   切换 provider
  /quit           退出
""")
    elif op in ("/hunt", "/h", "/go") or (op.startswith("http") and len(parts) == 1):
        # ═══════════════════════════════════════════════════════
        # 一键融合: recon→12检测器→LLM挖洞→记录→飞轮
        # ═══════════════════════════════════════════════════════
        target_url = parts[1] if len(parts) > 1 else op
        target = target_url.replace("http://", "").replace("https://", "").rstrip("/")
        state.target = target
        state.messages = []; state.turn = 0; state.findings = []
        state.done = False; state.verdict = ""
        print(f"{CYAN}{BOLD}[HUNT] {target}{NC}")

    # ════════════════ SAFETY GATE ════════════════
    # Check scope file if set
    from aimy.safety.guard import SafetyGuard
    guard = SafetyGuard(requests_per_second=1.0)
    if os.environ.get("AIMY_SCOPE_FILE"):
        ok, reason = guard.check_request(f"https://{target}")
        if not ok:
            print(f"{RED}[SAFETY] {reason}{NC}")
            print(f"{YELLOW}To proceed, verify the target is in scope and try again.{NC}")
            return

    # Pre-flight: confirm before launching
    print(f"{YELLOW}[SAFETY] Target: {target}{NC}")
    print(f"{YELLOW}[SAFETY] Expected: recon passively (0 requests), then active hunt (≤1 req/s){NC}")
    print(f"{YELLOW}[SAFETY] Data: max 3 records per endpoint, findings auto-recorded{NC}")
    print(f"{YELLOW}[SAFETY] Mode: {'Veteran (filtering low-value)' if settings.is_veteran() else 'Rookie (full detail)'}{NC}")
    print(f"{DIM}Press Enter to continue or /quit to abort...{NC}")
    try:
        if input() == '/quit':
            print(f"{YELLOW}Aborted.{NC}")
            return
    except (EOFError, KeyboardInterrupt):
        print(f"{YELLOW}Aborted.{NC}")
        return
    # ════════════════════════════════════════════

        # ── Phase 0: Recon ───────────────────────────────────
        print(f"{DIM}[Phase 0] Recon...{NC}")
        import subprocess as _sp, shutil as _sh
        has_subfinder = _sh.which("subfinder") is not None
        targets = [target]
        if has_subfinder:
            try:
                r = _sp.run(["subfinder","-d",target,"-silent","-passive"],
                            capture_output=True,text=True,timeout=30)
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line and "." in line and line not in targets:
                        targets.append(line)
                        if len(targets) >= 5: break
            except Exception: pass
        print(f"  {GREEN}{len(targets)} targets found{NC}")

        # ── Phase 1: ToolKit 12 detectors ─────────────────────
        for i, t in enumerate(targets[:5], 1):
            if state.is_time_up: break
            url = f"https://{t}"
            print(f"{DIM}[Phase 1] ToolKit on {t} ({i}/{min(5,len(targets))}){NC}")
            try:
                from aimy.core.bridge import ToolKit
                tk = ToolKit(target_url=url, verbose=False)
                df = tk.run_all(max_per_type=2)
                if df:
                    for f in df:
                        f_val = f.get("vuln_class", f.get("tool","detector"))
                        state.findings.append({
                            "tool": f_val,
                            "severity": "medium",
                            "summary": f.get("summary", str(f))[:200],
                            "endpoint": url,
                            "source": "toolkit",
                        })
                    print(f"  {GREEN}{len(df)} signals detected{NC}")
                else:
                    print(f"  {DIM}no signals{NC}")
            except Exception as e:
                print(f"  {YELLOW}ToolKit: {str(e)[:80]}{NC}")

        # ── Phase 2: LLM Hunt ─────────────────────────────────
        print(f"{DIM}[Phase 2] LLM Hunt on {target}{NC}")
        from aimy.core.loop import ReActLoop
        query = (f"Hunt {target} for high-value vulnerabilities: SSRF, SQLi, Auth Bypass, IDOR, RCE. "
                 f"Be systematic, rate limit 1 req/s. Report findings in Chinese.")
        state.started_loop_at = __import__('time').time()
        # Register Burp MCP tools into the loop
        try:
            from aimy.tools.adapters.burp_mcp import register_burp_tools
            adapter = register_burp_tools(runner, call_mcp=None)
            print(f"  {DIM}Burp: {len(adapter.tool_schemas)} tools registered (requests go through Burp){NC}")
        except Exception as e:
            print(f"  {YELLOW}Burp adapter unavailable: {e}{NC}")
        loop = ReActLoop(client=client, state=state, verbose=True, max_turns=12, time_budget=300)
        loop.run(query)

        # ── Phase 3: Flywheel auto-upgrade ────────────────────
        print(f"{DIM}[Phase 3] Flywheel auto-upgrade...{NC}")
        try:
            from aimy.memory.flywheel import _continuous_upgrade_check
            upgraded = _continuous_upgrade_check(silent=False)
        except Exception: pass

        # ── Phase 4: Auto-schedule auxiliary ──────────────────
        total_signals = len([f for f in state.findings if f.get("source")=="toolkit"])
        total_llm     = len([f for f in state.findings if f.get("source")!="toolkit"])
        all_findings  = total_signals + total_llm
        print(f"\n{CYAN}{BOLD}[HUNT DONE]{NC}")
        print(f"  Targets: {len(targets[:5])} | ToolKit: {total_signals} | LLM: {total_llm}")

        # ── 自动判断是否运行完整飞轮 + benchmark ──────────────
        try:
            from aimy.memory.flywheel import _load_counter, _CONTINUOUS_THRESHOLD
            c = _load_counter()
            total_records = c.get("total", 0)
            upgrades_done = c.get("since_last_upgrade", 0)
            print(f"  EVX: {total_records} total records, {upgrades_done} since last full flywheel")

            # 每累计 10 条记录 → 自动完整飞轮
            if total_records > 0 and total_records % 10 == 0 and upgrades_done <= 2:
                print(f"{YELLOW}  [Auto] Triggering full EVX flywheel (10+ records accumulated)...{NC}")
                try:
                    from aimy.memory.flywheel import Flywheel
                    Flywheel(verbose=True).run(skip_h1_sync=True)
                except Exception as e:
                    print(f"  {RED}Flywheel: {e}{NC}")

            # 每累计 20 条记录 → 建议跑 benchmark
            if total_records > 0 and total_records % 20 == 0:
                print(f"{YELLOW}  [Auto] Suggest: /benchmark to check blind spots (20 records reached){NC}")
        except Exception: pass

        print(f"  All findings auto-recorded to EVX flywheel")
    elif op in ("/bench-list", "/bl"):
        try:
            from run_benchmark import load_benchmarks
            benches = load_benchmarks(limit=200)
            print(f"  {BOLD}{len(benches)} benchmarks:{NC}")
            for b in benches[:30]:
                print(f"    {b['_name']:<25} lvl={b.get('level','?')} tags={b.get('tags',[])}")
            if len(benches) > 30: print(f"    ... +{len(benches)-30} more")
        except Exception as e:
            print(f"  {RED}Error: {e}{NC}")
    elif op == "/status":
        print(f"  Target: {state.target or 'not set'}")
        print(f"  Turns:  {state.turn}")
        print(f"  Provider: {client.description}")
        print(f"  Findings: {len(state.findings)}")
    elif op == "/model" and len(parts) > 1:
        state.model = parts[1]
        print(f"  Model set to: {parts[1]}")
    elif op == "/provider" and len(parts) > 1:
        new = LLMClient(parts[1])
        if new.available:
            client = new
            print(f"  Switched to: {client.description}")
        else:
            print(f"  {YELLOW}Provider {parts[1]} not available{NC}")
    elif op in ("/reset", "/clear"):
        state.messages = []
        state.turn = 0
        state.observation_buffer = []
        state.findings = []
        state.done = False
        state.verdict = ""
        print(f"  {GREEN}State cleared. Fresh session.{NC}")
    elif op in ("/veteran", "/v"):
        state._mode = "veteran"
        from aimy.tools.settings import settings
        settings.mode = "veteran"
        print(f"  {GREEN}Veteran: 专注高价值(SSRF/RCE/SQLi)，过滤反射XSS/OpenRedirect/信息泄露{NC}")
    elif op in ("/rookie", "/r"):
        state._mode = "rookie"
        from aimy.tools.settings import settings
        settings.mode = "rookie"
        print(f"  {YELLOW}Rookie: 输出详细说明+修复建议，不过滤低危{NC}")
    elif op in ("/tools", "/t"):
        for t in SIMPLE_TOOLS:
            name = t.get("function", {}).get("name", "?")
            desc = t.get("function", {}).get("description", "")[:80]
            print(f"  {CYAN}{name}{NC}: {desc}")
    elif op == "/providers":
        available = get_available_providers()
        for p in PROVIDER_PRIORITY:
            cfg = PROVIDERS.get(p, {})
            status = f"{GREEN}[+]{NC}" if p in available else f"{YELLOW}[x]{NC}"
            print(f"  {status} {p}: {cfg.get('label', '?')}")
    else:
        print(f"  {YELLOW}Unknown command: {op}{NC}")


# ── Default system prompt ─────────────────────────────────────────
DEFAULT_SYSTEM = """You are AIMY — an autonomous AI bug bounty hunting agent.
You have access to tools that let you execute shell commands, read files, write files, and search the web.

Your job: help the user find real security vulnerabilities with demonstrated business impact.

Rules:
1. Think before acting — explain your reasoning briefly
2. Use tools when you need concrete information
3. Report findings with severity and PoC
4. NEVER report theoretical risks without proven exploitability
5. One finding at a time — be thorough, not fast
6. When you've completed the task, stop calling tools and give your final verdict"""

REPL_SYSTEM = """You are AIMY — an AI bug bounty hunting agent on Windows.
你是 AIMY，一个 AI 漏洞赏金猎杀 Agent，运行在 Windows 交互模式。

PLATFORM: Windows with Git Bash. Standard Linux commands (curl, head, grep, awk) work fine.
平台: Windows + Git Bash，支持标准 Linux 命令。

MODES: /veteran (high-value only), /rookie (full detail), /reset (clear session)

AVAILABLE TOOLS:
- terminal: run shell commands. READ THE OUTPUT before calling again.
- read_file: read file contents with line numbers
- web_search: search the web
- run_recon(domain=X): full recon pipeline — use ONCE per target

CRITICAL RULES:
1. REPLY IN THE SAME LANGUAGE AS THE USER.
2. ONLY call tools when the user asks you to DO something concrete.
3. curl, which, ls, grep ALL WORK. STOP checking if they exist — they do.
4. When a tool returns output, READ IT and MOVE ON. Never call the same check twice.
5. Maximum 1 tool check per turn. After that, use the result.
6. If you're stuck, report what you found and ask — don't loop.
7. Use /reset if confused. Be concise."""


# ── Simple built-in tools ─────────────────────────────────────────
SIMPLE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "terminal",
            "description": "Run a shell command and return the output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "workdir": {"type": "string", "description": "Working directory"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file and return its contents with line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "offset": {"type": "integer", "description": "Start line"},
                    "limit": {"type": "integer", "description": "Max lines", "default": 200},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file (creates parent dirs).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "content": {"type": "string", "description": "File content"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
    },
]


if __name__ == "__main__":
    main()
