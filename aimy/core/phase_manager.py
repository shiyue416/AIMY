"""PhaseManager -- 七阶段流程自动推进

按 SKILL.md 定义的路由表，自动执行 P0→P1→...→P7。
多模型支持：不同阶段用不同 LLM。

用法:
    pm = PhaseManager(target="target.com", provider="longcat")
    pm.run()                     # 全自动推进
    pm.run_phase("p4")           # 只跑单个阶段
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import sys
from pathlib import Path
from typing import Optional

# colours
G = "\033[0;32m"; Y = "\033[1;33m"; C = "\033[0;36m"
B = "\033[1m"; D = "\033[2m"; R = "\033[0;31m"; NC = "\033[0m"

_HERE = Path(__file__).parent
_ROOT = _HERE.parent.parent
PHASES_JSON = _HERE / "phases.json"


class PhaseManager:
    """七阶段流程管理器。"""

    # LLM 模型路由（不同阶段用不同模型）
    PHASE_MODELS = {
        "p0": None,                    # 不调用 LLM
        "p1": None,                    # 人工填
        "p2": "groq",                  # 侦察→量大用免费
        "p3": "deepseek",              # 枚举→便宜快
        "p4": "longcat",              # 狩猎→强推理
        "p5": "deepseek",              # 验证→便宜
        "p6": "longcat",              # 报告→质量优先
        "p7": None,                    # 不调用 LLM
    }

    def __init__(self, target: str = "", provider: str = "",
                 scene: str = "", verbose: bool = True):
        self.target = target
        self.provider = provider or os.environ.get("AIMY_PROVIDER", "longcat")
        self.scene = scene.lower() or os.environ.get("AIMY_SCENE", "bounty").lower()
        self.verbose = verbose
        self._phases = self._load_phases()
        self._phase_order = self._resolve_phase_order()
        self._state: dict = {
            "current_phase": None,
            "findings": [],
            "recon_dir": "",
            "host_tech": [],
            "validated": [],
            "completed_phases": [],
            "errors": [],
        }

    # ── 加载路由表 ──────────────────────────────────────────────

    def _load_phases(self) -> dict:
        """从 phases.json 加载路由表。"""
        if PHASES_JSON.exists():
            with open(PHASES_JSON, encoding="utf-8") as f:
                data = json.load(f)
                return data.get("phases", {})
        return {}

    # ── 主入口 ──────────────────────────────────────────────────

    # ── 场景路由 ──────────────────────────────────────────────

    def _resolve_phase_order(self) -> list[str]:
        """根据场景决定走哪些阶段。"""
        selector = self._phases.get("scene_selector", {})
        routes = selector.get("routes", {})
        phase_list = routes.get(self.scene, routes.get("bounty", []))

        if self.verbose:
            scene_names = {"bounty": "赏金", "pentest": "渗透", "redteam": "对抗"}
            print(f"  {C}场景: {scene_names.get(self.scene, self.scene)} | "
                  f"阶段: {len(phase_list)} 步{NC}")
        return phase_list

    def run(self, start_from: str = "p0"):
        """全自动推进：从指定阶段开始，顺序执行到 P7。"""
        print(f"\n{C}{B}╔══════════════════════════════════════════════╗{NC}")
        print(f"{C}║  PhaseManager -- 场景化流程推进{NC}")
        scene_names = {"bounty": "赏金猎人", "pentest": "渗透测试", "redteam": "红蓝对抗"}
        print(f"{C}║  场景: {scene_names.get(self.scene, self.scene)}{NC}")
        print(f"{C}║  目标: {self.target}{NC}")
        print(f"{C}║  模型: {self.provider}{NC}")
        print(f"{C}╚══════════════════════════════════════════════╝{NC}{NC}")

        phase_names = self._phase_order
        started = False

        for phase_key in phase_names:
            if phase_key == start_from:
                started = True
            if not started:
                continue

            phase = self._phases[phase_key]
            order = phase.get("order", "?")
            name = phase.get("name", phase_key)

            if phase_key in self._state["completed_phases"]:
                continue

            self._state["current_phase"] = phase_key
            self._print_banner(order, name)

            try:
                if phase.get("auto", False):
                    self._run_auto(phase_key, phase)
                else:
                    # 人工阶段前执行自动化辅助
                    self._pre_manual_hook(phase_key, phase)
                    self._wait_manual(phase)
            except Exception as e:
                self._state["errors"].append({phase_key: str(e)})
                print(f"  {R}[ERROR] {e}{NC}")
                if not self._confirm("继续下一阶段"):
                    break

            self._state["completed_phases"].append(phase_key)
            time.sleep(0.5)

        self._summary()

    def run_phase(self, phase_key: str):
        """只跑单个阶段。"""
        phase = self._phases.get(phase_key)
        if not phase:
            print(f"{R}未知阶段: {phase_key}{NC}")
            return
        self._state["current_phase"] = phase_key
        self._print_banner(phase.get("order", "?"), phase.get("name", phase_key))
        if phase.get("auto", False):
            self._run_auto(phase_key, phase)
        else:
            self._wait_manual(phase)

    # ── 自动阶段执行 ────────────────────────────────────────────

    def _run_auto(self, phase_key: str, phase: dict):
        action = phase.get("action", "")
        model = self.PHASE_MODELS.get(phase_key, None)

        if model and self.verbose:
            print(f"  {D}模型: {model}{NC}")

        # 阶段特定执行逻辑
        actions = {
            "safety_gate":    self._execute_p0,
            "route_scene":    self._execute_scene,
            "recon_pipeline": self._execute_p2,
            "run_enum":       self._execute_p3,
            "run_hunt":       self._execute_p4,
            "run_validate":   self._execute_p5,
            "run_flywheel":   self._execute_p7,
            "anthropic_route": self._execute_anthropic_route,
        }

        executor = actions.get(action)
        if executor:
            executor(phase)
        else:
            print(f"  {Y}[SKIP] 无执行器: {action}{NC}")

    # ── 场景路由执行器 ──────────────────────────────────────────

    def _execute_scene(self, phase: dict):
        """自动检测 scene 并选择对应流程。"""
        print(f"  {G}场景: {self.scene}{NC}")
        if self.scene == "pentest":
            print(f"  {D} 流程: Recon→Hunt→提权→横向→外泄→报告→飞轮{NC}")
            print(f"  {Y} 注意: pentest 模式 Safety Gate 已关闭，需书面授权{NC}")
            print(f"  {D} 已加载 Anthropic 后渗透技能: 提权/横向/外泄{NC}")
        elif self.scene == "redteam":
            print(f"  {D} 流程: 打点→持久化→规避→C2→清理→报告{NC}")
            print(f"  {D} 已加载 Anthropic 技能: C2/持久化/规避/取证{NC}")
        else:
            print(f"  {D} 流程: bounty 标准七阶段{NC}")

    # ── Anthropic 路由 ───────────────────────────────────────────

    def _execute_anthropic_route(self, phase: dict):
        """加载并提示 Anthropic 防御/后渗透技能。"""
        skills = phase.get("anthropic_skills", [])
        print(f"  {B}{phase.get('name', '')}{NC}")
        print(f"  {D}{phase.get('prompt', '')}{NC}")
        print(f"  {C}需要的 Anthropic 技能:{NC}")
        for s in skills[:5]:
            print(f"    - anthropic-skills/{s}")
        if len(skills) > 5:
            print(f"    ... 共 {len(skills)} 个")
        print(f"  {D}加载: Skill(\"{skills[0]}\"){NC}")

        # 检查技能文件是否存在
        from pathlib import Path
        base = Path(__file__).parent.parent.parent / "anthropic-skills"
        missing = []
        for s in skills:
            if not (base / s).exists():
                missing.append(s)
        if missing:
            print(f"  {Y}  缺失 {len(missing)} 个技能: {', '.join(missing[:3])}{NC}")

        data_limits = phase.get("data_limits", "")
        if data_limits:
            print(f"  {R}数据限制: {data_limits}{NC}")

    # ── P0: Safety Gate ─────────────────────────────────────────

    def _execute_p0(self, phase: dict):
        """红线自动生效，验证 safety_gate 已加载。"""
        try:
            from aimy.tools.safety_gate import get_status
            s = get_status()
            print(f"  {G}[v] Safety Gate 已启用 (拦截={s['blocked']}, 净化={s['sanitized']}){NC}")
        except ImportError:
            print(f"  {Y}⚠ safety_gate 未加载，检查配置{NC}")

        print(f"  {D}[ ] ≤1 req/s | ≤500 req/day | 并发≤5{NC}")
        print(f"  {D}[ ] 只读模式 | DROP→SELECT 1 | PUT→403{NC}")
        print(f"  {D}[ ] Scope 白名单校验{NC}")

    # ── P2: 被动侦察 ────────────────────────────────────────────

    def _execute_p2(self, phase: dict):
        cli_template = phase.get("cli", "")
        if cli_template and self.target:
            cmd = cli_template.replace("{target}", self.target)
            print(f"  {G}执行: {cmd}{NC}")
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True,
                                   text=True, timeout=120)
                output = r.stdout + r.stderr
                # 提取输出目录
                for line in output.splitlines():
                    if "资产收集完成" in line or "recon_" in line:
                        self._state["recon_dir"] = line.strip()
                print(f"  {D}{output[:500]}{NC}")
            except subprocess.TimeoutExpired:
                print(f"  {Y}⚠ 超时，需手动检查{NC}")
            except Exception as e:
                print(f"  {Y}⚠ {e}{NC}")
        else:
            # 管线不可用时，直接用 subfinder + httpx
            print(f"  {G}直接运行: subfinder -d {self.target} ...{NC}")
            self._run_cmd(f"subfinder -d {self.target} -silent", label="subfinder")

        self._confirm("P2 完成，进入 P3")

    # ── P3: 主动枚举 ────────────────────────────────────────────

    def _execute_p3(self, phase: dict):
        tools = phase.get("tools", {})
        for tool_name, tool_path in tools.items():
            module = tool_path.replace("/", ".").replace(".py", "")
            print(f"  {G}[{tool_name}] {module}{NC}")
            try:
                __import__(module, fromlist=[""])
                print(f"  {D}  [v] 模块可用{NC}")
            except ImportError:
                print(f"  {Y}  ⚠ 模块不可用: {module}{NC}")

        # 指纹匹配 → 条件触发
        cond = phase.get("conditional", [])
        if cond and self.verbose:
            print(f"  {D}条件触发规则: {len(cond)} 条{NC}")
            for c in cond:
                print(f"    {c.get('match', '?')} → {c.get('read', c.get('test', c.get('run', '?')))}")

        self._confirm("P3 完成，进入 P4")

    # ── P4: 漏洞狩猎 ────────────────────────────────────────────

    def _execute_p4(self, phase: dict):
        signal_map = phase.get("signal_map", {})
        burp_tools = phase.get("burp_tools", {})
        stuck = phase.get("stuck_fallback", [])

        print(f"  {B}{len(signal_map)} 条信号→工具映射已就绪{NC}")

        # 自动匹配信号（如果有资产清单）
        if self._state.get("host_tech"):
            for entry in self._state["host_tech"]:
                matched = self._match_signals(str(entry), signal_map)
                for m in matched:
                    print(f"  {G}[v] 匹配: {m['signal']} → {m['tool']}{NC}")

        print(f"  {D}Burp 工具: {', '.join(burp_tools.values())}{NC}")
        print(f"  {D}卡壳兜底: {len(stuck)} 份文档{NC}")

        # 卡壳时推荐读的文档
        if stuck and self.verbose:
            print(f"  {Y}没思路时依次翻:{NC}")
            for i, s in enumerate(stuck[:5], 1):
                print(f"    {i}. {s}")

        # 自动调对应检测器
        auto_detect = self._auto_detect()
        if auto_detect:
            self._state["findings"].extend(auto_detect)

        # 业务流程分析
        self._run_workflow_analysis()

    def _match_signals(self, text: str, signal_map: dict) -> list:
        """根据资产信息匹配 P4 信号。"""
        matched = []
        for key, sig in signal_map.items():
            pattern = sig.get("match", "")
            if pattern and re.search(pattern, text, re.IGNORECASE):
                matched.append({
                    "signal": sig.get("playbook", key),
                    "tool": sig.get("tool", ""),
                })
        return matched

    def _auto_detect(self) -> list:
        """自动跑常见检测器。"""
        findings = []
        if not self.target:
            return findings

        detectors = [
            ("SSRF", f"from aimy.tools.ssrf_detector import check; print(check('{self.target}', 'url'))"),
            ("SQLi", f"from aimy.tools.sql_injection import check; print(check('{self.target}', 'id'))"),
        ]

        for name, cmd in detectors:
            try:
                r = subprocess.run(["python", "-c", cmd],
                                   capture_output=True, text=True, timeout=30)
                out = r.stdout.strip()
                if out and '"vulnerable": true' in out:
                    print(f"  {G}[v] {name} 命中!{NC}")
                    findings.append({"type": name, "result": out[:200]})
                else:
                    print(f"  {D}  {name}: 无命中{NC}")
            except Exception as e:
                print(f"  {D}  {name}: {e}{NC}")

        return findings

    # ── 业务流程分析 ──────────────────────────────────────────

    def _run_workflow_analysis(self):
        """分析端点列表中的业务流程，发现逻辑漏洞。"""
        if not self.target:
            return

        # 从状态中搜集 endpoints
        endpoints = [self.target]
        recon_dir = self._state.get("recon_dir", "")
        if recon_dir:
            urls_file = os.path.join(recon_dir, "3_urls.txt")
            if os.path.exists(urls_file):
                with open(urls_file) as f:
                    endpoints.extend([l.strip() for l in f if l.strip()])

        print(f"  {B}业务流程分析 ({len(endpoints)} 个端点):{NC}")
        try:
            from aimy.tools.workflow_analyzer import WorkflowAnalyzer
            wa = WorkflowAnalyzer(target=self.target, verbose=self.verbose)
            result = wa.analyze(endpoints)
            summary = wa.summary(result)
            if summary:
                print(summary)

                # 收集 findings
                for step in result.steps:
                    for f in step.findings:
                        self._state["findings"].append({
                            "type": "business_logic",
                            "vuln_class": "business logic",
                            "endpoint": step.endpoint,
                            "evidence": f,
                            "title": f"[工作流] {step.name}: {f}",
                        })
        except Exception as e:
            if self.verbose:
                print(f"  {Y}业务流程分析跳过: {e}{NC}")

    # ── P5: 验证门（8问）──────────────────────────────────

    def _execute_p5(self, phase: dict):
        checklist = phase.get("checklist", [])
        validator = phase.get("validator", {})

        print(f"  {B}8 问验证门 (AutoJudge 辅助打分):{NC}")
        for item in checklist:
            ans = self._confirm_yn(f"  {item}")
            if not ans and "停" in item:
                print(f"  {R}[x] 否决，停止{NC}")
                return

        # AutoJudge 辅助（只出分，不替你做决定）
        findings = self._state.get("findings", [])
        for finding in findings:
            try:
                from aimy.tools.auto_judge import AutoJudge
                v = AutoJudge(verbose=False).judge(finding)
                print(f"  {D}AutoJudge 参考: {v.summary} | {v.recommended_action}{NC}")
            except Exception:
                pass

        if validator.get("enabled"):
            print(f"  {D}Validator: 命中后自动验证（后台）{NC}")

        self._state["validated"] = self._state.get("findings", [])

    # ── P7: 飞轮 ────────────────────────────────────────────────

    def _execute_p7(self, phase: dict):
        triggers = phase.get("auto_triggers", [])
        for t in triggers:
            print(f"  {D}→ {t}{NC}")

        manual = phase.get("manual", "")
        if manual:
            print(f"  {Y}完整飞轮: {manual}{NC}")

    # ── 人工阶段前的自动化辅助 ──────────────────────────────

    def _pre_manual_hook(self, phase_key: str, phase: dict):
        """进入人工阶段前，自动做一些事。"""
        if phase_key == "p6":
            # P6: 自动查 H1 同类案例
            validated = self._state.get("validated", [])
            for finding in validated:
                vc = finding.get("vuln_class", "") or finding.get("type", "")
                if vc:
                    self._lookup_h1_cases(vc)

    def _lookup_h1_cases(self, vuln_class: str):
        """查 H1 上同类漏洞的案例，供写报告参考。"""
        from pathlib import Path

        h1_map = {
            "ssrf": "server-side-request-forgery-ssrf",
            "sqli": "blind-sql-injection",
            "xss": "cross-site-scripting-xss",
            "idor": "insecure-direct-object-reference-idor",
            "xxe": "xml-external-entity-xxe",
            "cmdi": "code-injection",
            "ssti": "server-side-template-injection-ssti",
            "lfi": "path-traversal",
            "cors": "cors",
            "csrf": "cross-site-request-forgery-csrf",
            "jwt": "jwt",
            "race": "race-condition",
            "graphql": "graphql",
            "business logic": "business-logic-errors",
            "auth bypass": "authentication-bypass",
            "file upload": "code-injection",
            "rce": "code-injection",
            "info disclosure": "information-disclosure",
            "open redirect": "open-redirect",
            "clickjacking": "clickjacking",
            "smuggling": "http-request-smuggling",
        }

        h1_key = h1_map.get(vuln_class.lower())
        if not h1_key:
            print(f"  {Y}[H1] 无 {vuln_class} 的案例映射{NC}")
            return

        h1_path = _ROOT / "references" / "h1-reports" / "by-weakness" / f"{h1_key}.md"
        if not h1_path.exists():
            print(f"  {Y}[H1] 文件不存在: {h1_path.name}{NC}")
            return

        try:
            text = h1_path.read_text(encoding="utf-8")
        except Exception:
            print(f"  {Y}[H1] 读取失败{NC}")
            return

        lines = text.splitlines()
        report_count = 0
        titles = []
        for line in lines:
            if line.startswith("### ["):
                report_count += 1
                title = line.replace("### [", "").split("](")[0] if "](" in line else line[5:]
                titles.append(title[:80])

        print(f"\n  {C}[H1] {vuln_class}: {report_count} 个公开案例{NC}")
        for i, t in enumerate(titles[:3], 1):
            print(f"  {D}  {i}. {t}{NC}")
        if titles:
            print(f"  {D}  完整列表: references/h1-reports/by-weakness/{h1_key}.md{NC}")

    # ── 人工阶段 ────────────────────────────────────────────────

    def _wait_manual(self, phase: dict):
        prompt = phase.get("prompt", "")
        checklist = phase.get("checklist", [])

        print(f"  {Y}需要人工操作:{NC}")
        print(f"  {D}{prompt}{NC}")
        for item in checklist:
            print(f"  {D}  [ ] {item}{NC}")
        input(f"\n  {B}完成后按 Enter 继续...{NC}")

    # ── 辅助 ────────────────────────────────────────────────────

    def _print_banner(self, order, name):
        print(f"\n{G}{'='*50}{NC}")
        print(f"{B}P{order}: {name}{NC}")
        print(f"{G}{'='*50}{NC}")

    def _run_cmd(self, cmd: str, label: str = ""):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=30)
            if label:
                print(f"  {D}  {label}: {r.stdout.strip()[:200]}{NC}")
            return r.stdout
        except Exception as e:
            print(f"  {Y}  {label}: {e}{NC}")
            return ""

    def _confirm(self, msg: str) -> bool:
        ans = input(f"\n  {Y}{msg}? [Y/n]: {NC}").strip().lower()
        return ans != "n"

    def _confirm_yn(self, msg: str) -> bool:
        ans = input(f"  {msg} [y/N]: {NC}").strip().lower()
        return ans == "y"

    def _summary(self):
        print(f"\n{C}{'='*50}{NC}")
        print(f"{B}PhaseManager 完成{NC}")
        print(f"  目标: {self.target}")
        print(f"  完成: {', '.join(self._state['completed_phases'])}")
        print(f"  发现: {len(self._state.get('findings', []))} 个")
        print(f"  错误: {len(self._state.get('errors', []))} 个")
        if self._state.get("errors"):
            for e in self._state["errors"]:
                print(f"    {R}{e}{NC}")
        print(f"{C}{'='*50}{NC}{NC}")


# ── CLI 入口 ──────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="PhaseManager -- 七阶段流程自动推进")
    ap.add_argument("-t", "--target", required=True, help="目标域名")
    ap.add_argument("-p", "--provider", default="", help="LLM 提供商")
    ap.add_argument("--phase", default="p0", help="起始阶段 (p0-p7)")
    ap.add_argument("--single", default="", help="只跑单个阶段")
    args = ap.parse_args()

    pm = PhaseManager(target=args.target, provider=args.provider)

    if args.single:
        pm.run_phase(args.single)
    else:
        pm.run(start_from=args.phase)


if __name__ == "__main__":
    main()
