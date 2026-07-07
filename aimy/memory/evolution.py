"""EvolutionEngine — 代码自进化引擎

飞轮只记数据，这个引擎负责根据数据改代码。

四个进化维度:
  1. 信号发现  — 手动挖到的洞不在19种信号里? 自动加一条
  2. 模型调优  — 哪个模型在哪个阶段表现好? 自动改PHASE_MODELS
  3. Safety Gate调优 — 误报太多? 自动调正则
  4. 检测器生成 — 新漏洞类被accept多次? 自动创建检测器模板

用法:
    from aimy.memory.evolution import EvolutionEngine
    ee = EvolutionEngine()
    ee.evolve_all()  # 跑全部进化流程
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from aimy.tools.log_utils import get_logger

logger = get_logger("evolution")

_HERE = Path(__file__).parent
_ROOT = _HERE.parent.parent
PHASES_JSON = _ROOT / "aimy" / "core" / "phases.json"
PROVIDERS_PY = _ROOT / "aimy" / "llm" / "providers.py"
PHASE_MANAGER_PY = _ROOT / "aimy" / "core" / "phase_manager.py"
SKILLS_DIR = _ROOT / "skills"


class EvolutionEngine:
    def __init__(self, verbose: bool = True, dry_run: bool = False):
        self.verbose = verbose
        self.dry_run = dry_run  # True = 只输出建议，不改代码
        self._changes: list[str] = []

    def log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    def warn(self, msg: str):
        if self.verbose:
            print(f"  [WARN] {msg}")

    def change(self, msg: str):
        self._changes.append(msg)
        print(f"  >>> {msg}")

    # ── 主入口 ──────────────────────────────────────────────────

    def evolve_all(self):
        """跑全部进化流程。"""
        print("\n\x1b[0;36m==================================================\x1b[0m")
        print("\x1b[1mEvolutionEngine -- 系统自进化\x1b[0m")
        if self.dry_run:
            print("  \x1b[1;33m[DRY RUN] 只输出建议，不改代码\x1b[0m")
        print("\x1b[0;36m==================================================\x1b[0m\n")

        self._evolve_signals()
        self._evolve_model_routing()
        self._evolve_safety_gate()

        if self._changes:
            print(f"\n  \x1b[1;32m进化建议: {len(self._changes)} 条\x1b[0m")
            for c in self._changes:
                print(f"    \x1b[2m>> {c}\x1b[0m")
            if self.dry_run:
                print(f"\n  \x1b[1;33m设置 dry_run=False 以应用改动\x1b[0m")
        else:
            print(f"\n  \x1b[1;33m无改动建议\x1b[0m")

        return self._changes

    # ── 1. 信号发现 ────────────────────────────────────────────

    def _evolve_signals(self):
        """从 FeedbackDB 中发现不在 phases.json 里的新信号。"""
        self.log("Phase 1: 信号发现...")

        try:
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            # 取最近 accepted 的技法和对应的 URL/端点
            rows = db._conn.execute(
                "SELECT technique, vuln_class, report_id FROM reports "
                "WHERE outcome='accepted' ORDER BY id DESC LIMIT 50"
            ).fetchall()
            db.close()
        except Exception as e:
            self.warn(f"FeedbackDB 不可用: {e}")
            return

        if not rows:
            self.log("  无 accepted 记录")
            return

        # 加载当前信号表
        signals = self._load_signal_map()
        if not signals:
            self.warn("无法加载 phases.json 信号表")
            return

        # 分析哪些技法没被现有信号覆盖
        unmatched = []
        for technique, vuln_class, rid in rows:
            text = f"{technique} {vuln_class} {rid or ''}".lower()
            matched = False
            for key, sig in signals.items():
                pattern = sig.get("match", "")
                if pattern and re.search(pattern, text, re.IGNORECASE):
                    matched = True
                    break
            if not matched and technique:
                unmatched.append((technique, vuln_class, rid))

        if not unmatched:
            self.log("  所有 accepted 技法都被现有信号覆盖")
            return

        # 从最频繁出现的未匹配技法中提取新信号
        freq = Counter()
        for technique, vuln_class, _ in unmatched:
            freq[(technique, vuln_class)] += 1

        self.log(f"  发现 {len(unmatched)} 条未匹配技法")
        new_signals = []
        for (tech, vc), count in freq.most_common(5):
            suggested_regex = self._suggest_regex(tech, vc)
            suggested_tool = self._suggest_tool(vc)
            signal_key = f"auto_{vc.lower().replace(' ', '_')[:20]}"

            new_signals.append({
                "key": signal_key,
                "match": suggested_regex,
                "playbook": f"{vc.lower().replace(' ', '-')}.md",
                "tool": suggested_tool,
                "auto_discovered": True,
                "hit_count": count,
            })

            self.change(
                f"新信号: [{vc}] \"{tech[:50]}...\" (x{count})\n"
                f"    添加: \"{signal_key}\": {{\n"
                f"      \"match\": \"{suggested_regex}\",\n"
                f"      \"tool\": \"{suggested_tool}\"\n"
                f"    }}"
            )

        # 如果 apply 模式，实际写入 phases.json
        if not self.dry_run and new_signals:
            self._apply_new_signals(new_signals)

    # ── 2. 模型路由调优 ────────────────────────────────────────

    def _evolve_model_routing(self):
        """分析哪个模型在哪个阶段表现好，自动调优。"""
        self.log("Phase 2: 模型路由调优...")

        try:
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            # 取各模型的接受率
            rows = db._conn.execute(
                "SELECT technique, outcome FROM reports WHERE technique LIKE '%model:%' "
                "ORDER BY id DESC LIMIT 100"
            ).fetchall()
            db.close()
            if not rows:
                self.log("  无模型表现数据")
                return
        except Exception:
            self.log("  无模型表现数据 (需接入模型跟踪)")
            return

    # ── 3. Safety Gate 调优 ────────────────────────────────────

    def _evolve_safety_gate(self):
        """分析 Safety Gate 是否有误报/漏报，调优正则规则。"""
        self.log("Phase 3: Safety Gate 调优...")

        try:
            from aimy.tools.safety_gate import get_status
            s = get_status()
            self.log(f"  当前: 拦截={s['blocked']}, 净化={s['sanitized']}, 通过={s['passed']}")
        except Exception:
            self.log("  Safety Gate 不可用")

        # 分析是否有被 Safety Gate 拦截但实际上是有效利用的场景
        try:
            archive_dir = _ROOT / "evidence" / "safety_intercepts"
            if archive_dir.exists():
                count = len(list(archive_dir.glob("*.json")))
                if count > 0:
                    self.change(f"Safety Gate 拦截记录: {count} 条，建议人工审查是否有误杀")
        except Exception:
            pass

    def _apply_new_signals(self, new_signals: list[dict]):
        """实际写入 phases.json，添加新信号。"""
        if not PHASES_JSON.exists():
            self.warn("phases.json 不存在")
            return

        # 备份
        backup = PHASES_JSON.with_suffix(".json.bak")
        import shutil
        shutil.copy2(str(PHASES_JSON), str(backup))
        self.log(f"  备份: {backup.name}")

        try:
            data = json.loads(PHASES_JSON.read_text(encoding="utf-8"))
            p4 = data.setdefault("phases", {}).setdefault("p4", {})
            signal_map = p4.setdefault("signal_map", {})

            added = 0
            for ns in new_signals:
                key = ns.pop("key")
                if key not in signal_map:
                    signal_map[key] = ns
                    added += 1

            if added:
                PHASES_JSON.write_text(
                    json.dumps(data, ensure_ascii=False, indent=2),
                    encoding="utf-8"
                )
                self.log(f"  写入 phases.json: 新增 {added} 条信号")
            else:
                self.log("  信号已存在，无需添加")
        except Exception as e:
            self.warn(f"写入 phases.json 失败: {e}")
            # 还原备份
            shutil.copy2(str(backup), str(PHASES_JSON))

    # ── 辅助 ────────────────────────────────────────────────────

    def _load_signal_map(self) -> dict:
        """从 phases.json 加载信号映射表。"""
        if PHASES_JSON.exists():
            try:
                data = json.loads(PHASES_JSON.read_text(encoding="utf-8"))
                p4 = data.get("phases", {}).get("p4", {})
                return p4.get("signal_map", {})
            except Exception:
                return {}
        return {}

    # 通用停用词（不产生信号价值）
    _STOP_WORDS = frozenset({
        "bug", "bounty", "agent", "hunt", "hunter", "test", "testing",
        "scan", "scanner", "check", "checker", "detect", "detector",
        "tool", "script", "python", "bash", "shell", "cmd",
        "vuln", "vulnerability", "vulnerabilities", "exploit", "payload",
        "attack", "attacker", "malicious", "security", "hack",
        "using", "based", "via", "with", "from", "into", "over",
        "automated", "automatic", "general", "common", "basic",
        "example", "demo", "sample", "simple", "advanced",
        "assessment", "analysis", "audit", "review", "test",
        "discovery", "enumeration", "recon", "reconnaissance",
        "proof", "concept", "poc", "report", "finding",
    })

    # 漏洞类 → 已知信号模式（从现有 phases.json 信号提取）
    _VULN_SIGNAL_PATTERNS = {
        "ssrf": r"url=|redirect=|proxy=|fetch=|webhook=|callback=|\\?target=",
        "sqli": r"(id|page|cat|pid|uid|article)=|sql|query|select|union|sleep",
        "xss": r"q=|search=|query=|name=|callback=|jsonp=|<script|alert",
        "idor": r"/api/user/|/api/order/|/profile/|uid=|user_id=|customer=|account=",
        "cmdi": r"cmd=|command=|exec=|ping=|nslookup=|traceroute=|whoami",
        "ssti": r"template=|render=|name=|{{|\\$\\{|#\\{|%\\{",
        "jwt": r"eyJ|Authorization:\s*Bearer|JWT|jwt|token",
        "xxe": r"xml|svg|DOCTYPE|entity|XXE|upload.*xml",
        "cors": r"Origin:|Access-Control|CORS|cors|cross.origin",
        "csrf": r"csrf|token|anti.csrf|same.site|_token",
        "graphql": r"graphql|query{|mutation{|introspection|gql",
        "race": r"race|concurrent|toctou|parallel|time.of.check",
        "lfi": r"file=|path=|include=|template=|\\.\\./|..\\\\",
        "business": r"order|payment|price|coupon|checkout|refund|wallet|balance|discount",
        "auth": r"login|signup|register|password|reset|forgot|oauth|sso|2fa|mfa",
        "upload": r"upload|file.*path|multipart|attachment|avatar|import",
        "takeover": r"cname|cloudfront|s3|heroku|github\.io|azure|unbounce",
        "smuggling": r"content.length|transfer.encoding|te\.cl|cl\.te|http/2",
        "prototype": r"__proto__|constructor|prototype|merge|assign",
        "info": r"\\.git|\\.env|config|backup|swagger|actuator|debug|heapdump",
        "redirect": r"redirect=|next=|url=|return=|destination=|target=",
        "waf": r"cloudflare|akamai|mod_security|waf|blocked|challenge",
        "llm": r"prompt|llm|chatbot|ai|gpt|inject|system.*message",
    }

    # 漏洞类 → 检测工具（完整版）
    _TOOL_MAP = {
        "ssrf": "aimy/tools/ssrf_detector.py",
        "sqli": "aimy/tools/sql_injection.py",
        "xss": "aimy/tools/xss_detector.py",
        "idor": "aimy/tools/dual_session.py",
        "cmdi": "aimy/tools/cmdi_detector.py",
        "ssti": "aimy/tools/ssti_detector.py",
        "jwt": "aimy/tools/jwt_detector.py",
        "xxe": "aimy/tools/deserialization_detector.py",
        "cors": "aimy/tools/cors_scanner.py",
        "graphql": "aimy/tools/graphql_scanner.py",
        "race": "aimy/tools/race_condition.py",
        "lfi": "aimy/tools/lfi_scanner.py",
        "business logic": "aimy/tools/biz_logic_scanner.py",
        "auth bypass": "aimy/tools/auth_bypass.py",
        "file upload": "aimy/tools/file_access.py",
        "prototype pollution": "aimy/tools/proto_pollution.py",
        "smuggling": "aimy/tools/http_client.py",
        "subdomain takeover": "aimy/tools/recon/subdomain.py",
        "open redirect": "aimy/tools/http_client.py",
        "info disclosure": "aimy/tools/attack_surface.py",
        "business": "aimy/tools/biz_logic_scanner.py",
        "auth": "aimy/tools/auth_bypass.py",
        "recon": "aimy/tools/recon_pipeline.py",
    }

    def _suggest_regex(self, technique: str, vuln_class: str) -> str:
        """根据技法和漏洞类生成精准的正则匹配模式。

        策略:
          1. 优先用已知漏洞类的信号模式
          2. 从技法名中提取有意义的非停用词
          3. 结合 URL 模式、参数名、文件扩展名
        """
        vc_lower = vuln_class.lower()

        # 1. 如果漏洞类有已知信号模式，优先使用
        for key, pattern in self._VULN_SIGNAL_PATTERNS.items():
            if key in vc_lower or vc_lower in key:
                return pattern

        # 2. 从技法中提取有意义的词（过滤停用词+短词）
        tech_lower = technique.lower()
        words = re.findall(r'[a-zA-Z][a-zA-Z0-9_]{3,}', tech_lower)

        meaningful = [
            w for w in words
            if w not in self._STOP_WORDS
            and not w.endswith("ing")      # scanning, testing → 过滤
            and not w.endswith("tion")     # automation, detection → 过滤
            and not w.startswith("re")     # recon, review → 已去停用词
        ]

        # 3. 如果技法中有明确的技术关键词
        tech_keywords = {
            "scope": "scope|authorization|access.control",
            "jwt": "jwt|token|eyJ",
            "oauth": "oauth|redirect_uri|client_id",
            "ldap": "ldap|389|directory",
            "rce": "rce|remote.code|execute|command|shell",
            "deserialization": "deserialize|pickle|objectinput|unserialize",
            "nosql": "nosql|mongodb|\\.find\\(|\\$where",
            "s3": "s3|bucket|amazonaws|storage",
            "kubernetes": "k8s|kubernetes|kube|pod|container",
            "docker": "docker|container|registry",
        }

        for keyword, pattern in tech_keywords.items():
            if keyword in tech_lower or keyword in vc_lower:
                return pattern

        # 4. 降级: 用最有意义的 2-3 个词
        if meaningful:
            # 只保留跟漏洞有明确关联的词
            signal_words = [w for w in meaningful if len(w) >= 4][:3]
            if signal_words:
                return "|".join(signal_words)

        # 5. 最终降级: 用漏洞类
        return vc_lower.replace(" ", "_")

    def _suggest_tool(self, vuln_class: str) -> str:
        """根据漏洞类建议检测工具。"""
        vc_lower = vuln_class.lower()

        # 精确匹配
        if vc_lower in self._TOOL_MAP:
            return self._TOOL_MAP[vc_lower]

        # 模糊匹配
        for key, tool in self._TOOL_MAP.items():
            if key in vc_lower or vc_lower in key:
                return tool

        return "aimy/tools/reasoning_engine.py"


# ── CLI ────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="EvolutionEngine -- 系统自进化")
    ap.add_argument("--apply", action="store_true", help="实际应用改动（默认 dry-run）")
    args = ap.parse_args()

    ee = EvolutionEngine(dry_run=not args.apply)
    ee.evolve_all()


if __name__ == "__main__":
    main()
