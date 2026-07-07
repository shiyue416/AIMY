"""
integration_bridge.py — EVX ↔ 78 工具 ↔ AutoPilot ↔ Benchmark 全互通桥接
Copy to: C:/Users/PC/Desktop/彦/aimy/core/bridge.py

打通三个断层:
  断层2: TechniqueAtomizer 调用 reasoning_engine + payload_mutator
  断层3: AutoPilot 调用 ssrf_detector + biz_logic_scanner + auth_bypass...
  断层4: Benchmark 盲区 → 自动检索对应 playbook 强化学习
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path
from typing import Optional

REF_DIR = Path("C:/Users/PC/Desktop/彦/references")
BENCH_DIR = Path("C:/Users/PC/Desktop/validation-benchmarks/benchmarks")


# ══════════════════════════════════════════════════════════════════
# 断层2: EVX ↔ 78 工具
# ══════════════════════════════════════════════════════════════════

class SmartAtomizer:
    """增强版技法原子拆解器 — 调用 reasoning_engine 做智能推理。

    用法:
        sa = SmartAtomizer()
        atoms    = sa.decompose("blind SSRF via Referer header", vuln_class="ssrf")
        variants = sa.smart_recombine(atoms)
        # → 基于知识图谱 + 推理引擎生成上下文相关变体
    """

    def __init__(self):
        self._reasoning = None
        self._kg = None
        self._loaded = False

    def _lazy_load(self):
        if self._loaded:
            return
        try:
            from aimy.tools.reasoning_engine import ReasoningEngine
            self._reasoning = ReasoningEngine()
        except Exception:
            self._reasoning = None
        try:
            from aimy.tools.knowledge_graph import KnowledgeGraph
            self._kg = KnowledgeGraph()
        except Exception:
            self._kg = None
        self._loaded = True

    def decompose(self, technique: str, vuln_class: str = "") -> dict:
        """调用 reasoning_engine 做智能分解，退化为关键词匹配。"""
        self._lazy_load()
        atoms = {"injection_point": "url_param", "protocol": "http",
                 "encoding": "plain", "context": ""}

        # Try reasoning engine
        if self._reasoning:
            try:
                h = self._reasoning.form_hypothesis(
                    evidence=f"Technique: {technique}",
                    vuln_class=vuln_class or technique.split()[0]
                )
                atoms["injection_point"] = h.parameters.get("injection_point", atoms["injection_point"])
                atoms["protocol"]        = h.parameters.get("protocol", atoms["protocol"])
                atoms["context"]         = h.parameters.get("context", "")
            except Exception:
                pass

        # Fallback: keyword matching
        t = technique.lower()
        for point in ["header", "body", "cookie", "path", "json_field", "url_param"]:
            if point.replace("_", " ") in t or point in t:
                atoms["injection_point"] = point
                break
        for prot in ["http", "https", "gopher", "dict", "file"]:
            if prot in t:
                atoms["protocol"] = prot
                break
        return atoms

    def smart_recombine(self, atoms: dict, vuln_class: str = "") -> list[dict]:
        """基于知识图谱检索 + 推理引擎生成上下文相关变体。"""
        self._lazy_load()
        variants = []

        # Try knowledge graph for historical patterns
        if self._kg:
            try:
                similar = self._kg.query(atoms.get("injection_point", ""), limit=5)
                for entry in similar:
                    if isinstance(entry, dict) and "technique" in entry:
                        variants.append({"desc": str(entry.get("technique",""))[:100],
                                         "source": "knowledge_graph"})
            except Exception:
                pass

        # Try reasoning engine for novel variants
        if self._reasoning:
            try:
                for _ in range(3):
                    next_step = self._reasoning.suggest_next_test(
                        evidence=f"{vuln_class} via {atoms.get('injection_point','')}",
                        tried=[]
                    )
                    if next_step:
                        variants.append({"desc": next_step, "source": "reasoning_engine"})
            except Exception:
                pass

        # Fallback: use payload_mutator
        if not variants:
            try:
                from aimy.tools.payload_mutator import mutate_value
                base_payload = f"{atoms.get('protocol','http')}://127.0.0.1"
                for _ in range(3):
                    mutated = mutate_value(base_payload)
                    variants.append({"desc": mutated, "source": "payload_mutator"})
            except Exception:
                pass

        return variants[:10]


# ══════════════════════════════════════════════════════════════════
# 断层3: AutoPilot ↔ SSRF / BizLogic / Auth / Fuzzer / WAF
# ══════════════════════════════════════════════════════════════════

class ToolKit:
    """AutoPilot 的工具箱 — 对每个目标按优先级跑实际检测器。

    用法:
        tk = ToolKit(target_url="https://target.com")
        findings = tk.run_all(max_per_type=2)
        # → 调用 ssrf_detector, auth_bypass, biz_logic, waf, ssti...
    """

    def __init__(self, target_url: str, verbose: bool = False):
        self.target = target_url
        self.verbose = verbose

    def run_all(self, max_per_type: int = 2) -> list[dict]:
        """按优先级跑所有检测器，返回 findings 列表。"""
        findings = []
        detectors = [
            ("ssrf",              self._check_ssrf),
            ("auth_bypass",       self._check_auth),
            ("biz_logic",         self._check_biz),
            ("waf_detect",        self._check_waf),
            ("ssti",              self._check_ssti),
            ("sqli",              self._check_sqli),
            ("lfi",               self._check_lfi),
            ("xss",               self._check_xss),
            ("idor",              self._check_idor),
            ("cors",              self._check_cors),
            ("graphql",           self._check_graphql),
        ]
        for vuln_name, detector_func in detectors:
            try:
                result = detector_func()
                if result:
                    for item in result[:max_per_type]:
                        item.setdefault("vuln_class", vuln_name)
                        findings.append(item)
                    if self.verbose:
                        print(f"  [{vuln_name}] found {len(result[:max_per_type])}")
            except Exception as e:
                if self.verbose:
                    print(f"  [{vuln_name}] error: {e}")
        return findings

    # Detector wrappers
    def _discover_params(self, url):
        """爬取目标发现所有带参数的端点 + 页面提示"""
        import requests as _req, re as _re
        endpoints = {}
        page_hints = []

        try:
            r = _req.get(url, timeout=10)
            text = r.text
            # 表单字段
            inputs = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', text, _re.I)
            actions = _re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', text, _re.I)
            action = actions[0] if actions else ""
            if inputs:
                ep = action if action.startswith("http") else (url.rstrip("/") + "/" + action.lstrip("/"))
                endpoints[action or "/"] = {"url": ep, "params": list(set(inputs))}

            # 页面内提示的内部地址
            lines_seen = set()
            for m in _re.finditer(r'https?://([\w.-]+)', text):
                h = m.group(1)
                if h not in url and h not in lines_seen and h != "example.com":
                    page_hints.append(h); lines_seen.add(h)
            for m in _re.finditer(r'\b([a-z][a-z0-9-]+[a-z])\b', text):
                h = m.group(1)
                if h not in lines_seen and len(h) > 3 and h not in ("localhost","this","that","from","with","have","com","html","http"):
                    page_hints.append(h); lines_seen.add(h)
        except Exception:
            pass

        if not endpoints:
            endpoints["/"] = {"url": url, "params": []}
        return endpoints, list(set(page_hints))

    def _check_ssrf(self):
        findings = []
        try:
            from aimy.tools.ssrf_detector import check as check_ssrf
            import requests as _req, re as _re
            endpoints, page_hints = self._discover_params(self.target)

            # 对每个端点、每个参数跑 SSRF 检测
            for path, ep in endpoints.items():
                ep_url = ep["url"]
                params = ep["params"]
                if not params:
                    params = ["url", "redirect", "file", "path", "src",
                              "target", "fetch", "load", "page", "next",
                              "image", "img", "callback", "read", "document"]
                for param in params:
                    try:
                        r = check_ssrf(ep_url, param, timeout=8)
                        if r.get("vulnerable"):
                            # 尝试所有页面提示的内部地址作为 payload
                            for h in page_hints[:5]:
                                for proto in ["http"]:
                                    test_url = f"{ep_url}?{param}={proto}://{h}/"
                                    try:
                                        hr = _req.get(test_url, timeout=8)
                                        flag_m = _re.search(r'FLAG\{[^}]+}|flag\{[^}]+}|<FLAG>', hr.text)
                                        if flag_m:
                                            flag_val = flag_m.group(0)
                                            if "<FLAG>" in flag_val:
                                                continue
                                            findings.append({
                                                "vulnerable": True, "type": "ssrf_flag",
                                                "endpoint": ep_url, "parameter": param,
                                                "flag": flag_val,
                                                "summary": f"SSRF via ?{param}={proto}://{h}/ → {flag_val}",
                                            })
                                            if self.verbose:
                                                print(f"    [SSRF] ✓ ?{param}={proto}://{h}/ → {flag_val}")
                                            return findings
                                    except Exception:
                                        pass
                            # 没找到 flag 但 SSRF 可达
                            r["endpoint"] = ep_url
                            r["parameter"] = param
                            findings.append(r)
                            if self.verbose:
                                print(f"    [SSRF] {param}={r.get('payload','')[:30]} → {r.get('type','hit')}")
                    except Exception:
                        pass
        except Exception as e:
            if self.verbose:
                print(f"    [SSRF] error: {e}")
        return findings

    def _check_auth(self):
        try:
            from aimy.tools.auth_bypass import check as check_auth
            result = check_auth(self.target)
            return _normalize(result, "auth_bypass")
        except Exception:
            return []

    def _check_biz(self):
        try:
            from aimy.tools.biz_logic_scanner import check as check_biz
            result = check_biz(self.target)
            return _normalize(result, "biz_logic_scanner")
        except Exception:
            return []

    def _check_waf(self):
        try:
            from aimy.tools.waf_bypass import fingerprint_waf
            waf_name = fingerprint_waf(self.target)
            return [{"tool": "waf_detect", "summary": f"WAF: {waf_name}"}] if waf_name else []
        except Exception:
            return []

    def _check_ssti(self):
        try:
            from aimy.tools.ssti_detector import check as check_ssti
            result = check_ssti(self.target)
            return _normalize(result, "ssti_detector")
        except Exception:
            return []

    def _check_sqli(self):
        try:
            from aimy.tools.sql_injection import check as check_sqli
            result = check_sqli(self.target)
            return _normalize(result, "sql_injection")
        except Exception:
            return []

    def _check_lfi(self):
        try:
            from aimy.tools.lfi_scanner import check as check_lfi
            result = check_lfi(self.target)
            return _normalize(result, "lfi_scanner")
        except Exception:
            return []

    def _check_xss(self):
        try:
            from aimy.tools.xss_detector import check as check_xss
            result = check_xss(self.target)
            return _normalize(result, "xss_detector")
        except Exception:
            return []

    def _check_idor(self):
        try:
            from aimy.tools.auth_engine import check_idor
            result = check_idor(self.target) if hasattr(
                _import_or_none("aimy.tools.auth_engine"), "check_idor"
            ) else []
            return _normalize(result, "auth_engine")
        except Exception:
            return []

    def _check_cors(self):
        try:
            from aimy.tools.cors_scanner import check as check_cors
            result = check_cors(self.target)
            return _normalize(result, "cors_scanner")
        except Exception:
            return []

    def _check_graphql(self):
        try:
            from aimy.tools.graphql_scanner import check as check_graphql
            result = check_graphql(self.target)
            return _normalize(result, "graphql_scanner")
        except Exception:
            return []


def _import_or_none(modname):
    try:
        return __import__(modname, fromlist=["*"])
    except Exception:
        return None


def _normalize(result, tool_name: str) -> list[dict]:
    """把各种检测器返回格式统一为 findings list。"""
    if result is None:
        return []
    if isinstance(result, list):
        return [{"tool": tool_name, "summary": str(r)[:200]} for r in result]
    if isinstance(result, dict):
        return [{"tool": tool_name, "summary": result.get("summary", str(result))[:200]}]
    if isinstance(result, bool) and result:
        return [{"tool": tool_name, "summary": f"{tool_name} detected issue"}]
    return []


# ══════════════════════════════════════════════════════════════════
# 断层4: Benchmark 盲区 → 自动推荐学习资源
# ══════════════════════════════════════════════════════════════════

class LearningAdvisor:
    """Benchmark 盲区 → 自动检索 playbook + 推荐训练靶场。

    用法:
        la = LearningAdvisor()
        plan = la.get_training_plan("ssrf", 0.10)  # SSRF 成功率 10% → 训练计划
    """

    PLAYBOOK_MAP = {
        "ssrf":  ["ssrf", "服务端请求伪造", "blind_request", "cloud_metadata"],
        "sqli":  ["sqli", "sql注入", "sql_injection", "error_based", "blind_sqli"],
        "xss":   ["xss", "跨站脚本", "reflected", "stored", "dom"],
        "ssti":  ["ssti", "模板注入", "jinja2", "twig"],
        "lfi":   ["lfi", "文件包含", "path_traversal"],
        "idor":  ["idor", "越权", "authorization", "access_control"],
        "auth":  ["auth_bypass", "认证绕过", "jwt", "oauth", "authentication"],
        "rce":   ["rce", "命令注入", "代码执行", "command_injection"],
        "csrf":  ["csrf", "跨站请求伪造"],
        "xxe":   ["xxe", "xml外部实体"],
        "biz":   ["biz_logic", "业务逻辑", "race_condition"],
    }
    BENCH_MAP = {
        "ssrf": ["XBEN-020-24"],
        "ssti": ["XBEN-076-24"],
        "sqli": ["XBEN-001-24", "XBEN-002-24", "XBEN-003-24"],
        "idor": ["XBEN-001-24"],
        "auth": ["XBEN-001-24"],
    }

    def get_training_plan(self, vuln_class: str, current_rate: float) -> dict:
        """返回强化训练计划。"""
        kw_list = self.PLAYBOOK_MAP.get(vuln_class.lower(), [vuln_class])

        # 1. 找对应 playbook
        playbooks = []
        for kw in kw_list:
            for pb in REF_DIR.glob("playbooks/**/*"):
                if kw.lower() in pb.name.lower():
                    playbooks.append(str(pb))

        # 2. 找对应靶场
        benches = self.BENCH_MAP.get(vuln_class.lower(), [])

        # 3. 找对应 payload
        payload_files = []
        for kw in kw_list:
            for p in REF_DIR.glob("payloader/**/*"):
                if kw.lower() in p.name.lower():
                    payload_files.append(str(p))

        return {
            "vuln_class": vuln_class,
            "current_rate": current_rate,
            "playbooks": playbooks[:5],
            "training_benches": benches[:5],
            "payload_files": payload_files[:5],
            "suggestion": (
                f"成功率 {current_rate:.0%} 偏低，建议：\n"
                f"  1. 读 playbook: {next(iter(playbooks), 'N/A')}\n"
                f"  2. 打靶场: {', '.join(benches[:3]) or 'N/A'}\n"
                f"  3. 搜 payload: {next(iter(payload_files), 'N/A')}"
            ),
        }
