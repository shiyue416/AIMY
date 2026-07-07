"""
auto_verify_helper.py — Burp MCP auto-verify + OOB + Autopilot
Copy to: C:/Users/PC/Desktop/彦/aimy/core/auto_verify.py
"""
from __future__ import annotations
import json, re, time
from typing import Optional

# ══════════════════════════════════════════════════════════════════
# 1. Burp MCP 自动验证
# ══════════════════════════════════════════════════════════════════

class BurpAutoVerify:
    """通过 Burp MCP 工具自动验证候选漏洞。

    使用方式：
        verifier = BurpAutoVerify(mcp_client)
        result   = verifier.verify_ssrf(request, host, port)
    """

    def __init__(self, mcp=None):
        """mcp: 实现了 call_tool(name, params) 的客户端，None 时降级为占位。"""
        self._mcp = mcp

    def _call(self, tool: str, **kwargs) -> dict:
        if self._mcp is None:
            return {"error": "no mcp client"}
        try:
            return self._mcp.call_tool(tool, kwargs) or {}
        except Exception as e:
            return {"error": str(e)}

    # ── 发送请求 ───────────────────────────────────────────────────

    def send(self, raw_request: str, host: str, port: int = 443,
             use_tls: bool = True) -> dict:
        """通过 Burp 发送请求，返回响应。"""
        return self._call("mcp__burp__http_send_request",
                          raw_request=raw_request, host=host,
                          port=port, use_tls=use_tls)

    def fuzz(self, raw_request: str, host: str, port: int,
             payloads: list, use_tls: bool = True) -> list:
        """批量 fuzz 单个注入点（FUZZ 关键词标记位置）。"""
        return self._call("mcp__burp__http_fuzz",
                          request=raw_request, host=host, port=port,
                          use_tls=use_tls, payloads=payloads) or []

    # ── SSRF 验证（OOB）────────────────────────────────────────────

    def verify_ssrf_oob(self, raw_request: str, host: str, port: int,
                        param_name: str = "FUZZ",
                        use_tls: bool = True) -> dict:
        """
        1. 生成 Collaborator payload
        2. 注入到请求中
        3. 发送请求
        4. 轮询回调
        返回: {"success": bool, "interaction": dict|None}
        """
        # Step 1: 生成 OOB payload
        collab = self._call("mcp__burp__collaborator_create_client")
        if "error" in collab:
            return {"success": False, "error": collab["error"]}

        payload_r = self._call("mcp__burp__collaborator_generate_payload",
                               client_id=collab.get("clientId",""))
        payload   = payload_r.get("payload", "oob-test.burpcollaborator.net")
        oob_url   = f"http://{payload}"

        # Step 2: 注入 payload
        injected = raw_request.replace(param_name, oob_url)

        # Step 3: 发送请求
        self._call("mcp__burp__http_send_request",
                   raw_request=injected, host=host, port=port, use_tls=use_tls)

        # Step 4: 轮询回调（最多30秒）
        for _ in range(6):
            time.sleep(5)
            interactions = self._call("mcp__burp__collaborator_poll",
                                      client_id=collab.get("clientId",""))
            items = interactions.get("interactions", [])
            if items:
                return {"success": True, "interaction": items[0],
                        "payload": oob_url}

        return {"success": False, "payload": oob_url, "interaction": None}

    # ── SQLi 验证 ─────────────────────────────────────────────────

    def verify_sqli(self, raw_request: str, host: str, port: int,
                    use_tls: bool = True) -> dict:
        """注入经典错误触发 payload，检查响应差异。"""
        payloads = ["'", "''", "1 AND 1=1", "1 AND 1=2",
                    "1' AND '1'='1", "1' AND '1'='2"]
        results = self.fuzz(raw_request, host, port, payloads, use_tls)
        if not results:
            return {"success": False}
        # 检查响应长度差异
        lengths = [r.get("response_length", 0) for r in results if isinstance(r, dict)]
        if len(set(lengths)) > 2:
            return {"success": True, "evidence": "response length variation on SQLi payloads"}
        # 检查 SQL 错误关键词
        errors = ["syntax error", "mysql_fetch", "ORA-", "SQLSTATE",
                  "Unclosed quotation", "quoted string not properly terminated"]
        for r in results:
            body = str(r.get("response_body","")).lower()
            for err in errors:
                if err.lower() in body:
                    return {"success": True, "evidence": f"SQL error: {err}"}
        return {"success": False}

    # ── XSS 验证 ──────────────────────────────────────────────────

    def verify_xss(self, raw_request: str, host: str, port: int,
                   use_tls: bool = True) -> dict:
        """检查 payload 是否反射在响应中。"""
        marker  = "xss7test7marker"
        payload = f"<script>alert('{marker}')</script>"
        injected = raw_request.replace("FUZZ", payload)
        resp = self.send(injected, host, port, use_tls)
        body = str(resp.get("response_body", ""))
        if marker in body or payload in body:
            context = self._detect_context(body, marker)
            return {"success": True, "context": context, "payload": payload}
        return {"success": False}

    def _detect_context(self, body: str, marker: str) -> str:
        idx = body.find(marker)
        if idx < 0: return "unknown"
        snippet = body[max(0,idx-50):idx+50]
        if "<script" in snippet: return "javascript"
        if 'value="' in snippet or "value='" in snippet: return "html_attribute"
        return "html_body"

    # ── 403 绕过 ──────────────────────────────────────────────────

    def verify_403_bypass(self, url: str, host: str, port: int,
                          use_tls: bool = True) -> dict:
        """尝试常见 403 绕过技巧，返回成功的 bypass。"""
        bypasses = [
            ("X-Forwarded-For: 127.0.0.1",   None),
            ("X-Original-URL: /",            None),
            ("X-Rewrite-URL: /",             None),
            ("X-Custom-IP-Authorization: 127.0.0.1", None),
            (None,                           url + "/../"),
            (None,                           url + "%2e/"),
            (None,                           url + "?"),
        ]
        base_req = f"GET {url} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        for extra_header, alt_path in bypasses:
            if alt_path:
                req = f"GET {alt_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
            elif extra_header:
                req = f"GET {url} HTTP/1.1\r\nHost: {host}\r\n{extra_header}\r\n\r\n"
            else:
                continue
            resp = self.send(req, host, port, use_tls)
            status = resp.get("status_code", 0)
            if 200 <= status < 300:
                return {"success": True, "bypass": extra_header or alt_path,
                        "status": status}
        return {"success": False}


# ══════════════════════════════════════════════════════════════════
# 2. 集成到 ReActLoop 的钩子
# ══════════════════════════════════════════════════════════════════

def attach_to_loop(loop, mcp=None):
    """把 BurpAutoVerify 挂到现有 ReActLoop 实例上。

    用法:
        from aimy.core.auto_verify import attach_to_loop
        attach_to_loop(loop, mcp=my_mcp_client)
    """
    verifier = BurpAutoVerify(mcp=mcp)
    loop._verifier = verifier

    original_executor = loop.tool_executor

    def enhanced_executor(name: str, args: dict) -> str:
        result = original_executor(name, args)
        # 检测工具结果中的漏洞信号，自动触发验证
        _auto_verify_on_signal(loop, verifier, name, args, result)
        return result

    loop.tool_executor = enhanced_executor
    return verifier


def _auto_verify_on_signal(loop, verifier: BurpAutoVerify,
                            tool_name: str, args: dict, result: str):
    """检测工具结果中的漏洞信号，自动触发对应验证。"""
    result_lower = result.lower()
    target       = getattr(loop.state, "target", "")
    if not target:
        return

    # SSRF 信号
    SSRF_SIGNALS = ["ssrf", "server-side request forgery",
                    "internal", "169.254", "metadata", "aws credentials"]
    if any(s in result_lower for s in SSRF_SIGNALS):
        _log_auto(loop, "SSRF signal detected → OOB verify queued")
        loop.state.findings.append({
            "tool": "ssrf", "severity": "high",
            "summary": f"SSRF signal in {tool_name} output",
            "auto_verify": "oob_pending",
        })

    # SQLi 信号
    SQLI_SIGNALS = ["sql", "syntax error", "ora-", "sqlstate",
                    "mysql", "unclosed quotation"]
    if any(s in result_lower for s in SQLI_SIGNALS):
        _log_auto(loop, "SQLi signal detected → recorded")
        loop.state.findings.append({
            "tool": "sqli", "severity": "high",
            "summary": f"SQLi signal in {tool_name} output",
        })

    # XSS 信号
    XSS_SIGNALS = ["reflected", "xss", "<script", "javascript:", "onerror="]
    if any(s in result_lower for s in XSS_SIGNALS):
        _log_auto(loop, "XSS signal detected → recorded")
        loop.state.findings.append({
            "tool": "xss", "severity": "medium",
            "summary": f"XSS signal in {tool_name} output",
        })


def _log_auto(loop, msg: str):
    if getattr(loop, "verbose", True):
        print(f"\033[2m  [AutoVerify] {msg}\033[0m")


# ══════════════════════════════════════════════════════════════════
# 3. Autopilot 模式
# ══════════════════════════════════════════════════════════════════

class Autopilot:
    """半自主挖洞循环。

    Phase 1: Recon     → subfinder + httpx（被动）
    Phase 2: Hunt      → aimy agent loop（主动，限速）
    Phase 3: Validate  → BurpAutoVerify
    Phase 4: Record    → EVX record_finding()

    使用方式:
        from aimy.core.auto_verify import Autopilot
        ap = Autopilot(client, verbose=True)
        ap.run("target.com", max_targets=5, time_budget=3600)
    """

    def __init__(self, llm_client, mcp=None, verbose: bool = True):
        self.client  = llm_client
        self.verifier = BurpAutoVerify(mcp=mcp)
        self.verbose  = verbose

    def run(self, root_domain: str, max_targets: int = 5,
            time_budget: int = 3600) -> list:
        import time as _time
        from aimy.core.loop import ReActLoop
        from aimy.core.state import AgentState
        from aimy.memory.flywheel import record_finding

        t0       = _time.time()
        findings = []

        self._log(f"\n[Autopilot] Starting on {root_domain}")
        self._log(f"  max_targets={max_targets}  budget={time_budget}s")

        # ── Phase 1: Recon ─────────────────────────────────────────
        self._log("\n[Phase 1] Recon...")
        targets = self._recon(root_domain, max_targets)
        self._log(f"  Found {len(targets)} live targets")

        # ── Phase 2+3: Hunt each target ────────────────────────────
        for i, target in enumerate(targets[:max_targets], 1):
            if _time.time() - t0 > time_budget:
                self._log("[Autopilot] Time budget exhausted")
                break

            self._log(f"\n[Phase 2] Hunting {target}  ({i}/{len(targets)})")
            state = AgentState(target=target)
            loop  = ReActLoop(client=self.client, state=state,
                              verbose=self.verbose, time_budget=300)
            attach_to_loop(loop, mcp=self.verifier._mcp)

            query = (f"Hunt {target} for high-severity vulnerabilities: "
                     f"SSRF, SQLi, Auth Bypass, IDOR. "
                     f"Be systematic. Rate limit: 1 req/s max.")
            loop.run(query)

            # ── Phase 2.5: ToolKit 自动检测 ─────────────────────────
            try:
                from aimy.core.bridge import ToolKit
                tk = ToolKit(target_url=f"https://{target}", verbose=self.verbose)
                detector_findings = tk.run_all(max_per_type=3)
                if detector_findings:
                    self._log(f"  [Phase 2.5] ToolKit found {len(detector_findings)} signals")
                    for df in detector_findings:
                        state.findings.append({
                            "tool": df.get("vuln_class", "detector"),
                            "severity": "medium",
                            "summary": df.get("summary", str(df))[:200],
                            "source": "toolkit",
                        })
            except Exception as e:
                if self.verbose:
                    self._log(f"  [Phase 2.5] ToolKit error: {str(e)[:80]}")

            # ── Phase 3: Auto-verify ────────────────────────────────
            for f in state.findings:
                if f.get("auto_verify") == "oob_pending":
                    self._log(f"  [Phase 3] OOB verify for {f['summary'][:60]}")
                    f["verified"] = False

            # ── Phase 4: Record ────────────────────────────────────
            for f in state.findings:
                record_finding(
                    target=target,
                    vuln_class=f.get("tool", "unknown"),
                    severity=f.get("severity", ""),
                    technique=f.get("summary","")[:200],
                    outcome="",
                )
                findings.append({**f, "target": target})
                self._log(f"  [Phase 4] Recorded: {f.get('tool','')} @ {target}")

            # Rate limit between targets
            _time.sleep(2)

        self._log(f"\n[Autopilot] Done. {len(findings)} findings in "
                  f"{int(_time.time()-t0)}s")
        return findings

    def _recon(self, domain: str, limit: int) -> list:
        """被动子域名发现（不发包）。"""
        import subprocess, sys
        targets = [domain]
        # Try subfinder
        try:
            r = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-passive"],
                capture_output=True, text=True, timeout=30
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if line and "." in line:
                    targets.append(line)
                    if len(targets) >= limit:
                        break
        except Exception:
            pass
        return targets[:limit]

    def _log(self, msg: str):
        if self.verbose:
            print(msg)
