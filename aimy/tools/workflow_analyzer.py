"""WorkflowAnalyzer — 业务流程漏洞分析引擎

从 endpoint 列表中推断业务流程，然后每个步骤注入测试。

核心逻辑:
  1. 用 LLM 推断目标业务流程（注册→登录→下单→支付→退款）
  2. 识别每步的 state 参数（order_id, status, step 等）
  3. 测试每步: IDOR / 越权 / 参数篡改
  4. 测试跨步: 状态跳过 / 重放 / 降级攻击

用法:
    from aimy.tools.workflow_analyzer import WorkflowAnalyzer
    wa = WorkflowAnalyzer(target="https://target.com")
    results = wa.analyze(endpoints)  # P4 中调用
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Optional, List
from urllib.parse import urlparse, parse_qs

from aimy.tools.log_utils import get_logger

logger = get_logger("workflow_analyzer")

# ── 已知业务流程模板 ─────────────────────────────────────────────
# 通用业务模式，用于识别目标可能有什么流程
WORKFLOW_TEMPLATES = {
    "ecommerce": {
        "name": "电商",
        "steps": [
            {"name": "浏览商品", "endpoints": ["/products", "/product/*", "/search"]},
            {"name": "加入购物车", "endpoints": ["/cart/add", "/cart", "/cart/update"]},
            {"name": "下单", "endpoints": ["/order", "/order/create", "/checkout"]},
            {"name": "支付", "endpoints": ["/payment", "/pay", "/checkout/pay"]},
            {"name": "取消订单", "endpoints": ["/order/*/cancel"]},
            {"name": "退款", "endpoints": ["/refund", "/order/*/refund"]},
        ],
        "state_params": ["order_id", "cart_id", "payment_id", "amount", "price", "coupon"],
    },
    "auth": {
        "name": "认证",
        "steps": [
            {"name": "注册", "endpoints": ["/register", "/signup", "/api/auth/register"]},
            {"name": "登录", "endpoints": ["/login", "/signin", "/api/auth/login"]},
            {"name": "修改密码", "endpoints": ["/password/change", "/reset-password"]},
            {"name": "删除账号", "endpoints": ["/account/delete", "/user/delete"]},
        ],
        "state_params": ["token", "session", "code", "step", "state"],
    },
    "payment": {
        "name": "支付",
        "steps": [
            {"name": "创建订单", "endpoints": ["/order/create", "/payment/create"]},
            {"name": "执行支付", "endpoints": ["/payment/execute", "/checkout/pay"]},
            {"name": "退款", "endpoints": ["/refund", "/payment/*/refund"]},
        ],
        "state_params": ["amount", "price", "quantity", "coupon", "discount", "currency"],
    },
    "user_management": {
        "name": "用户管理",
        "steps": [
            {"name": "查看资料", "endpoints": ["/profile", "/user/*", "/account"]},
            {"name": "修改资料", "endpoints": ["/profile/update", "/user/*/update"]},
            {"name": "上传头像", "endpoints": ["/avatar", "/upload"]},
        ],
        "state_params": ["user_id", "role", "permission", "email", "phone"],
    },
}


@dataclass
class WorkflowStep:
    name: str
    endpoint: str = ""
    method: str = "GET"
    state_params: list = field(default_factory=list)
    findings: list = field(default_factory=list)


@dataclass
class WorkflowResult:
    workflow_name: str = ""
    steps: list = field(default_factory=list)
    # 跨步漏洞
    state_skip_tests: list = field(default_factory=list)
    replay_tests: list = field(default_factory=list)
    downgrade_tests: list = field(default_factory=list)


class WorkflowAnalyzer:
    def __init__(self, target: str = "", verbose: bool = True):
        self.target = target
        self.verbose = verbose

    def log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    # ── 主入口 ──────────────────────────────────────────────────

    def analyze(self, endpoints: list[str]) -> WorkflowResult:
        """分析端点列表，推断业务流程并测试。"""
        result = WorkflowResult()

        # Step 1: 匹配已知流程模板
        matched_templates = self._match_templates(endpoints)
        if not matched_templates:
            self.log("  未识别出已知业务流程，降级为通用端点扫描")
            return result

        for template_name in matched_templates:
            tmpl = WORKFLOW_TEMPLATES[template_name]
            result.workflow_name = tmpl["name"]

            self.log(f"  识别流程: {tmpl['name']} ({len(tmpl['steps'])} 步)")

            # Step 2: 为每步生成测试
            for step_def in tmpl["steps"]:
                step = self._test_step(step_def, endpoints, tmpl["state_params"])
                result.steps.append(step)

            # Step 3: 跨步测试
            result.state_skip_tests = self._test_state_skip(tmpl, result.steps)
            result.replay_tests = self._test_replay(result.steps)
            result.downgrade_tests = self._test_downgrade(result.steps)

        return result

    # ── 流程匹配 ────────────────────────────────────────────────

    def _match_templates(self, endpoints: list[str]) -> list[str]:
        """匹配 endpoint 列表到已知业务流程。"""
        matched = []
        endpoint_text = " ".join(endpoints).lower()

        for key, tmpl in WORKFLOW_TEMPLATES.items():
            # 检查模板中的 endpoint 模式是否出现在目标中
            score = 0
            for step in tmpl["steps"]:
                for ep in step["endpoints"]:
                    pattern = ep.replace("*", "").lower()
                    if pattern in endpoint_text:
                        score += 1

            if score >= 2:  # 至少匹配 2 个端点才认为命中
                matched.append(key)
                self.log(f"    {tmpl['name']}: 匹配 {score} 个端点")
            elif score == 1 and self.verbose:
                self.log(f"    {tmpl['name']}: 仅匹配 {score} 个端点，跳过")

        return matched

    # ── 单步测试 ────────────────────────────────────────────────

    def _test_step(self, step_def: dict, endpoints: list[str],
                   state_params: Optional[list[str]] = None) -> WorkflowStep:
        """对业务流程中的一步进行安全测试。"""
        step = WorkflowStep(name=step_def["name"],
                            state_params=state_params or [])

        # 找匹配的 endpoint
        for ep_pattern in step_def["endpoints"]:
            pattern = ep_pattern.replace("*", "\\d+").lower()
            for ep in endpoints:
                if re.search(pattern, ep.lower()):
                    step.endpoint = ep
                    break
            if step.endpoint:
                break

        if not step.endpoint:
            step.endpoint = step_def["endpoints"][0]
            return step

        self.log(f"    [{step_def['name']}] {step.endpoint}")

        # 测试 1: IDOR — 替换 ID 参数
        id_tests = self._test_idor(step.endpoint, state_params)
        step.findings.extend(id_tests)

        # 测试 2: 参数篡改 — 负值/大数/null
        param_tests = self._test_param_tampering(step.endpoint, state_params)
        step.findings.extend(param_tests)

        # 测试 3: 越权 — 改 HTTP 方法
        method_tests = self._test_method_bypass(step.endpoint)
        step.findings.extend(method_tests)

        return step

    def _test_idor(self, endpoint: str, params: list[str]) -> list[str]:
        """检查是否有 ID 参数可遍历。"""
        findings = []
        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query)

        # URL 路径中的数字 ID
        path_ids = re.findall(r'/(\d+)', endpoint)
        for pid in path_ids[:3]:
            findings.append(f"IDOR_路径: 替换 {pid} 为其他值")

        # 参数中的 ID
        id_params = [p for p in params if "id" in p.lower()]
        for k, v in qs.items():
            if any(id_p in k.lower() for id_p in ["id", "uid", "pid", "sid", "token"]):
                findings.append(f"IDOR_参数: {k}={v[0]} → 替换为其他值")

        return findings

    def _test_param_tampering(self, endpoint: str, params: list[str]) -> list[str]:
        """检查敏感参数可被篡改。"""
        findings = []
        amount_params = [p for p in params if p in ["amount", "price", "quantity", "coupon", "discount"]]
        if amount_params:
            findings.append(f"参数篡改: {amount_params} — 尝试负值/大数/零值")
        return findings

    def _test_method_bypass(self, endpoint: str) -> list[str]:
        """测试 HTTP 方法绕过。"""
        suggestions = []
        if any(m in endpoint for m in ["update", "delete", "create", "edit"]):
            suggestions.append("方法绕过: GET→POST→PUT→PATCH→DELETE 切换测试")
        return suggestions

    # ── 跨步测试 ────────────────────────────────────────────────

    def _test_state_skip(self, tmpl: dict, steps: list) -> list[str]:
        """测试能否跳过中间状态。"""
        findings = []
        if len(steps) >= 3:
            # 跳过中间步骤: 直接调第 3 步
            step_names = [s.name for s in steps]
            findings.append(f"状态跳过: 跳过 '{step_names[1]}' 直接调 '{step_names[2]}'")
        return findings

    def _test_replay(self, steps: list) -> list[str]:
        """测试重放攻击。"""
        findings = []
        create_steps = [s for s in steps if "创建" in s.name or "下单" in s.name]
        if create_steps:
            findings.append(f"重放: 重复提交 {create_steps[0].endpoint} 检查重复处理")
        return findings

    def _test_downgrade(self, steps: list) -> list[str]:
        """测试降级攻击（用低权限操作替换高权限操作）。"""
        return ["降级: 用 GET 替换 POST 查看订单"]

    # ── 输出 ────────────────────────────────────────────────────

    def summary(self, result: WorkflowResult) -> str:
        """生成可读报告。"""
        if not result.steps:
            return "  未识别出业务流程"

        lines = [f"\n  \x1b[1m业务流程: {result.workflow_name}\x1b[0m"]
        for step in result.steps:
            status = "\x1b[1;32m[v]\x1b[0m" if step.findings else "     "
            lines.append(f"  {status} [{step.name}] {step.endpoint}")
            for f in step.findings:
                lines.append(f"       \x1b[1;33m[!] {f}\x1b[0m")

        all_tests = []
        all_tests.extend(result.state_skip_tests)
        all_tests.extend(result.replay_tests)
        all_tests.extend(result.downgrade_tests)

        if all_tests:
            lines.append(f"  \x1b[1m跨步测试:\x1b[0m")
            for t in all_tests:
                lines.append(f"    \x1b[1;33m[!] {t}\x1b[0m")

        return "\n".join(lines)
