"""
MCP 统一状态管理 — Burp + Fiddler + Playwright + AIMY 跨工具上下文传递。

解决 MCP 层缺少统一状态管理的问题:
    ✓ Burp 发现 JWT → Playwright 自动做 session 劫持验证
    ✓ Playwright 登录成功 → cookies 注入 Burp Scanner session rule
    ✓ Fiddler 截获请求 → Burp Repeater 自动导入
    ✓ AIMY 扫描发现 → Burp Sitemap 自动添加 issue

核心设计:
    SessionStore — 共享 session 状态 (cookies, tokens, auth headers)
    EventBus — 跨工具事件总线 (pub/sub 模式)
    ContextBridge — 高层 API，封装常用跨工具工作流

用法:
    from aimy.tools.mcp_bridge import bridge

    # Burp 发现 JWT → Playwright 验证
    bridge.on_jwt_found(token="eyJ...", url="https://target.com/api")

    # Playwright 登录成功 → Burp 注入 session
    bridge.on_login_success(cookies={"session": "abc123"}, url="https://target.com")

    # Fiddler 截获请求 → Burp Repeater
    bridge.on_request_captured(request_raw, url="https://target.com/api/user")

    # 消费待处理事件
    for event in bridge.pending_events:
        dispatch(event)

版本: 1.0.0
"""

from __future__ import annotations

import json
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from aimy.tools.schemas import (
    MCPBridgeEvent, MCPSource, FindingSchema, AssetSchema, Severity
)
from aimy.tools.log_utils import get_logger

logger = get_logger("mcp_bridge")

VERSION = "1.0.0"
MAX_EVENT_HISTORY = 1000


# ── Session Store ──────────────────────────────────────────────────────────


@dataclass
class SessionState:
    """跨工具共享的 session 状态"""
    session_id: str
    url: str
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)  # {"jwt": "...", "csrf": "...", "api_key": "..."}
    roles: List[str] = field(default_factory=list)  # ["admin", "user", "anonymous"]
    created_at: float = field(default_factory=time.time)
    source: MCPSource = MCPSource.AIMY


@dataclass
class SharedContext:
    """全局共享上下文 — 跨工具可访问的状态快照

    包含:
        - 当前目标 URL
        - 活跃 session (按角色分层)
        - 已发现资产列表
        - 已验证漏洞列表
        - 侦察摘要
    """
    target_url: Optional[str] = None
    target_domain: Optional[str] = None
    sessions: Dict[str, SessionState] = field(default_factory=dict)
    assets: List[AssetSchema] = field(default_factory=list)
    findings: List[FindingSchema] = field(default_factory=list)
    recon_summary: Dict[str, Any] = field(default_factory=dict)
    tech_stack: List[str] = field(default_factory=list)
    waf_type: Optional[str] = None
    scope_domains: List[str] = field(default_factory=list)

    # 跨工具引用
    burp_task_ids: List[str] = field(default_factory=list)
    playwright_browser_active: bool = False
    fiddler_capturing: bool = False

    def get_session_by_role(self, role: str) -> Optional[SessionState]:
        for s in self.sessions.values():
            if role in s.roles:
                return s
        return None

    def get_admin_session(self) -> Optional[SessionState]:
        return self.get_session_by_role("admin")

    def get_user_session(self) -> Optional[SessionState]:
        return self.get_session_by_role("user")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_domain": self.target_domain,
            "sessions": {k: {"url": v.url, "roles": v.roles, "has_auth": bool(v.cookies or v.auth_headers)}
                         for k, v in self.sessions.items()},
            "asset_count": len(self.assets),
            "finding_count": len(self.findings),
            "tech_stack": self.tech_stack,
            "waf_type": self.waf_type,
            "scope_domains": self.scope_domains,
        }

    def summary(self) -> str:
        crit = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        return (
            f"SharedContext({self.target_domain or '?'}): "
            f"{len(self.assets)} assets, {len(self.findings)} findings "
            f"({crit}C/{high}H), {len(self.sessions)} sessions"
        )


# ── Event Bus ──────────────────────────────────────────────────────────────


class EventBus:
    """跨工具事件总线 — pub/sub 模式。

    每个 MCP 工具可以:
        1. subscribe(event_type, callback) — 订阅感兴趣的事件
        2. publish(event) — 发布事件
        3. poll() — 拉取待处理事件

    预定义工作流:
        jwt_found → verify_session_hijack (Playwright)
        session_captured → set_scanner_session (Burp)
        request_trapped → send_to_repeater (Burp)
        finding_ready → add_to_sitemap (Burp)
        auth_success → inject_cookies (所有工具)
        recon_complete → start_hunt (AIMY)
    """

    def __init__(self):
        self._subscriptions: Dict[str, List[Callable[[MCPBridgeEvent], None]]] = {}
        self._events: deque[MCPBridgeEvent] = deque(maxlen=MAX_EVENT_HISTORY)
        self._processed: Set[str] = set()

    def subscribe(self, event_type: str, callback: Callable[[MCPBridgeEvent], None]):
        if event_type not in self._subscriptions:
            self._subscriptions[event_type] = []
        self._subscriptions[event_type].append(callback)
        logger.debug("EventBus: subscribed to %s (total: %d)", event_type,
                     len(self._subscriptions[event_type]))

    def unsubscribe(self, event_type: str, callback: Callable[[MCPBridgeEvent], None]):
        if event_type in self._subscriptions:
            self._subscriptions[event_type].remove(callback)

    def publish(self, event: MCPBridgeEvent):
        self._events.append(event)
        logger.debug("EventBus: published %s from %s → %s",
                     event.event_type, event.source.value,
                     event.target_tool.value if event.target_tool else "broadcast")

        # 异步通知订阅者
        if event.event_type in self._subscriptions:
            for cb in self._subscriptions[event.event_type]:
                try:
                    cb(event)
                except Exception as e:
                    logger.warning("EventBus: callback error for %s: %s", event.event_type, e)

    @property
    def pending_events(self) -> List[MCPBridgeEvent]:
        """待处理事件 (未被标记为 processed)"""
        return [e for e in self._events if e.id not in self._processed]

    def mark_processed(self, event_id: str):
        self._processed.add(event_id)

    def pop_pending(self) -> Optional[MCPBridgeEvent]:
        """取出最早的一个未处理事件"""
        for e in self._events:
            if e.id not in self._processed:
                self._processed.add(e.id)
                return e
        return None

    def find_by_type(self, event_type: str, limit: int = 10) -> List[MCPBridgeEvent]:
        return [e for e in self._events if e.event_type == event_type][-limit:]

    def stats(self) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        for e in self._events:
            type_counts[e.event_type] = type_counts.get(e.event_type, 0) + 1
        return {
            "total_events": len(self._events),
            "pending": len(self.pending_events),
            "by_type": type_counts,
            "subscriptions": {k: len(v) for k, v in self._subscriptions.items()},
        }


# ── Context Bridge (高层 API) ──────────────────────────────────────────────


class ContextBridge:
    """跨 MCP 工具的高层桥接 API。

    封装了最常见的跨工具工作流，一行调用即可完成上下文传递。
    """

    def __init__(self):
        self.shared = SharedContext()
        self.bus = EventBus()
        self._auto_routing = True  # 自动路由事件到目标工具

    # ── 工作流 1: Burp JWT → Playwright session 劫持验证 ────────────────

    def on_jwt_found(self, token: str, url: str, source: MCPSource = MCPSource.BURP):
        """Burp 发现 JWT → 自动发布事件给 Playwright 做验证"""
        event = MCPBridgeEvent.jwt_found(token, url, source)
        self.shared.sessions[f"jwt_{event.id}"] = SessionState(
            session_id=event.id, url=url, tokens={"jwt": token}
        )
        self.bus.publish(event)
        logger.info("Bridge: JWT found → routing to Playwright for session hijack verification")
        return event

    # ── 工作流 2: Playwright 登录 → Burp Scanner session ─────────────────

    def on_login_success(self, cookies: Dict[str, str], url: str,
                         role: str = "user", auth_header: str = None):
        """Playwright 登录成功 → cookies 注入 Burp Scanner"""
        event = MCPBridgeEvent.session_captured(cookies, url)
        session = SessionState(
            session_id=event.id, url=url, cookies=cookies,
            roles=[role],
        )
        if auth_header:
            session.auth_headers["Authorization"] = auth_header
        self.shared.sessions[event.id] = session
        self.bus.publish(event)
        logger.info("Bridge: Session captured (role=%s) → routing to Burp Scanner", role)
        return event

    # ── 工作流 3: Fiddler 截获 → Burp Repeater ───────────────────────────

    def on_request_captured(self, request_raw: str, url: str,
                            method: str = "GET", interesting: bool = False):
        """Fiddler 截获请求 → Burp Repeater"""
        event = MCPBridgeEvent.request_trapped(request_raw, url)
        if interesting:
            event.data["interesting"] = True
            event.data["method"] = method
        self.bus.publish(event)
        if interesting:
            logger.info("Bridge: Interesting request captured → routing to Burp Repeater")
        return event

    # ── 工作流 4: AIMY 发现 → Burp Sitemap ───────────────────────────────

    def on_finding_discovered(self, finding: FindingSchema):
        """AIMY 扫描发现漏洞 → 添加到 Burp Sitemap"""
        event = MCPBridgeEvent.finding_ready(finding)
        self.shared.findings.append(finding)
        self.bus.publish(event)
        logger.info("Bridge: Finding [%s] %s → routing to Burp Sitemap",
                    finding.severity.value, finding.title[:50])
        return event

    # ── 工作流 5: 侦察完成 → 自动进入 Hunt ──────────────────────────────

    def on_recon_complete(self, summary: Dict[str, Any]):
        """六维侦察完成 → 触发 Hunt 阶段"""
        event = MCPBridgeEvent(
            source=MCPSource.AIMY,
            event_type="recon_complete",
            data={"summary": summary, "action": "start_hunt"},
        )
        self.shared.recon_summary = summary
        self.shared.assets.extend(summary.get("assets", []))
        self.bus.publish(event)
        logger.info("Bridge: Recon complete (%s) → triggering Hunt phase",
                    summary.get("stats", "?"))
        return event

    # ── 工作流 6: 双 session IDOR 检测 ────────────────────────────────────

    def on_dual_session_ready(self, admin_session: Dict[str, str],
                              user_session: Dict[str, str], url: str):
        """双 session 准备就绪 → 触发 IDOR 扫描"""
        admin_s = SessionState(
            session_id=uuid.uuid4().hex[:8], url=url,
            cookies=admin_session, roles=["admin"]
        )
        user_s = SessionState(
            session_id=uuid.uuid4().hex[:8], url=url,
            cookies=user_session, roles=["user"]
        )
        self.shared.sessions[admin_s.session_id] = admin_s
        self.shared.sessions[user_s.session_id] = user_s

        event = MCPBridgeEvent(
            source=MCPSource.AIMY,
            event_type="dual_session_ready",
            target_url=url,
            target_tool=MCPSource.BURP,
            data={
                "admin_session_id": admin_s.session_id,
                "user_session_id": user_s.session_id,
                "action": "run_idor_scan",
            },
        )
        self.bus.publish(event)
        logger.info("Bridge: Dual sessions ready → triggering IDOR scan")
        return event

    # ── 查询 API ──────────────────────────────────────────────────────────

    @property
    def pending_events(self) -> List[MCPBridgeEvent]:
        return self.bus.pending_events

    def consume_events(self, n: int = 10) -> List[MCPBridgeEvent]:
        """消费 N 个事件并标记为已处理"""
        consumed = []
        for _ in range(n):
            e = self.bus.pop_pending()
            if e is None:
                break
            consumed.append(e)
        return consumed

    def stats(self) -> Dict[str, Any]:
        return {
            "bridge_version": VERSION,
            "event_bus": self.bus.stats(),
            "shared_context": self.shared.to_dict(),
            "auto_routing": self._auto_routing,
        }

    def print_dashboard(self):
        """打印跨工具桥接仪表盘"""
        s = self.shared
        b = self.bus

        crit = sum(1 for f in s.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in s.findings if f.severity == Severity.HIGH)
        med = sum(1 for f in s.findings if f.severity == Severity.MEDIUM)

        lines = [
            "+" + "-" * 58 + "+",
            f"|  [MCP] Bridge Dashboard{' ' * 35}|",
            "+" + "-" * 58 + "+",
            f"|  Target:  {s.target_url or '(not set)'}{' ' * (44 - max(0, len(s.target_url or '')))}|",
            f"|  Tech:    {', '.join(s.tech_stack) or '(unknown)'}{' ' * (42 - max(0, len(', '.join(s.tech_stack))))}|",
            f"|  WAF:     {s.waf_type or '(none detected)'}{' ' * 39}|",
            "+" + "-" * 58 + "+",
            f"|  Sessions: {len(s.sessions)}  |  Assets: {len(s.assets):>4}  |  Findings: {len(s.findings):>3}     |",
            f"|  Critical: {crit:>2} |  High: {high:>4} |  Medium: {med:>4} {' ' * 20}|",
            "+" + "-" * 58 + "+",
            f"|  Events: {b.stats()['total_events']:>5}  |  Pending: {b.stats()['pending']:>3} {' ' * 26}|",
            f"|  Burp: {'ON ' if s.burp_task_ids else 'off':<4} Fiddler: {'ON ' if s.fiddler_capturing else 'off':<4} Playwright: {'ON ' if s.playwright_browser_active else 'off':<4} {' ' * 17}|",
            "+" + "-" * 58 + "+",
        ]
        print("\n".join(lines))


# ── 全局单例 ──────────────────────────────────────────────────────────────

bridge = ContextBridge()


# ── CLI ────────────────────────────────────────────────────────────────────


def main():
    import argparse
    parser = argparse.ArgumentParser(description="MCP Bridge — 跨工具状态管理")
    sub = parser.add_subparsers(dest="cmd")

    # dashboard
    sub.add_parser("dashboard", help="显示跨工具桥接仪表盘")

    # stats
    sub.add_parser("stats", help="显示事件总线和共享上下文统计")

    # jwt
    jwt_p = sub.add_parser("jwt", help="模拟 Burp 发现 JWT")
    jwt_p.add_argument("--token", required=True)
    jwt_p.add_argument("--url", required=True)

    # login
    login_p = sub.add_parser("login", help="模拟 Playwright 登录成功")
    login_p.add_argument("--cookies", required=True, help="JSON: {\"session\":\"abc\"}")
    login_p.add_argument("--url", required=True)
    login_p.add_argument("--role", default="user")

    # consume
    consume_p = sub.add_parser("consume", help="消费待处理事件")
    consume_p.add_argument("-n", type=int, default=10)

    args = parser.parse_args()

    if args.cmd == "dashboard":
        bridge.print_dashboard()
    elif args.cmd == "stats":
        print(json.dumps(bridge.stats(), ensure_ascii=False, indent=2))
    elif args.cmd == "jwt":
        bridge.on_jwt_found(args.token, args.url)
        print(f"✓ JWT event published → {[e.event_type for e in bridge.pending_events]}")
    elif args.cmd == "login":
        cookies = json.loads(args.cookies)
        bridge.on_login_success(cookies, args.url, args.role)
        print(f"✓ Login event published (role={args.role})")
    elif args.cmd == "consume":
        events = bridge.consume_events(args.n)
        print(f"✓ Consumed {len(events)} events:")
        for e in events:
            print(f"  [{e.source.value}] {e.event_type} → {e.target_tool.value if e.target_tool else 'broadcast'}")
    else:
        bridge.print_dashboard()


if __name__ == "__main__":
    main()
