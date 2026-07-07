import threading
import http.server
import socket
import struct
import string
import random
import time
import re
import json
import urllib.request
import urllib.error
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from aimy.tools.log_utils import get_logger

logger = get_logger("oob_server")


# ═══════════════════════════════════════════
# P0 修补: interactsh 集成 — 隐藏你的 IP/域名
# ═══════════════════════════════════════════
# 自建 OOB 会暴露你的 IP/域名在目标 DNS/HTTP 日志中。
# interactsh (ProjectDiscovery) 是匿名的公共 OOB 服务 — 目标看到的是
# cxxxxx.interactsh.com，而不是你的 IP。
# 优先级: interactsh > 自建 (interactsh 不可用时)
# ═══════════════════════════════════════════

INTERACTSH_SERVER = "oast.pro"          # 默认 interactsh 服务器
INTERACTSH_POLL_INTERVAL = 5             # 轮询间隔 (秒)
INTERACTSH_TIMEOUT = 10                  # 注册超时 (秒)
INTERACTSH_SESSION_FILE = "/tmp/aimy_interactsh_session.json"


class InteractshClient:
    """interactsh 匿名 OOB 客户端。

    特性:
      - 零痕迹: 目标日志中只出现 *.interactsh.com，不暴露你的 IP
      - 无需注册: 自动生成唯一 correlation-id
      - 支持 DNS/HTTP/SMTP 三种回调
      - 轮询模式: 定时查询 interactsh 服务器获取回调记录
    """

    def __init__(self, server: str = INTERACTSH_SERVER):
        self._server = server
        self._correlation_id = ""
        self._secret = ""
        self._token = ""
        self._domain = ""
        self._registered = False
        self._callbacks: Dict[str, list] = {}

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def url(self) -> str:
        return f"http://{self._domain}" if self._domain else ""

    @property
    def is_available(self) -> bool:
        return self._registered

    def _gen_keys(self) -> tuple:
        """生成随机 correlation-id + secret。"""
        cid = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        secret = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
        return cid, secret

    def register(self, server: str = "") -> bool:
        """向 interactsh 服务器注册，获取唯一子域名。"""
        if server:
            self._server = server

        cid, secret = self._gen_keys()
        payload = json.dumps({
            "correlation-id": cid,
            "secret": secret,
        }).encode()

        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    f"https://{self._server}/register",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=INTERACTSH_TIMEOUT) as resp:
                    data = json.loads(resp.read().decode())
                    self._domain = data.get("domain", "")
                    self._token = data.get("token", "")
                    self._correlation_id = cid
                    self._secret = secret
                    self._registered = bool(self._domain)

                    if self._registered:
                        # 持久化 session (可跨进程复用)
                        try:
                            with open(INTERACTSH_SESSION_FILE, "w") as f:
                                json.dump({
                                    "domain": self._domain,
                                    "correlation_id": cid,
                                    "secret": secret,
                                    "token": self._token,
                                    "server": self._server,
                                }, f)
                        except Exception:
                            pass

                        logger.info(
                            "interactsh 注册成功: %s (server=%s)",
                            self._domain, self._server
                        )
                        return True

            except urllib.error.URLError as e:
                logger.debug("interactsh 注册 attempt %d: %s", attempt + 1, e)
            except Exception as e:
                logger.debug("interactsh 注册异常: %s", e)
            time.sleep(1)

        logger.warning("interactsh 注册失败 (server=%s)，回退到自建 OOB", self._server)
        return False

    def try_restore(self) -> bool:
        """尝试从持久化文件恢复之前的 interactsh session。"""
        try:
            import os
            if os.path.exists(INTERACTSH_SESSION_FILE):
                with open(INTERACTSH_SESSION_FILE) as f:
                    sess = json.load(f)
                # 只恢复 30 分钟内的 session (interactsh 默认 24h 有效)
                if time.time() - os.path.getmtime(INTERACTSH_SESSION_FILE) < 1800:
                    self._domain = sess["domain"]
                    self._correlation_id = sess["correlation_id"]
                    self._secret = sess["secret"]
                    self._token = sess.get("token", "")
                    self._server = sess.get("server", INTERACTSH_SERVER)
                    self._registered = True
                    logger.info("interactsh session 恢复: %s", self._domain)
                    return True
        except Exception:
            pass
        return False

    def poll(self) -> List[dict]:
        """轮询 interactsh 服务器获取回调记录。"""
        if not self._registered:
            return []

        try:
            url = (
                f"https://{self._server}/poll"
                f"?id={self._correlation_id}&secret={self._secret}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=INTERACTSH_POLL_INTERVAL) as resp:
                data = json.loads(resp.read().decode())
                records = data.get("data", []) if isinstance(data, dict) else []
                parsed = []
                for r in records:
                    parsed.append({
                        "type": r.get("protocol-type", "unknown"),
                        "remote_address": r.get("remote-address", ""),
                        "timestamp": r.get("timestamp", ""),
                        "raw_request": r.get("raw-request", ""),
                        "raw_response": r.get("raw-response", ""),
                    })
                return parsed
        except Exception as e:
            logger.debug("interactsh poll: %s", e)
            return []

    def generate_payload(self, cb_type: str = "http") -> str:
        """生成可注入的 OOB payload (隐藏你的 IP)。"""
        if not self._registered:
            return ""
        if cb_type == "dns":
            return f"{self._correlation_id}.{self._domain}"
        elif cb_type == "http":
            return f"http://{self._correlation_id}.{self._domain}"
        elif cb_type == "full":
            # 同时支持 DNS + HTTP
            return f"http://{self._correlation_id}.{self._domain}"
        return self._domain

    def make_dynamic_payload(self, context: str = "") -> str:
        """为每次注入生成唯一的动态 payload。"""
        if not self._registered:
            return ""
        dynamic_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"http://{dynamic_id}.{self._correlation_id}.{self._domain}"


# 全局 interactsh 客户端
_interactsh_client: Optional[InteractshClient] = None


def get_interactsh() -> Optional[InteractshClient]:
    """获取全局 interactsh 客户端 (懒加载)。"""
    global _interactsh_client
    if _interactsh_client is None:
        _interactsh_client = InteractshClient()
        # 先尝试恢复已有 session
        if not _interactsh_client.try_restore():
            # 注册新 session
            _interactsh_client.register()
    return _interactsh_client if _interactsh_client.is_available else None


@dataclass
class CallbackRecord:
    path: str
    headers: Dict[str, str]
    client: tuple
    timestamp: float
    raw_data: Optional[bytes] = None


class OOBServer:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None
        self._dns_sock = None
        self._dns_thread = None
        self._running = False
        self._callbacks: Dict[str, List[CallbackRecord]] = {}
        self._cb_lock = threading.Lock()
        # AIMY stealth: interactsh 优先 (不暴露你的 IP)
        self._interactsh: Optional[InteractshClient] = None
        self._use_interactsh: bool = False

    @classmethod
    def get_instance(cls, host: str = "0.0.0.0", port: int = 0):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    # AIMY stealth: 优先 interactsh (匿名), 自建 OOB 仅作 fallback
                    ish = get_interactsh()
                    if ish is not None:
                        cls._instance = cls(host, port)
                        cls._instance._interactsh = ish
                        cls._instance._use_interactsh = True
                        logger.info("OOB 后端: interactsh (%s) — 目标看不到你的 IP", ish.domain)
                    else:
                        cls._instance = cls(host, port)
                        cls._instance._interactsh = None
                        cls._instance._use_interactsh = False
                        logger.warning(
                            "OOB 后端: 自建 (interactsh 不可用) — "
                            "⚠️ 目标 DNS/HTTP 日志将记录你的出口 IP! 仅用于测试环境!"
                        )
        return cls._instance

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._httpd = http.server.HTTPServer(
                (self.host, self.port), self._make_handler(self)
            )
            self.port = self._httpd.server_address[1]
            self._thread = threading.Thread(
                target=self._httpd.serve_forever, daemon=True
            )
            self._thread.start()
            self._running = True
            logger.info("OOB HTTP listener on 0.0.0.0:%d", self.port)
            return True
        except OSError as e:
            logger.warning("OOB HTTP bind failed: %s", e)
            return False

    def start_dns(self) -> Optional[str]:
        """启动 DNS 监听 (优先 interactsh, 自建仅作 fallback)。

        返回 OOB 域名。interactsh 模式下不绑定本地端口。
        """
        # 优先 interactsh (匿名 DNS 回调)
        ish = getattr(self, '_interactsh', None)
        if ish is not None and ish.is_available:
            logger.info("OOB DNS 后端: interactsh (%s)", ish.domain)
            return ish.domain

        # fallback: 自建 (⚠️ DNS 日志会暴露你的 IP)
        try:
            self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._dns_sock.bind(("0.0.0.0", 0))
            self._dns_sock.settimeout(1.0)
            dns_port = self._dns_sock.getsockname()[1]
            self._dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
            self._dns_thread.start()
            lan_ip = self._get_lan_ip()
            token = "".join(random.choices(string.ascii_lowercase, k=6))
            domain = f"{token}.{lan_ip.replace('.', '-')}.oob"
            logger.warning(
                "OOB DNS 后端: 自建 domain=%s — ⚠️ 目标 DNS 日志将记录你的 IP!", domain
            )
            return domain
        except OSError as e:
            logger.warning("OOB DNS bind failed: %s", e)
            return None

    def _dns_loop(self):
        while self._running:
            try:
                data, addr = self._dns_sock.recvfrom(512)
                domain = self._parse_dns_query(data)
                if domain:
                    with self._cb_lock:
                        self._callbacks.setdefault("dns", []).append(
                            CallbackRecord(
                                path=f"/dns/{domain}",
                                headers={},
                                client=addr,
                                timestamp=time.time(),
                                raw_data=data,
                            )
                        )
            except socket.timeout:
                continue
            except Exception:
                break

    @staticmethod
    def _parse_dns_query(data: bytes) -> Optional[str]:
        try:
            if len(data) < 12:
                return None
            qdcount = struct.unpack("!H", data[4:6])[0]
            if qdcount < 1:
                return None
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                if length & 0xC0:
                    pos += 2
                    break
                pos += 1
                if pos + length > len(data):
                    return None
                labels.append(
                    data[pos : pos + length].decode("ascii", errors="replace")
                )
                pos += length
            return ".".join(labels)
        except Exception:
            return None

    def register_callback_id(self, cb_id: str) -> str:
        """注册回调 ID，返回注入 payload URL。

        优先返回 interactsh URL (匿名), 不可用时返回自建 URL (暴露 IP)。
        """
        with self._cb_lock:
            self._callbacks.setdefault(cb_id, [])

        # 优先 interactsh (不暴露你的 IP)
        ish = getattr(self, '_interactsh', None)
        if ish is not None and ish.is_available:
            return f"http://{cb_id}.{ish.domain}"

        # fallback: 自建 (⚠️ 暴露你的 LAN IP)
        return f"http://{self._get_lan_ip()}:{self.port}/cb/{cb_id}"

    def pop_callbacks(self, cb_id: str) -> List[CallbackRecord]:
        """获取并清空指定回调 ID 的记录 (同时检查 interactsh + 自建)。"""
        records = []
        with self._cb_lock:
            records = self._callbacks.pop(cb_id, [])

        # 同时从 interactsh 轮询
        ish = getattr(self, '_interactsh', None)
        if ish is not None and ish.is_available:
            for raw in ish.poll():
                if cb_id in raw.get("raw_request", "") or cb_id in raw.get("raw_response", ""):
                    records.append(CallbackRecord(
                        path=f"/interactsh/{raw.get('type', 'unknown')}",
                        headers={},
                        client=(raw.get("remote_address", ""), 0),
                        timestamp=time.time(),
                        raw_data=raw.get("raw_request", "").encode() if raw.get("raw_request") else None,
                    ))
        return records

    def has_callback(self, cb_id: str) -> bool:
        """检查是否有指定 cb_id 的回调 (同时检查 interactsh + 自建)。"""
        with self._cb_lock:
            if len(self._callbacks.get(cb_id, [])) > 0:
                return True

        # 同时检查 interactsh
        ish = getattr(self, '_interactsh', None)
        if ish is not None and ish.is_available:
            for raw in ish.poll():
                if cb_id in raw.get("raw_request", "") or cb_id in raw.get("raw_response", ""):
                    return True
        return False

    def stop(self):
        self._running = False
        if self._httpd:
            self._httpd.shutdown()
        if self._dns_sock:
            try:
                self._dns_sock.close()
            except Exception:
                pass

    @staticmethod
    def _get_lan_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def _make_handler(server):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                match = re.match(r"^/cb/([\w-]+)", self.path)
                if match:
                    cb_id = match.group(1)
                    rec = CallbackRecord(
                        path=self.path,
                        headers=dict(self.headers),
                        client=self.client_address,
                        timestamp=time.time(),
                    )
                    with server._cb_lock:
                        server._callbacks.setdefault(cb_id, []).append(rec)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        return Handler
