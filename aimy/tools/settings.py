import os
import time
from pathlib import Path
from typing import Optional, Set


class _Settings:
    MODES = {"rookie", "veteran"}

    def __init__(self):
        # ── SSL ──
        # 修补: 默认开启 SSL 验证 (原默认关闭为安全风险)
        self.verify_ssl = os.environ.get("AIMY_VERIFY_SSL", "1").lower() in ("1", "true", "yes")

        # ── 场景模式 ──
        # 三场景: bounty / pentest / redteam
        # 两子模式: rookie (详细输出) / veteran (简洁输出)
        self._scene = os.environ.get("AIMY_SCENE", "bounty").lower()
        self._scene_profile: dict = {}

        # ── 旧模式保留兼容 ──
        self.mode = os.environ.get("AIMY_MODE", "veteran").lower()
        if self.mode not in self.MODES:
            self.mode = "veteran"

        # ═══════════════════════════════════════════
        # 安全约束 (P0 修补新增)
        # 所有参数可通过环境变量覆盖，但不可低于硬上限
        # ═══════════════════════════════════════════

        # ═══════════════════════════════════════════
        # Safety Gate: 只读模式 (P1 新增 2026-07-01)
        # 默认开启 — 写操作 payload 被净化，PUT/PATCH/DELETE 拦截
        # ═══════════════════════════════════════════
        self.read_only: bool = os.environ.get("AIMY_READ_ONLY", "1").lower() in ("1", "true", "yes")

        # ── 速率控制 ──
        self.rate_limit: float = float(os.environ.get("AIMY_RATE", "1.0"))        # req/s, Iron Rule: ≤1
        self.rate_limit = max(0.2, min(self.rate_limit, 1.0))                    # 硬夹: [0.2, 1.0]

        # ── 并发控制 ──
        self.max_concurrency: int = int(os.environ.get("AIMY_MAX_CONCUR", "3"))   # Iron Rule: ≤5
        self.max_concurrency = max(1, min(self.max_concurrency, 5))               # 硬夹: [1, 5]

        # ── 日配额 ──
        self.max_requests_per_day: int = int(os.environ.get("AIMY_DAILY_MAX", "500"))  # Iron Rule: 500

        # ── Scope ──
        self.scope_file: str = os.environ.get("AIMY_SCOPE_FILE", "")
        self.require_confirm: bool = os.environ.get("AIMY_REQUIRE_CONFIRM", "1").lower() in ("1", "true", "yes")

        # ── 数据提取上限 (Iron Rule: 验证即停, ≤3条) ──
        self.max_data_rows: int = int(os.environ.get("AIMY_MAX_ROWS", "3"))
        self.max_data_rows = max(1, min(self.max_data_rows, 20))                  # 硬夹: [1, 20]
        self.max_file_read_lines: int = int(os.environ.get("AIMY_MAX_FILE_LINES", "10"))

        # ── 熔断 ──
        self.fuse_429_seconds: int = int(os.environ.get("AIMY_FUSE_429", "300"))   # 429→5min
        self.fuse_503_seconds: int = int(os.environ.get("AIMY_FUSE_503", "600"))   # 503→10min
        self.fuse_consecutive_timeouts: int = int(os.environ.get("AIMY_FUSE_TIMEOUTS", "3"))  # 连续超时→跳过

        # ═══════════════════════════════════════════
        # 运行时计数器
        # ═══════════════════════════════════════════
        self._request_count_today: int = 0
        self._last_request_time: float = 0.0
        self._active_requests: int = 0
        self._scope_domains: Set[str] = set()
        self._scope_loaded: bool = False

    # ── 模式 ──
    def set_mode(self, mode: str):
        mode = mode.lower()
        if mode in self.MODES:
            self.mode = mode

    def is_rookie(self) -> bool:
        return self.mode == "rookie"

    def is_veteran(self) -> bool:
        return self.mode == "veteran"

    # ═══════════════════════════════════════════
    # Scope 管理 (P0 新增)
    # ═══════════════════════════════════════════

    def load_scope(self) -> Set[str]:
        """从 scope 文件加载授权域名白名单。每行一个域名，# 开头为注释。"""
        if self._scope_loaded:
            return self._scope_domains
        self._scope_loaded = True

        if not self.scope_file or not Path(self.scope_file).exists():
            return self._scope_domains  # 空集合 — 后续调用 is_in_scope 会警告

        try:
            with open(self.scope_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # 去掉协议和路径，只保留 hostname
                        if "://" in line:
                            from urllib.parse import urlparse
                            line = urlparse(line).hostname or line
                        self._scope_domains.add(line)
        except Exception:
            pass
        return self._scope_domains

    def is_in_scope(self, url: str) -> bool:
        """
        校验 URL 是否在授权范围内。
        返回 True = 在 scope 内或 scope 未配置（允许但警告）。
        返回 False = 明确不在 scope 内。
        """
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return False

        self.load_scope()

        if not self._scope_domains:
            # 无 scope 文件 — 允许但调用方应警告
            return True

        for domain in self._scope_domains:
            if hostname == domain or hostname.endswith("." + domain):
                return True
        return False

    def require_scope_or_raise(self, url: str):
        """如果 URL 不在 scope 内，抛出 PermissionError。"""
        if not self.is_in_scope(url):
            raise PermissionError(
                f"[SCOPE] {url} 不在授权范围内。已加载 {len(self._scope_domains)} 个授权域名。"
            )

    # ═══════════════════════════════════════════
    # 并发槽位管理 (P0 新增)
    # ═══════════════════════════════════════════

    def acquire_slot(self) -> bool:
        """获取并发槽位。超限返回 False。"""
        if self._active_requests >= self.max_concurrency:
            return False
        self._active_requests += 1
        return True

    def release_slot(self):
        """释放并发槽位。"""
        self._active_requests = max(0, self._active_requests - 1)

    @property
    def active_requests(self) -> int:
        return self._active_requests

    # ═══════════════════════════════════════════
    # 日配额 (P0 新增)
    # ═══════════════════════════════════════════

    def check_daily_quota(self) -> bool:
        """检查是否还有日配额。返回 True = 还有额度。"""
        return self._request_count_today < self.max_requests_per_day

    def quota_remaining(self) -> int:
        """返回剩余日配额。"""
        return max(0, self.max_requests_per_day - self._request_count_today)

    # ═══════════════════════════════════════════
    # 请求记录 (P0 新增)
    # ═══════════════════════════════════════════

    def record_request(self):
        """记录一次请求。"""
        self._request_count_today += 1
        self._last_request_time = time.time()

    @property
    def last_request_time(self) -> float:
        return self._last_request_time

    @property
    def request_count_today(self) -> int:
        return self._request_count_today

    def reset_daily_counters(self):
        """重置日计数器（跨天时调用）。"""
        self._request_count_today = 0

    def __repr__(self):
        return (
            f"<Settings mode={self.mode} ssl={self.verify_ssl} "
            f"rate={self.rate_limit}/s concur≤{self.max_concurrency} "
            f"daily≤{self.max_requests_per_day} rows≤{self.max_data_rows} "
            f"scope={'set' if self._scope_domains else 'none'}>"
        )


# 全局单例
settings = _Settings()

# ══════════════════════════════════════════════════════════════════
# Safety Gate 自动安装钩子
# settings 是所有工具模块的第一导入，在此处自动安装 monkey-patch
# 确保任何 requests.Session() 使用都受只读模式保护
# ══════════════════════════════════════════════════════════════════
if settings.read_only:
    try:
        from aimy.tools.safety_gate import install_hook, enable
        enable()
        install_hook()
    except ImportError:
        pass  # safety_gate.py 尚未创建时静默跳过
