"""Safety guard — rate limiter + circuit breaker."""

from __future__ import annotations

import time


class RateLimiter:
    """Token-bucket rate limiter for outbound requests."""

    def __init__(self, requests_per_second: float = 1.0, max_burst: int = 5):
        self.rate = requests_per_second
        self.max_burst = max_burst
        self._tokens = float(max_burst)
        self._last_refill = time.time()

    def acquire(self) -> bool:
        """Try to acquire a token. Returns True if allowed, False if rate-limited."""
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(self.max_burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def wait_and_acquire(self, timeout: float = 10.0) -> bool:
        """Block until a token is available or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.acquire():
                return True
            time.sleep(0.1)
        return False


class CircuitBreaker:
    """Circuit breaker: opens after N consecutive failures, auto-resets."""

    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 300.0):
        self.threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._last_failure = 0.0
        self._open = False

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (requests should be blocked)."""
        if self._open:
            if time.time() - self._last_failure > self.reset_timeout:
                # Auto-reset
                self._open = False
                self._failures = 0
            else:
                return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._open = False

    def record_failure(self) -> None:
        self._failures += 1
        self._last_failure = time.time()
        if self._failures >= self.threshold:
            self._open = True


class SafetyGuard:
    """Combined safety gate: rate limiter + circuit breaker + scope check."""

    def __init__(self, requests_per_second: float = 1.0,
                 scope_file: str = ""):
        self.rate_limiter = RateLimiter(requests_per_second)
        self.circuit_breaker = CircuitBreaker()
        from aimy.safety.scope import ScopeChecker
        self.scope_checker = ScopeChecker(scope_file)

    def check_request(self, url: str) -> tuple[bool, str]:
        """Check if a request to URL is allowed.

        Returns: (allowed, reason)
        """
        if self.circuit_breaker.is_open:
            return False, "Circuit breaker open — too many failures"

        if not self.scope_checker.is_in_scope(url):
            return False, f"URL not in scope: {url}"

        if not self.rate_limiter.acquire():
            return False, "Rate limited — too many requests"

        return True, "ok"

    def record_result(self, success: bool) -> None:
        """Record the result of a request."""
        if success:
            self.circuit_breaker.record_success()
        else:
            self.circuit_breaker.record_failure()
