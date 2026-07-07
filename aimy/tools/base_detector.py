"""
BaseDetector — 所有漏洞检测器的基类。

强制基线对比，防止认证墙误报。
子类只需覆写 _check_impl()，基线由模板方法自动建立。

Usage:
    class MyDetector(BaseDetector):
        def _check_impl(self, url, param, **kwargs):
            r = self.sess.get(url, params={param: payload})
            if indicator in r.text and not self.is_false_positive(indicator, r):
                return {"vulnerable": True, ...}
            return {"vulnerable": False, ...}

    # Backward-compatible module-level API
    def check(url, param, sess=None, timeout=10.0, **kwargs):
        return MyDetector().check(url, param, sess=sess, timeout=timeout, **kwargs)
"""

from typing import Optional
import hashlib
import time
import requests

from aimy.tools.http_client import build_url
from aimy.tools.log_utils import get_logger
from aimy.tools.settings import settings

logger = get_logger("base_detector")


class BaseDetector:
    """Template-method base class for vulnerability detectors.

    Lifecycle:
        1. check()          — template method (DO NOT override)
        2. _setup_session() — initialize HTTP session
        3. _build_baseline()— send neutral probe to establish normal response
        4. _check_impl()    — subclass detection logic (MUST override)
    """

    def __init__(self):
        self.sess: Optional[requests.Session] = None
        self._baseline_text: str = ""
        self._baseline_size: int = 0
        self._baseline_hash: int = 0

    # ── Template Method ────────────────────────────────────────

    def __init__(self):
        super().__init__()
        # 遥测：自动记录检测结果到 FeedbackCollector
        self._detector_name: str = self.__class__.__name__

    def check(self, url: str, param: str,
              sess: Optional[requests.Session] = None,
              timeout: float = 10.0,
              **kwargs) -> dict:
        """Template method.

        Establishes baseline, then delegates to subclass.
        Returns: {"vulnerable": bool, "type": str|None, "evidence": list, ...}
        """
        self._setup_session(sess)
        self._build_baseline(url, param, timeout, **kwargs)
        result = self._check_impl(url, param, timeout=timeout, **kwargs)
        self._record_telemetry(url, param, result)
        return result

    # ── Telemetry Hook ───────────────────────────────────────────

    def _record_telemetry(self, url: str, param: str, result: dict) -> None:
        """自动记录检测结果到反馈收集器（子体→本体数据回流）"""
        try:
            from aimy.telemetry.collector import get_collector, TestResult
            from aimy.telemetry.anonymizer import Anonymizer

            collector = get_collector()
            if not collector.enabled:
                return

            domain, endpoint = Anonymizer.anonymize_url(url)
            vuln_type = str(result.get("type") or result.get("vuln_type") or "unknown")
            payload_raw = str(result.get("payload", "") or result.get("evidence", ""))

            tr = TestResult(
                vuln_type=vuln_type,
                target_domain=domain,
                target_endpoint=endpoint,
                http_method="GET",
                found=bool(result.get("vulnerable", False)),
                confidence=float(result.get("confidence", 0.0)),
                severity=str(result.get("severity", "")),
                skill_used="",
                tool_used=self._detector_name,
                payload_hash=hashlib.sha256(payload_raw.encode()).hexdigest()[:16] if payload_raw else "",
                payload_category=param,
                requests_sent=1,
            )
            collector.record(tr)
        except Exception:
            pass  # 遥测失败不能影响检测主线

    # ── Internal ────────────────────────────────────────────────

    def _setup_session(self, sess: Optional[requests.Session]) -> None:
        if sess is not None:
            self.sess = sess
        else:
            self.sess = requests.Session()
            self.sess.verify = settings.verify_ssl

    def _build_baseline(self, url: str, param: str, timeout: float,
                        **kwargs) -> None:
        """Send a neutral request to establish the normal response pattern.

        This is the anchor against which all subsequent responses are compared.
        If the target has an auth wall, the baseline will be the login page.
        """
        try:
            r = self.sess.get(
                build_url(url, param, "1"),
                timeout=timeout
            )
            self._baseline_text = r.text
            self._baseline_size = len(r.text)
            self._baseline_hash = hash(r.text[:200])
            logger.debug("baseline: size=%d hash=%d", self._baseline_size, self._baseline_hash)
        except Exception as e:
            logger.debug("baseline failed: %s", e)
            self._baseline_text = ""
            self._baseline_size = 0
            self._baseline_hash = 0

    # ── Public API for Subclasses ───────────────────────────────

    def is_false_positive(self,
                          indicator: Optional[str] = None,
                          response: Optional[requests.Response] = None,
                          response_text: Optional[str] = None,
                          skip_size_check: bool = False) -> bool:
        """Check if response matches baseline (auth wall / login page).

        Args:
            indicator: The string (error pattern, payload, marker)
            response: A requests.Response object.
            response_text: Raw response text.
            skip_size_check: If True, skip size comparison.
                            Use for XSS/injection where the page
                            structure is identical but payload IS
                            reflected inline.

        Returns:
            True  → skip this finding (auth wall / false positive)
            False → genuine deviation from baseline
        """
        text = response_text or (response.text if response is not None else "")
        if not text:
            return False

        # Gate 1: Same size (±50 bytes) = same page = auth wall
        # Skip for XSS/injection where payload reflected without structure change
        if not skip_size_check:
            if self._baseline_size and abs(len(text) - self._baseline_size) < 50:
                return True

        # Gate 2: Indicator already existed in the baseline
        if indicator and self._baseline_text and indicator in self._baseline_text:
            return True

        return False

    # ── Subclass Interface ─────────────────────────────────────

    def _check_impl(self, url: str, param: str, **kwargs) -> dict:
        """Override with detection logic.

        The baseline is already established when this runs.
        Use self.is_false_positive() to guard every vulnerability determination.
        Use self.sess for HTTP requests.
        """
        raise NotImplementedError(
            "Subclass must implement _check_impl(url, param, **kwargs)"
        )
