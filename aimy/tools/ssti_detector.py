import re, time
from typing import Optional
import requests

from aimy.tools.log_utils import get_logger
from aimy.tools.http_client import build_url
from aimy.tools.payload_engine import generate
from aimy.tools.settings import settings
from aimy.tools.base_detector import BaseDetector

logger = get_logger("ssti_detector")

TEMPLATE_ENGINE_FINGERPRINTS = {
    "jinja2": [r"\{\{999999\*999999\}\}", r"\{\{config\}\}"],
    "twig": [r"\{\{999999\*999999\}\}", r"\$\{999999\*999999\}"],
    "freemarker": [r"\$\{999999\*999999\}"],
    "velocity": [r"\$\{999999\*999999\}"],
    "smarty": [r"\{999999\*999999\}"],
    "handlebars": [r"\{\{999999\*999999\}\}"],
    "mustache": [r"\{\{999999\*999999\}\}"],
    "mako": [r"\$\{999999\*999999\}"],
    "tornado": [r"\{\{999999\*999999\}\}"],
    "django": [r"\{\{999999\*999999\}\}"],
    "angular": [r"\{\{999999\*999999\}\}"],
}


def _measure_time_baseline(url, param, sess, timeout):
    """Timing baseline — separate from content baseline in BaseDetector."""
    samples = []
    for _ in range(2):
        try:
            start = time.time()
            sess.get(build_url(url, param, "NOMINAL_TEST"), timeout=timeout)
            samples.append(time.time() - start)
        except Exception:
            pass
    return sum(samples) / len(samples) if samples else 0.3


class SSTIDetector(BaseDetector):
    """SSTI detection — inherits baseline from BaseDetector."""

    def _check_impl(self, url: str, param: str, **kwargs) -> dict:
        timeout = kwargs.get("timeout", 10.0)
        waf_name = kwargs.get("waf_name")
        result = {"vulnerable": False, "engine": None, "evidence": [],
                  "payload": None, "rce_available": False}

        context = "numeric" if param.lower() in ("id", "uid", "pid", "page") else "string"

        # Phase 1: Indicator-based detection (guarded by baseline)
        seeds = generate("ssti", "detect", "all", waf_name)
        for entry in seeds:
            payload = entry["payload"]
            indicator = entry["indicator"]
            try:
                r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                if indicator in r.text and not self.is_false_positive(indicator, r):
                    result["vulnerable"] = True
                    result["evidence"].append("ssti: %s => %s" % (payload[:25], indicator))
                    result["payload"] = payload
                    for engine, patterns in TEMPLATE_ENGINE_FINGERPRINTS.items():
                        for pat in patterns:
                            if re.search(pat, r.text):
                                result["engine"] = engine
                                break
                    break
            except Exception as e:
                logger.debug("ssti payload %s: %s", payload[:20], e)

        # Phase 2: Alternative payloads
        if not result["vulnerable"] and context == "string":
            alt_pairs = [
                ('{{"a".toUpperCase()}}', "A", "javascript"),
                ('{{"a".upper()}}', "A", "python"),
                ('${"a".toUpperCase()}', "A", "java"),
                ('#{7+7}', "14", "java"),
            ]
            for payload, indicator, engine_hint in alt_pairs:
                try:
                    r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                    if indicator in r.text and not self.is_false_positive(indicator, r):
                        result["vulnerable"] = True
                        result["evidence"].append(
                            "ssti: %s => %s (engine=%s)" % (payload[:25], indicator, engine_hint))
                        result["payload"] = payload
                        result["engine"] = engine_hint
                        break
                except Exception as e:
                    logger.debug("ssti alt %s: %s", payload[:20], e)

        # Phase 3: Time-based detection
        if not result["vulnerable"]:
            baseline = _measure_time_baseline(url, param, self.sess, timeout)
            if baseline < timeout * 0.8:
                threshold = max(2.0, baseline * 1.5 + 1.5)
                time_payloads = [
                    "{{ ''.__class__.__mro__[1].__subclasses__() and sleep(3) }}",
                    "{% if 1==1 %}{% endif %}",
                ]
                for payload in time_payloads:
                    try:
                        start = time.time()
                        self.sess.get(build_url(url, param, payload), timeout=timeout + 3)
                        if time.time() - start >= threshold:
                            result["vulnerable"] = True
                            result["evidence"].append("ssti: time-based anomaly detected")
                            result["payload"] = payload
                            break
                    except requests.Timeout:
                        pass
                    except Exception:
                        continue

        # Phase 4: Blind RCE probe
        if result.get("vulnerable"):
            blind_seeds = generate("ssti", "blind", "all", waf_name)
            for entry in blind_seeds:
                payload = entry["payload"]
                indicator = entry["indicator"]
                try:
                    r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                    if indicator in r.text:
                        result["rce_available"] = True
                        result["evidence"].append("ssti rce: %s" % payload[:30])
                        break
                except Exception as e:
                    logger.debug("ssti blind %s: %s", payload[:20], e)

        return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    """Backward-compatible module-level API."""
    return SSTIDetector().check(url, param, sess=sess, timeout=timeout,
                                waf_name=waf_name)
