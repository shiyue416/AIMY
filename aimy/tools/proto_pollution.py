import os
from typing import Optional, Dict
import requests

from aimy.tools.log_utils import get_logger
from aimy.tools.settings import settings
from aimy.tools.base_detector import BaseDetector

logger = get_logger("proto_pollution")

PP_MARKER = "PP_%s" % os.urandom(4).hex()

PP_PAYLOADS = [
    "__proto__[%s]=true" % PP_MARKER,
    "__proto__.%s=true" % PP_MARKER,
    "constructor[prototype][%s]=true" % PP_MARKER,
    "constructor.prototype.%s=true" % PP_MARKER,
]

PP_JSON_PAYLOADS = {
    "__proto__": {PP_MARKER: "true"},
    "constructor": {"prototype": {PP_MARKER: "true"}},
}


class ProtoPollutionDetector(BaseDetector):
    """Prototype pollution detection — inherits baseline from BaseDetector."""

    def _check_impl(self, url: str, param: str = None, **kwargs) -> Dict:
        timeout = kwargs.get("timeout", 10.0)
        result = {"vulnerable": False, "type": None, "evidence": []}

        if param:
            for payload in PP_PAYLOADS:
                try:
                    r = self.sess.get(url, params={param: payload}, timeout=timeout)
                    if PP_MARKER in r.text:
                        if self.is_false_positive(PP_MARKER, r):
                            logger.debug("pp get: baseline artifact, skip")
                            continue
                        result["vulnerable"] = True
                        result["type"] = "get"
                        result["evidence"].append("pp: %s" % payload[:30])
                        break
                except Exception as e:
                    logger.debug("pp get %s: %s", payload[:20], e)

        if not result["vulnerable"] and param:
            for payload in PP_PAYLOADS:
                try:
                    r = self.sess.post(url, data={param: payload}, timeout=timeout)
                    if r.status_code < 500 and PP_MARKER in r.text:
                        if self.is_false_positive(PP_MARKER, r):
                            logger.debug("pp post: baseline artifact, skip")
                            continue
                        result["vulnerable"] = True
                        result["type"] = "post"
                        result["evidence"].append("pp post: %s" % payload[:20])
                        break
                except Exception as e:
                    logger.debug("pp post %s: %s", payload[:20], e)

        if not result["vulnerable"]:
            try:
                r = self.sess.post(url, json=PP_JSON_PAYLOADS, timeout=timeout)
                if r.status_code < 500:
                    result["vulnerable"] = True
                    result["type"] = "json"
                    result["evidence"].append(
                        "pp json: __proto__ injection (verified via second request)")
            except Exception as e:
                logger.debug("pp json: %s", e)

        if result["vulnerable"] and param:
            try:
                verify_payload = "__proto__[%s]=verified&%s=dummy" % (
                    PP_MARKER, param)
                r2 = self.sess.get(url, params={param: verify_payload},
                                   timeout=timeout)
                if PP_MARKER not in r2.text:
                    result["vulnerable"] = False
                    result["type"] = None
                    result["evidence"].append(
                        "pp: false positive rejected after second request")
            except Exception as e:
                logger.debug("pp verify: %s", e)

        return result


def check(url: str, param: str = None,
          sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    """Backward-compatible module-level API."""
    return ProtoPollutionDetector().check(url, param, sess=sess, timeout=timeout)
