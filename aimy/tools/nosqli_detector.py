import re, time, json as _json
from typing import Optional
import requests

from aimy.tools.log_utils import get_logger
from aimy.tools.http_client import build_url
from aimy.tools.payload_engine import generate
from aimy.tools.settings import settings
from aimy.tools.base_detector import BaseDetector

logger = get_logger("nosqli_detector")

NOSQLI_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoDB",
    r"Uncaught MongoDB",
    r"ArangoError",
    r"arangosh",
    r"Couchbase",
    r"Cassandra",
    r"RethinkDB",
    r"Firebase",
    r"Invalid BSON",
]


class NoSQLIDetector(BaseDetector):
    """NoSQL injection detection — inherits baseline from BaseDetector."""

    def _check_impl(self, url: str, param: str, **kwargs) -> dict:
        timeout = kwargs.get("timeout", 10.0)
        waf_name = kwargs.get("waf_name")
        result = {"vulnerable": False, "type": None, "evidence": [],
                  "payload": None}

        # Phase 1: Boolean + error detection
        seeds = generate("nosqli", "boolean", "string", waf_name)
        for entry in seeds:
            payload = entry["payload"]
            try:
                r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                diff = abs(len(r.text) - self._baseline_size)
                if diff > 30:
                    result["vulnerable"] = True
                    result["type"] = "boolean"
                    result["evidence"].append(
                        "nosqli: %s (%d diff)" % (payload[:25], diff))
                    result["payload"] = payload
                    break
                for pat in NOSQLI_ERROR_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        if self.is_false_positive(pat, r):
                            logger.debug("nosqli error: baseline artifact, skip %s",
                                         pat[:25])
                            continue
                        result["vulnerable"] = True
                        result["type"] = "error"
                        result["evidence"].append("nosqli error: %s" % pat[:25])
                        result["payload"] = payload
                        break
            except Exception as e:
                logger.debug("nosqli payload %s: %s", payload[:20], e)
            if result["vulnerable"]:
                break

        # Phase 2: Time-based detection
        if not result["vulnerable"]:
            time_seeds = generate("nosqli", "where_time", "string", waf_name)
            for entry in time_seeds:
                payload = entry["payload"]
                threshold = entry.get("threshold", 2.5)
                try:
                    start_t = time.time()
                    r = self.sess.get(build_url(url, param, payload),
                                      timeout=timeout + 2)
                    elapsed = time.time() - start_t
                    if elapsed >= threshold:
                        result["vulnerable"] = True
                        result["type"] = "time"
                        result["evidence"].append(
                            "nosqli time: %s (%.1fs)" % (payload[:25], elapsed))
                        result["payload"] = payload
                        break
                except Exception as e:
                    logger.debug("nosqli time %s: %s", payload[:20], e)

        # Phase 3: JSON injection
        if not result["vulnerable"]:
            json_seeds = generate("nosqli", "json", "json", waf_name)
            for entry in json_seeds:
                payload_raw = entry["payload"]
                try:
                    r = self.sess.post(url, json={param: _json.loads(payload_raw)},
                                       timeout=timeout)
                    if r.status_code == 200 and \
                       len(r.text) > self._baseline_size + 10:
                        result["vulnerable"] = True
                        result["type"] = "json"
                        result["evidence"].append(
                            "nosqli json: %s" % payload_raw[:25])
                        result["payload"] = payload_raw
                        break
                except Exception as e:
                    logger.debug("nosqli json: %s", e)

        return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    """Backward-compatible module-level API."""
    return NoSQLIDetector().check(url, param, sess=sess, timeout=timeout,
                                  waf_name=waf_name)
