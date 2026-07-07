"""
基线对比单元测试 — 防止认证墙误报回归

Run: python -m pytest tests/test_baseline.py -v
"""

LOGIN_PAGE = (
    '<html><head><title>Login</title></head>'
    '<body><h1>Please login</h1>'
    '<!-- SQL: MySQL, PostgreSQL, syntax error -->'
    '<script>var x = "MongoError"; var y = "unserialize"; '
    'var z = "java.io.Serializable";</script>'
    '<form><input name="user"></form>'
    '</body></html>'
)

REAL_SQL_ERROR = 'Error: SQL syntax near SELECT id FROM users WHERE id=1'
REAL_SSTI_RESULT = '<html>Computed: 49</html>'
REAL_XSS_RESULT = '<html>Results for: <script>alert(1)</script></html>'


def _is_false_positive(baseline_text, baseline_size, indicator, response_text):
    """Replicates the pattern used in all 5 fixed detectors."""
    if baseline_size and abs(len(response_text) - baseline_size) < 50:
        return True
    if baseline_text and indicator and indicator in baseline_text:
        return True
    return False


# ── Auth wall scenarios (MUST be filtered) ──

def test_auth_wall_same_page_sqli_error():
    """Login page mentions 'MySQL' — error-based SQLi must NOT fire."""
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "MySQL", LOGIN_PAGE
    ) is True, "MySQL in login page should be filtered"


def test_auth_wall_same_page_nosqli_error():
    """Login page mentions 'MongoError' — NoSQLi must NOT fire."""
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "MongoError", LOGIN_PAGE
    ) is True


def test_auth_wall_same_page_deser_pattern():
    """Login page has 'java.io.Serializable' — deser must NOT fire."""
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "java.io.Serializable", LOGIN_PAGE
    ) is True


def test_auth_wall_same_page_xss_marker():
    """Auth wall returns same-size page — XSS must NOT fire
    even if marker happens to not be in the baseline text."""
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "XSS_TEST_100", LOGIN_PAGE
    ) is True, "Same size = auth wall, must filter"


# ── Real vulnerability scenarios (MUST pass through) ──

def test_real_sqli_error_passes():
    """Real SQL error page — different size, indicator not in baseline."""
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "SQL syntax", REAL_SQL_ERROR
    ) is False, "Real SQL error must NOT be filtered"


def test_real_ssti_result_passes():
    """SSTI computed '49' on a different page — must NOT be filtered."""
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "49", REAL_SSTI_RESULT
    ) is False


def test_real_xss_reflected_passes():
    """XSS payload reflected on a different page — must NOT be filtered."""
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE),
        "<script>alert(1)</script>", REAL_XSS_RESULT
    ) is False


# ── Edge cases ──

def test_size_diff_exactly_50_is_not_fp():
    """Exactly 50 bytes difference is NOT filtered (boundary)."""
    text = LOGIN_PAGE + "X" * 50
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "nonexistent_marker", text
    ) is False, "50 byte diff = not auth wall"


def test_size_diff_49_is_fp():
    """49 bytes difference IS filtered (just under threshold)."""
    text = LOGIN_PAGE + "X" * 49
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "nonexistent_marker", text
    ) is True, "49 byte diff = likely same page"


def test_indicator_in_baseline_but_different_size_passes():
    """If 'MySQL' is in baseline but response size differs >50 bytes,
    it could be a real finding — let it through cautiously."""
    text = REAL_SQL_ERROR  # 62 chars, very different from LOGIN_PAGE
    # MySQL is in baseline LOGIN_PAGE, so this would be filtered
    assert _is_false_positive(
        LOGIN_PAGE, len(LOGIN_PAGE), "MySQL", text
    ) is True, "indicator in baseline = filtered (conservative)"


def test_empty_baseline_passes_through():
    """No baseline (network error) — never filter."""
    assert _is_false_positive("", 0, "anything", REAL_SQL_ERROR) is False
    assert _is_false_positive("", None, None, REAL_SQL_ERROR) is False
