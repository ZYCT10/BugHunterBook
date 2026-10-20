"""Тесты huntkit.headers: парсер заголовков и анализатор security headers."""



from huntkit.headers import Severity, analyze, parse_header_block


# ------------------------------------------------------------- parse_header_block
def test_parse_skips_status_line_and_lowercases_names() -> None:
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom: A\r\n"
    parsed = parse_header_block(raw)
    assert parsed == {"content-type": "text/html", "x-custom": "A"}


def test_parse_joins_repeated_headers() -> None:
    raw = "Set-Cookie: a=1\nSet-Cookie: b=2\n"
    assert parse_header_block(raw)["set-cookie"] == "a=1, b=2"


def test_parse_ignores_garbage_lines() -> None:
    raw = "Content-Type: text/html\nгрязь без двоеточия\n: пусто\n"
    parsed = parse_header_block(raw)
    assert parsed == {"content-type": "text/html"}


# --------------------------------------------------------------------- analyze
def _secure_headers() -> dict[str, str]:
    return {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
    }


def test_well_configured_headers_have_no_findings() -> None:
    report = analyze(_secure_headers(), is_https=True)
    assert report.findings == []
    assert report.max_severity is None


def test_missing_hsts_over_https_is_medium() -> None:
    headers = _secure_headers()
    del headers["Strict-Transport-Security"]
    report = analyze(headers, is_https=True)
    hsts = [f for f in report.findings if f.header == "Strict-Transport-Security"]
    assert hsts and hsts[0].severity is Severity.MEDIUM


def test_missing_hsts_over_http_is_info() -> None:
    headers = _secure_headers()
    del headers["Strict-Transport-Security"]
    report = analyze(headers, is_https=False)
    hsts = [f for f in report.findings if f.header == "Strict-Transport-Security"]
    assert hsts and hsts[0].severity is Severity.INFO


def test_frame_ancestors_counts_as_clickjacking_protection() -> None:
    headers = _secure_headers()
    del headers["X-Frame-Options"]  # защита остаётся через CSP frame-ancestors
    report = analyze(headers, is_https=True)
    assert not [f for f in report.findings if f.header == "X-Frame-Options"]


def test_leaky_headers_flagged() -> None:
    headers = _secure_headers()
    headers["Server"] = "nginx/1.25.1"
    headers["X-Powered-By"] = "PHP/8.1"
    report = analyze(headers, is_https=True)
    leaky = {f.header for f in report.findings}
    assert {"server", "x-powered-by"} <= leaky


def test_empty_headers_reports_core_missing_and_max_medium() -> None:
    report = analyze({}, is_https=True)
    headers_flagged = {f.header for f in report.findings}
    assert "Content-Security-Policy" in headers_flagged
    assert "X-Content-Type-Options" in headers_flagged
    assert report.max_severity is Severity.MEDIUM


def test_end_to_end_from_raw_block() -> None:
    raw = "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: Apache\n"
    report = analyze(parse_header_block(raw), is_https=True)
    assert report.max_severity is Severity.MEDIUM
    assert any(f.header == "server" for f in report.findings)
