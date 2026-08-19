"""
Unit tests for HeadersAuditor
"""

from aegisweb.scanner.headers_auditor import HeadersAuditor


def test_perfect_headers():
    auditor = HeadersAuditor()
    perfect_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()"
    }
    res = auditor.audit(perfect_headers)
    assert res["percentage"] == 100
    assert res["grade"] == "A+"
    assert len(res["missing_headers"]) == 0


def test_cors_wildcard_credentials():
    auditor = HeadersAuditor()
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }
    res = auditor.audit(headers)
    assert len(res["cors_issues"]) == 1
    assert "Wildcard Origin Allowed with Credentials" in res["cors_issues"][0]["title"]