"""
Unit tests for CookieAuditor
"""

from aegisweb.scanner.cookie_auditor import CookieAuditor


def test_cookie_missing_flags():
    auditor = CookieAuditor()
    raw_cookies = ["session_id=12345; Path=/"]
    res = auditor.audit(raw_cookies)
    assert res["total_cookies"] == 1
    assert res["cookies"][0]["secure"] is False
    assert res["cookies"][0]["httponly"] is False
    assert len(res["findings"]) >= 2


def test_secure_cookie():
    auditor = CookieAuditor()
    raw_cookies = ["session_id=12345; Path=/; Secure; HttpOnly; SameSite=Strict"]
    res = auditor.audit(raw_cookies)
    assert res["cookies"][0]["secure"] is True
    assert res["cookies"][0]["httponly"] is True
    assert res["cookies"][0]["samesite"] == "Strict"
    assert len(res["findings"]) == 0