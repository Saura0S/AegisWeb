"""
Unit tests for PlainEnglishTranslator
"""

from aegisweb.reports.plain_english import PlainEnglishTranslator


def test_translate_hsts():
    translator = PlainEnglishTranslator()
    finding = {"header": "Strict-Transport-Security (HSTS)", "severity": "HIGH"}
    res = translator.translate_finding(finding)
    assert "HTTPS Protection" in res["title"]
    assert "public Wi-Fi" in res["why_dangerous"]
    assert res["severity"] == "HIGH"


def test_translate_dmarc():
    translator = PlainEnglishTranslator()
    finding = {"title": "Email Spoofing Vulnerability (Missing / Ineffective DMARC Policy)", "severity": "HIGH"}
    res = translator.translate_finding(finding)
    assert "Email Domain Vulnerable" in res["title"]
    assert "Scammers can send" in res["why_dangerous"]