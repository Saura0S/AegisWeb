"""
Unit tests for OWASPAuditor
"""

from aegisweb.reports.owasp_matrix import OWASPAuditor


def test_owasp_audit_clean():
    auditor = OWASPAuditor()
    res = auditor.audit([])
    assert res["passed_count"] == 10
    assert res["failed_count"] == 0
    assert res["owasp_compliance_score"] == 100
    assert res["status"] == "COMPLIANT"


def test_owasp_audit_with_findings():
    auditor = OWASPAuditor()
    findings = [
        {"title": "Missing Cross-Site Scripting Shield (CSP)", "cwe": "CWE-79", "owasp": "A03:2021", "severity": "HIGH"},
        {"title": "Missing Automatic HTTPS Protection (HSTS)", "cwe": "CWE-319", "owasp": "A02:2021", "severity": "HIGH"},
        {"title": "Exposed Administrative Portal (/admin)", "cwe": "CWE-200", "owasp": "A01:2021", "severity": "MEDIUM"}
    ]
    res = auditor.audit(findings)
    assert res["failed_count"] >= 2
    assert res["owasp_compliance_score"] < 100
    assert res["categories"]["A01:2021"]["status"] == "FAIL"
    assert res["categories"]["A02:2021"]["status"] == "FAIL"
    assert res["categories"]["A03:2021"]["status"] == "FAIL"