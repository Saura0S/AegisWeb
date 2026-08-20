"""
Unit tests for ComplianceAuditor
"""

from aegisweb.reports.compliance import ComplianceAuditor


def test_compliance_evaluation():
    auditor = ComplianceAuditor()
    findings = [
        {"title": "Missing Automatic HTTPS Protection (HSTS)", "severity": "HIGH"},
        {"title": "Email Spoofing Vulnerability (Missing / Ineffective DMARC Policy)", "severity": "HIGH"}
    ]
    res = auditor.evaluate_compliance(findings)
    assert "PCI-DSS v4.0" in res["frameworks"]
    assert "ISO/IEC 27001:2022" in res["frameworks"]
    assert res["overall_governance_score"] > 0