"""
Unit tests for EmailSecurityAuditor
"""

from aegisweb.scanner.email_sec_auditor import EmailSecurityAuditor


def test_email_auditor_init():
    auditor = EmailSecurityAuditor(timeout=2.0)
    assert auditor.timeout == 2.0