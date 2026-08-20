"""
Unit tests for AdminAuditor
"""

from aegisweb.scanner.admin_checker import AdminAuditor


def test_admin_auditor_init():
    auditor = AdminAuditor(timeout=2.0)
    assert len(auditor.ADMIN_TARGETS) >= 5
    assert auditor.timeout == 2.0