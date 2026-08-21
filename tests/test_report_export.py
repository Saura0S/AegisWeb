"""
Unit tests for ReportGenerator export methods and directory isolation
"""

import os
import shutil
import tempfile
from aegisweb.reports.generator import ReportGenerator
from aegisweb.reports.compliance import ComplianceAuditor
from aegisweb.reports.owasp_matrix import OWASPAuditor


def test_export_all_isolated_directory():
    test_dir = tempfile.mkdtemp()
    target_reports_dir = os.path.join(test_dir, "reports", "example_com")

    compliance_data = ComplianceAuditor().evaluate_compliance([])
    owasp_data = OWASPAuditor().audit([])

    sample_payload = {
        "domain": "example.com",
        "grade": "A",
        "score_percentage": 90,
        "executive_findings": [],
        "ssl_info": {"has_ssl": True, "protocol_version": "TLSv1.3", "days_remaining": 85},
        "email_sec": {"spoofing_vulnerable": False, "dmarc_strength": "Strict"},
        "headers_audit": {"missing_headers": []},
        "compliance": compliance_data,
        "owasp": owasp_data,
        "secret_results": {"leaks": []},
        "admin_portals": [],
        "exposed_files": [],
        "nginx_patch": "add_header X-Frame-Options DENY;\n",
        "apache_patch": "Header always set X-Frame-Options DENY\n",
        "caddy_patch": "header X-Frame-Options DENY\n"
    }

    generator = ReportGenerator(sample_payload)
    generator.export_all(target_reports_dir)

    assert os.path.isdir(target_reports_dir)
    assert os.path.exists(os.path.join(target_reports_dir, "audit_report.html"))
    assert os.path.exists(os.path.join(target_reports_dir, "executive_summary.md"))
    assert os.path.exists(os.path.join(target_reports_dir, "scan_dataset.json"))
    assert os.path.exists(os.path.join(target_reports_dir, "nginx_patch.conf"))
    assert os.path.exists(os.path.join(target_reports_dir, "apache_patch.htaccess"))
    assert os.path.exists(os.path.join(target_reports_dir, "caddy_patch.Caddyfile"))

    # Verify JSON content
    with open(os.path.join(target_reports_dir, "scan_dataset.json"), "r", encoding="utf-8") as f:
        content = f.read()
        assert "example.com" in content
        assert "vulnerability_exposure_percentage" in content

    # Cleanup
    shutil.rmtree(test_dir)


def test_resolve_target_dir_auto_nesting():
    sample_payload = {
        "domain": "example.com",
        "grade": "A",
        "score_percentage": 95
    }
    generator = ReportGenerator(sample_payload)

    # Passing 'reports' should auto-nest under 'reports/example.com'
    resolved = generator._resolve_target_dir("reports")
    assert resolved == os.path.join("reports", "example.com")

    # Passing empty string should auto-nest under 'reports/example.com'
    resolved_empty = generator._resolve_target_dir("")
    assert resolved_empty == os.path.join("reports", "example.com")

    # Passing 'reports/example.com' should stay 'reports/example.com'
    resolved_exact = generator._resolve_target_dir("reports/example.com")
    assert resolved_exact == os.path.normpath("reports/example.com")