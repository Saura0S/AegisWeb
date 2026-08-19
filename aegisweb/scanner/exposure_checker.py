"""
Sensitive File & Public Information Exposure Checker
"""

import urllib3
import requests
from typing import Dict, List, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ExposureChecker:
    """Non-intrusively tests for publicly exposed configuration files, git directories, and debug endpoints."""

    SENSITIVE_PATHS = [
        {"path": "/.env", "name": "Environment Config (.env)", "severity": "CRITICAL", "desc": "Contains plaintext API keys and database credentials."},
        {"path": "/.git/HEAD", "name": "Git Repository Metadata (/.git)", "severity": "CRITICAL", "desc": "Exposes full source code history."},
        {"path": "/wp-config.php.bak", "name": "WordPress Backup Config", "severity": "HIGH", "desc": "Exposes WordPress database credentials."},
        {"path": "/backup.sql", "name": "Database Dump (/backup.sql)", "severity": "CRITICAL", "desc": "Public database backup dump."},
        {"path": "/phpinfo.php", "name": "PHP Information Page", "severity": "MEDIUM", "desc": "Discloses PHP runtime configuration and server variables."},
        {"path": "/swagger.json", "name": "Swagger / OpenAPI Schema", "severity": "LOW", "desc": "Public API schema documentation."},
        {"path": "/robots.txt", "name": "Robots Exclusion File", "severity": "INFO", "desc": "May list hidden administrative directories."},
        {"path": "/.well-known/security.txt", "name": "Security Policy (security.txt)", "severity": "INFO", "desc": "Vulnerability reporting contact info."}
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisWeb/1.0"}

    def audit(self, base_url: str) -> Dict[str, Any]:
        """Probe for sensitive file exposures."""
        base_url = base_url.rstrip("/")
        exposed_files = []
        findings = []

        for target in self.SENSITIVE_PATHS:
            test_url = f"{base_url}{target['path']}"
            try:
                resp = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Filter out custom 200 soft-404 HTML pages for .env/.git
                    is_valid = True
                    if target["path"] == "/.git/HEAD" and "ref:" not in resp.text:
                        is_valid = False
                    elif target["path"] == "/.env" and ("=" not in resp.text or "<html" in resp.text.lower()):
                        is_valid = False

                    if is_valid:
                        exposed_files.append({
                            "path": target["path"],
                            "name": target["name"],
                            "url": test_url,
                            "status_code": resp.status_code,
                            "severity": target["severity"],
                            "size_bytes": len(resp.content)
                        })
                        if target["severity"] in ["CRITICAL", "HIGH", "MEDIUM"]:
                            findings.append({
                                "severity": target["severity"],
                                "title": f"Sensitive File Exposed: {target['name']}",
                                "cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                                "owasp": "A05:2021-Security Misconfiguration",
                                "recommendation": f"Block public web access to '{target['path']}' in web server configuration."
                            })
            except requests.exceptions.RequestException:
                pass

        return {
            "total_exposed": len(exposed_files),
            "exposed_files": exposed_files,
            "findings": findings
        }