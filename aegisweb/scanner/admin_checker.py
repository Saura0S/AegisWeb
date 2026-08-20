"""
Admin Portal & Broken Access Control Auditor Module
"""

import urllib3
import requests
from typing import List, Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AdminAuditor:
    """Audits accessibility of administrative dashboards and management portals."""

    ADMIN_TARGETS = [
        {"path": "/admin", "name": "Standard Admin Portal"},
        {"path": "/admin/login", "name": "Admin Login Gateway"},
        {"path": "/administrator", "name": "Joomla/CMS Administrator"},
        {"path": "/wp-admin", "name": "WordPress Admin Area"},
        {"path": "/dashboard", "name": "User/Management Dashboard"},
        {"path": "/cpanel", "name": "cPanel Control Panel"},
        {"path": "/phpmyadmin", "name": "phpMyAdmin Database Manager"},
        {"path": "/actuator", "name": "Spring Boot Actuator Endpoints"},
        {"path": "/actuator/health", "name": "Spring Boot Health Metrics"},
        {"path": "/api/docs", "name": "Public API Swagger Documentation"}
    ]

    def __init__(self, timeout: int = 4):
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisWeb/1.0"}

    def audit(self, base_url: str) -> Dict[str, Any]:
        """Probe common administrative paths."""
        base_url = base_url.rstrip("/")
        discovered_portals = []
        findings = []

        for target in self.ADMIN_TARGETS:
            test_url = f"{base_url}{target['path']}"
            try:
                resp = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
                status = resp.status_code
                
                # Check if accessible or redirected to login
                if status == 200:
                    # Filter out custom 404 pages
                    body_lower = resp.text.lower()
                    if "not found" not in body_lower and "404" not in body_lower:
                        portal_info = {
                            "name": target["name"],
                            "path": target["path"],
                            "url": test_url,
                            "final_url": resp.url,
                            "status_code": status,
                            "is_exposed": True
                        }
                        discovered_portals.append(portal_info)
                        findings.append({
                            "severity": "MEDIUM",
                            "title": f"Exposed Administrative Portal ({target['name']})",
                            "cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                            "owasp": "A01:2021-Broken Access Control",
                            "source_location": test_url,
                            "recommendation": f"Restrict public IP access to '{target['path']}' via IP whitelisting or VPN gateway."
                        })
            except requests.exceptions.RequestException:
                pass

        return {
            "total_admin_portals": len(discovered_portals),
            "portals": discovered_portals,
            "findings": findings
        }