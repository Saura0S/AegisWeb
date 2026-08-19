"""
SSL/TLS Certificate, Cipher & Protocol Auditor
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class SSLChecker:
    """Audits SSL/TLS certificates, expiry dates, and encryption standards."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def audit(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Inspect SSL certificate details and cipher strength."""
        hostname = hostname.split("/")[0].split(":")[0].strip()
        result = {
            "has_ssl": False,
            "issuer": "N/A",
            "subject": "N/A",
            "expires_on": "N/A",
            "days_remaining": 0,
            "is_expired": False,
            "is_expiring_soon": False,
            "protocol_version": "N/A",
            "cipher": "N/A",
            "san": [],
            "status": "FAIL",
            "findings": []
        }

        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher_info = ssock.cipher()
                    protocol = ssock.version()

                    result["has_ssl"] = True
                    result["protocol_version"] = protocol or "TLS"
                    result["cipher"] = cipher_info[0] if cipher_info else "N/A"

                    # Parse expiration date
                    not_after_str = cert.get("notAfter", "")
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (not_after - now).days
                        result["expires_on"] = not_after.strftime("%Y-%m-%d")
                        result["days_remaining"] = max(0, days_left)
                        result["is_expired"] = days_left <= 0
                        result["is_expiring_soon"] = 0 < days_left <= 30

                    # Parse Issuer & Subject
                    for item in cert.get("issuer", ()):
                        for key, val in item:
                            if key in ["organizationName", "commonName"]:
                                result["issuer"] = val
                                break

                    for item in cert.get("subject", ()):
                        for key, val in item:
                            if key == "commonName":
                                result["subject"] = val
                                break

                    # Parse SANs
                    sans = []
                    for k, v in cert.get("subjectAltName", ()):
                        if k == "DNS":
                            sans.append(v)
                    result["san"] = sans

                    # Formulate Findings
                    if result["is_expired"]:
                        result["findings"].append({
                            "id": "SSL-001",
                            "severity": "CRITICAL",
                            "title": "SSL/TLS Certificate Has Expired",
                            "cwe": "CWE-295: Improper Certificate Validation",
                            "owasp": "A02:2021-Cryptographic Failures"
                        })
                    elif result["is_expiring_soon"]:
                        result["findings"].append({
                            "id": "SSL-002",
                            "severity": "MEDIUM",
                            "title": f"SSL Certificate Expiring in {result['days_remaining']} Days",
                            "cwe": "CWE-295: Improper Certificate Validation",
                            "owasp": "A02:2021-Cryptographic Failures"
                        })

                    if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        result["findings"].append({
                            "id": "SSL-003",
                            "severity": "HIGH",
                            "title": f"Deprecated Insecure TLS Version Detected ({protocol})",
                            "cwe": "CWE-326: Inadequate Encryption Strength",
                            "owasp": "A02:2021-Cryptographic Failures"
                        })

                    result["status"] = "PASS" if not result["is_expired"] else "FAIL"

        except Exception as e:
            result["findings"].append({
                "id": "SSL-000",
                "severity": "HIGH",
                "title": f"HTTPS/SSL Connection Failed: {str(e)}",
                "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
                "owasp": "A02:2021-Cryptographic Failures"
            })

        return result