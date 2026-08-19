"""
Session & Cookie Security Auditor Module
"""

import re
from typing import List, Dict, Any


class CookieAuditor:
    """Audits HTTP cookies for Secure, HttpOnly, and SameSite defensive attributes."""

    def audit(self, set_cookie_headers: List[str]) -> Dict[str, Any]:
        """Audit raw Set-Cookie header strings."""
        findings = []
        cookies_analyzed = []

        for raw_cookie in set_cookie_headers:
            parts = [p.strip() for p in raw_cookie.split(";")]
            if not parts:
                continue

            name_val = parts[0].split("=", 1)
            cookie_name = name_val[0]

            attributes = {p.split("=")[0].lower(): (p.split("=")[1] if "=" in p else True) for p in parts[1:]}

            has_secure = "secure" in attributes
            has_httponly = "httponly" in attributes
            samesite = attributes.get("samesite", "missing")

            cookie_info = {
                "name": cookie_name,
                "secure": has_secure,
                "httponly": has_httponly,
                "samesite": samesite,
                "is_vulnerable": False,
                "issues": []
            }

            if not has_secure:
                cookie_info["issues"].append("Missing 'Secure' flag (Transmitted in cleartext over unencrypted HTTP)")
                cookie_info["is_vulnerable"] = True
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                    "cwe": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "recommendation": f"Add 'Secure' attribute to cookie '{cookie_name}'."
                })

            if not has_httponly:
                cookie_info["issues"].append("Missing 'HttpOnly' flag (Accessible to client JavaScript / XSS theft)")
                cookie_info["is_vulnerable"] = True
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                    "cwe": "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "recommendation": f"Add 'HttpOnly' attribute to cookie '{cookie_name}' to prevent XSS session hijacking."
                })

            if samesite == "missing" or str(samesite).lower() == "none":
                cookie_info["issues"].append("Insecure or Missing 'SameSite' attribute (Vulnerable to CSRF)")
                cookie_info["is_vulnerable"] = True
                findings.append({
                    "severity": "LOW",
                    "title": f"Cookie '{cookie_name}' Insecure SameSite Policy",
                    "cwe": "CWE-352: Cross-Site Request Forgery (CSRF)",
                    "owasp": "A01:2021-Broken Access Control",
                    "recommendation": f"Set 'SameSite=Lax' or 'SameSite=Strict' for cookie '{cookie_name}'."
                })

            cookies_analyzed.append(cookie_info)

        return {
            "total_cookies": len(cookies_analyzed),
            "cookies": cookies_analyzed,
            "findings": findings
        }