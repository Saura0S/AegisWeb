"""
Security Headers & CORS Misconfiguration Auditor
"""

from typing import Dict, List, Any


class HeadersAuditor:
    """Audits HTTP headers against OWASP Top 10 and CWE defensive security standards."""

    DEFENSIVE_RULES = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "weight": 25,
            "severity": "HIGH",
            "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
            "owasp": "A05:2021-Security Misconfiguration",
            "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
            "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
        },
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "weight": 25,
            "severity": "HIGH",
            "cwe": "CWE-693: Protection Mechanism Failure",
            "owasp": "A03:2021-Injection (XSS Defense)",
            "recommendation": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;",
            "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\""
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "weight": 15,
            "severity": "MEDIUM",
            "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers (Clickjacking)",
            "owasp": "A05:2021-Security Misconfiguration",
            "recommendation": "X-Frame-Options: SAMEORIGIN",
            "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "apache": "Header always set X-Frame-Options \"SAMEORIGIN\""
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "weight": 15,
            "severity": "MEDIUM",
            "cwe": "CWE-693: Protection Mechanism Failure",
            "owasp": "A05:2021-Security Misconfiguration",
            "recommendation": "X-Content-Type-Options: nosniff",
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": "Header always set X-Content-Type-Options \"nosniff\""
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "weight": 10,
            "severity": "LOW",
            "cwe": "CWE-200: Exposure of Sensitive Information",
            "owasp": "A01:2021-Broken Access Control",
            "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
            "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "weight": 10,
            "severity": "LOW",
            "cwe": "CWE-693: Protection Mechanism Failure",
            "owasp": "A05:2021-Security Misconfiguration",
            "recommendation": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "nginx": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            "apache": "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\""
        }
    }

    LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]

    def audit(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Perform comprehensive defensive header and CORS assessment."""
        norm_headers = {k.lower(): str(v) for k, v in headers.items()}
        
        score = 0
        max_score = sum(r["weight"] for r in self.DEFENSIVE_RULES.values())
        present = []
        missing = []
        leaks = []
        cors_issues = []

        # Audit Defensive Headers
        for key, meta in self.DEFENSIVE_RULES.items():
            if key in norm_headers:
                score += meta["weight"]
                present.append({
                    "header": meta["name"],
                    "raw_key": key,
                    "value": norm_headers[key],
                    "status": "PASS"
                })
            else:
                missing.append({
                    "header": meta["name"],
                    "raw_key": key,
                    "severity": meta["severity"],
                    "cwe": meta["cwe"],
                    "owasp": meta["owasp"],
                    "recommendation": meta["recommendation"],
                    "nginx_patch": meta["nginx"],
                    "apache_patch": meta["apache"],
                    "status": "FAIL"
                })

        # Audit Server Banner Leaks
        for leak in self.LEAK_HEADERS:
            if leak in norm_headers:
                leaks.append({
                    "header": leak,
                    "value": norm_headers[leak],
                    "severity": "LOW",
                    "cwe": "CWE-200: Exposure of Sensitive Information",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "recommendation": f"Remove or mask '{leak}' header to prevent version fingerprinting."
                })

        # Audit CORS Misconfiguration
        cors_origin = norm_headers.get("access-control-allow-origin", "")
        cors_creds = norm_headers.get("access-control-allow-credentials", "")
        if cors_origin == "*" and cors_creds.lower() == "true":
            cors_issues.append({
                "severity": "HIGH",
                "title": "Insecure CORS: Wildcard Origin Allowed with Credentials",
                "cwe": "CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
                "owasp": "A01:2021-Broken Access Control",
                "recommendation": "Do not allow credentials (cookies/tokens) when Access-Control-Allow-Origin is set to '*'."
            })

        percentage = round((score / max_score) * 100) if max_score > 0 else 0
        grade = "A+" if percentage >= 95 else ("A" if percentage >= 85 else ("B" if percentage >= 70 else ("C" if percentage >= 55 else ("D" if percentage >= 40 else "F"))))

        return {
            "score": score,
            "max_score": max_score,
            "percentage": percentage,
            "grade": grade,
            "present_headers": present,
            "missing_headers": missing,
            "info_leaks": leaks,
            "cors_issues": cors_issues
        }