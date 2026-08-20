"""
OWASP Top 10 (2021) Standard Compliance & Checklist Engine
Maps technical security posture against all 10 OWASP Top 10 categories.
"""

from typing import List, Dict, Any


class OWASPAuditor:
    """Evaluates scan findings against the official OWASP Top 10:2021 framework."""

    OWASP_CATEGORIES = {
        "A01:2021": {
            "title": "Broken Access Control",
            "description": "Restrictions on what authenticated and unauthenticated users can do are not properly enforced.",
            "keywords": ["admin", "portal", "dashboard", "cpanel", "cors", "takeover", "exposure", "access control"],
            "impact": "Unauthorized access to sensitive user data, admin privileges, and resource manipulation.",
            "remediation": "Enforce strict role-based access control (RBAC), disable directory listings, restrict CORS to trusted origins, and protect admin endpoints."
        },
        "A02:2021": {
            "title": "Cryptographic Failures",
            "description": "Sensitive data transmitted over public channels is not properly protected with strong encryption.",
            "keywords": ["ssl", "tls", "hsts", "cipher", "certificate", "crypto", "encryption", "https"],
            "impact": "Data in transit (passwords, tokens, personal information) can be intercepted and decrypted via public networks.",
            "remediation": "Enforce TLS 1.2/1.3, deprecate weak cipher suites, mandate HSTS with long max-age and preload."
        },
        "A03:2021": {
            "title": "Injection",
            "description": "Untrusted user data is executed by an interpreter as part of a command or query (e.g. XSS, SQLi).",
            "keywords": ["csp", "content-security-policy", "xss", "script", "injection"],
            "impact": "Execution of malicious scripts in visitor browsers, credential theft, session hijacking, and page defacement.",
            "remediation": "Deploy a strict Content-Security-Policy (CSP), sanitize input, and parameterize queries."
        },
        "A04:2021": {
            "title": "Insecure Design",
            "description": "Risks related to design and architectural flaws, lacking threat modeling and defense-in-depth.",
            "keywords": ["spf", "dmarc", "spoofing", "phishing", "email"],
            "impact": "Domain impersonation for fraudulent invoice scams, employee phishing, and business email compromise.",
            "remediation": "Implement SPF records and enforce a strict DMARC rejection policy (p=reject or p=quarantine)."
        },
        "A05:2021": {
            "title": "Security Misconfiguration",
            "description": "Insecure default configurations, missing security headers, or open cloud permissions.",
            "keywords": ["x-frame-options", "x-content-type-options", "clickjacking", "sniffing", "referrer-policy", "permissions-policy", "misconfiguration"],
            "impact": "Clickjacking framing, MIME confusion attacks, browser feature abuse, and information leaks.",
            "remediation": "Apply hardened security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) across all web responses."
        },
        "A06:2021": {
            "title": "Vulnerable and Outdated Components",
            "description": "Using software components, libraries, or server daemons with known vulnerabilities or end-of-life status.",
            "keywords": ["server banner", "outdated", "deprecated", "tls 1.0", "tls 1.1", "version"],
            "impact": "Direct exploitation of unpatched vulnerabilities in web servers, frameworks, and third-party dependencies.",
            "remediation": "Strip server version disclosure banners (server_tokens off) and maintain automated patch management."
        },
        "A07:2021": {
            "title": "Identification and Authentication Failures",
            "description": "Weaknesses in user session management, password handling, or hardcoded API tokens.",
            "keywords": ["secret", "api key", "token", "jwt", "cookie", "httponly", "samesite", "secure flag"],
            "impact": "Session token theft via JavaScript (XSS), credential exposure, and unauthorized API account usage.",
            "remediation": "Attach HttpOnly, Secure, and SameSite attributes to cookies; store API keys in backend environment variables."
        },
        "A08:2021": {
            "title": "Software and Data Integrity Failures",
            "description": "Code and infrastructure that does not protect against integrity violations (e.g. dangling CNAMEs, untrusted CDNs).",
            "keywords": ["takeover", "dangling", "cname", "integrity", "subdomain takeover"],
            "impact": "Attacker registers abandoned cloud buckets/subdomains and serves malicious payloads under the company's verified domain.",
            "remediation": "Continuously monitor and delete dangling DNS CNAME pointers to decommissioned cloud providers."
        },
        "A09:2021": {
            "title": "Security Logging and Monitoring Failures",
            "description": "Insufficient logging, monitoring, and alerting that prevents timely detection of security breaches.",
            "keywords": ["rua", "ruf", "logging", "monitoring", "dmarc-reports"],
            "impact": "Breaches go undetected for months, preventing incident response and forensic analysis.",
            "remediation": "Configure DMARC aggregate reporting (rua=mailto:...) and centralize web application audit logs."
        },
        "A10:2021": {
            "title": "Server-Side Request Forgery (SSRF)",
            "description": "Web applications fetching remote resources without validating the user-supplied destination URL.",
            "keywords": ["ssrf", "actuator", "internal route", "metadata"],
            "impact": "Internal cloud metadata service (169.254.169.254) theft and internal network pivot.",
            "remediation": "Restrict web server egress, validate URL schemas, and block requests targeting private IP spaces."
        }
    }

    def audit(self, all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall findings against the 10 OWASP categories."""
        checklist = {}
        passed_count = 0
        failed_count = 0

        for cat_id, cat_info in self.OWASP_CATEGORIES.items():
            violations = []
            for finding in all_findings:
                text_to_search = (
                    finding.get("title", "") + " " +
                    finding.get("cwe", "") + " " +
                    finding.get("owasp", "") + " " +
                    finding.get("header", "")
                ).lower()

                for kw in cat_info["keywords"]:
                    if kw in text_to_search:
                        violations.append({
                            "title": finding.get("title", finding.get("header", "Finding")),
                            "severity": finding.get("severity", "MEDIUM")
                        })
                        break

            is_passed = len(violations) == 0
            if is_passed:
                passed_count += 1
            else:
                failed_count += 1

            checklist[cat_id] = {
                "id": cat_id,
                "title": cat_info["title"],
                "description": cat_info["description"],
                "status": "PASS" if is_passed else "FAIL",
                "violations_count": len(violations),
                "violations": violations,
                "impact": cat_info["impact"],
                "remediation": cat_info["remediation"]
            }

        score = int((passed_count / 10) * 100)
        return {
            "categories": checklist,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "owasp_compliance_score": score,
            "status": "COMPLIANT" if score >= 80 else ("PARTIALLY COMPLIANT" if score >= 50 else "NON-COMPLIANT")
        }