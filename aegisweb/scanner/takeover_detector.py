"""
Subdomain Takeover & Dangling CNAME Detector
"""

from typing import Dict, List, Any

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class TakeoverDetector:
    """Detects dangling CNAME records pointing to abandoned third-party cloud services."""

    CLOUD_FINGERPRINTS = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "s3.amazonaws.com": "AWS S3 Bucket",
        "azurewebsites.net": "Microsoft Azure App Service",
        "myshopify.com": "Shopify Store",
        "surge.sh": "Surge.sh Hosting",
        "pantheonsite.io": "Pantheon",
        "readme.io": "Readme.io",
        "zendesk.com": "Zendesk",
        "ghost.io": "Ghost CMS"
    }

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def audit(self, domain: str, cnames: List[str] = None) -> Dict[str, Any]:
        """Check for dangling CNAME pointers."""
        findings = []
        matched_cnames = []

        if cnames is None and DNS_AVAILABLE:
            cnames = []
            try:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = self.timeout
                resolver.timeout = self.timeout
                answers = resolver.resolve(domain, "CNAME")
                for r in answers:
                    cnames.append(str(r.target).rstrip("."))
            except Exception:
                pass

        for cname in (cnames or []):
            for pattern, service_name in self.CLOUD_FINGERPRINTS.items():
                if pattern in cname.lower():
                    matched_cnames.append({"cname": cname, "service": service_name})
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Potential Subdomain Takeover Risk on '{domain}'",
                        "cwe": "CWE-284: Improper Access Control (Dangling DNS Pointer)",
                        "owasp": "A01:2021-Broken Access Control",
                        "recommendation": f"Verify '{cname}' in your {service_name} account. If decommissioned, delete the CNAME record immediately."
                    })

        return {
            "domain": domain,
            "cnames": cnames or [],
            "matched_cloud_services": matched_cnames,
            "takeover_risk": len(findings) > 0,
            "findings": findings
        }