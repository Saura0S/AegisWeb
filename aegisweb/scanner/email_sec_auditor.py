"""
Email Security, SPF & DMARC Anti-Spoofing Auditor Module
"""

from typing import Dict, Any, List

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class EmailSecurityAuditor:
    """Audits SPF and DMARC DNS records to identify email spoofing and phishing vulnerabilities."""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def audit(self, domain: str) -> Dict[str, Any]:
        """Check domain SPF and DMARC enforcement."""
        domain = domain.strip().lower()
        result = {
            "domain": domain,
            "has_spf": False,
            "spf_record": "None",
            "spf_strength": "FAIL",
            "has_dmarc": False,
            "dmarc_record": "None",
            "dmarc_policy": "None",
            "dmarc_strength": "FAIL",
            "spoofing_vulnerable": True,
            "findings": []
        }

        if not DNS_AVAILABLE:
            return result

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        # 1. Audit SPF Record
        try:
            txt_records = resolver.resolve(domain, "TXT")
            for rdata in txt_records:
                txt_str = "".join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    result["has_spf"] = True
                    result["spf_record"] = txt_str
                    if "-all" in txt_str:
                        result["spf_strength"] = "STRONG (Hard Fail: -all)"
                    elif "~all" in txt_str:
                        result["spf_strength"] = "MODERATE (Soft Fail: ~all)"
                    elif "?all" in txt_str or "+all" in txt_str:
                        result["spf_strength"] = "WEAK (Permissive: +all/?all)"
                    break
        except Exception:
            pass

        # 2. Audit DMARC Record
        dmarc_domain = f"_dmarc.{domain}"
        try:
            dmarc_records = resolver.resolve(dmarc_domain, "TXT")
            for rdata in dmarc_records:
                txt_str = "".join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_str.startswith("v=DMARC1"):
                    result["has_dmarc"] = True
                    result["dmarc_record"] = txt_str
                    if "p=reject" in txt_str:
                        result["dmarc_policy"] = "reject"
                        result["dmarc_strength"] = "STRONG (p=reject)"
                    elif "p=quarantine" in txt_str:
                        result["dmarc_policy"] = "quarantine"
                        result["dmarc_strength"] = "MODERATE (p=quarantine)"
                    elif "p=none" in txt_str:
                        result["dmarc_policy"] = "none"
                        result["dmarc_strength"] = "WEAK (p=none - Monitoring Only)"
                    break
        except Exception:
            pass

        # Evaluate Overall Spoofing Risk
        if not result["has_dmarc"] or result["dmarc_policy"] == "none":
            result["spoofing_vulnerable"] = True
            result["findings"].append({
                "severity": "HIGH",
                "title": "Email Spoofing Vulnerability (Missing / Ineffective DMARC Policy)",
                "cwe": "CWE-345: Insufficient Verification of Data Authenticity",
                "owasp": "A05:2021-Security Misconfiguration",
                "recommendation": f"Implement a DMARC policy with 'p=quarantine' or 'p=reject' on '_dmarc.{domain}'."
            })
        else:
            result["spoofing_vulnerable"] = False

        if not result["has_spf"]:
            result["findings"].append({
                "severity": "MEDIUM",
                "title": "Missing SPF Record in DNS",
                "cwe": "CWE-345: Insufficient Verification of Data Authenticity",
                "owasp": "A05:2021-Security Misconfiguration",
                "recommendation": f"Add an SPF TXT record 'v=spf1 mx -all' to {domain}."
            })

        return result