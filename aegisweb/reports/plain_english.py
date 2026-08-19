"""
Plain-English Executive Risk Translator Module
Converts complex cybersecurity findings into clear, business-focused risk narratives.
"""

from typing import Dict, Any, List


class PlainEnglishTranslator:
    """Translates technical vulnerabilities into non-technical executive briefs."""

    RISK_DICTIONARY = {
        "Strict-Transport-Security (HSTS)": {
            "title": "Missing Automatic HTTPS Protection (HSTS)",
            "what_is_it": "Your website doesn't strictly force browsers to only use encrypted HTTPS connections.",
            "why_dangerous": "If a user visits your website from public Wi-Fi (like an airport or coffee shop), an attacker can strip the encryption and intercept logins, credit cards, and private customer data.",
            "how_to_fix": "Add the HSTS header to your web server to instruct browsers to never load your website over unencrypted HTTP.",
            "business_impact": "High Risk — Potential customer data interception and compliance violation (PCI-DSS / GDPR)."
        },
        "Content-Security-Policy (CSP)": {
            "title": "Missing Cross-Site Scripting Shield (CSP)",
            "what_is_it": "Your website lacks a security policy defining which scripts and assets are allowed to load.",
            "why_dangerous": "If a malicious script is injected into your website, it can secretly steal customer passwords, redirect visitors to scams, or hijack user accounts without your knowledge.",
            "how_to_fix": "Define a Content-Security-Policy header in your web server that only trusts scripts from your own verified domain.",
            "business_impact": "High Risk — Brand reputation damage, malware distribution to visitors, and credential theft."
        },
        "X-Frame-Options": {
            "title": "Vulnerable to Clickjacking (Fake Framing)",
            "what_is_it": "Your website allows other external websites to load your pages inside an invisible iframe overlay.",
            "why_dangerous": "Attackers can trick your logged-in users into clicking buttons (like 'Confirm Payment' or 'Delete Account') while thinking they are clicking a completely different game or video.",
            "how_to_fix": "Set 'X-Frame-Options: SAMEORIGIN' to prohibit unauthorized websites from embedding your site inside their frames.",
            "business_impact": "Medium Risk — Unauthorized customer actions, fraudulent transactions, and phishing attacks."
        },
        "X-Content-Type-Options": {
            "title": "MIME-Type Sniffing Exposure",
            "what_is_it": "Your website doesn't tell browsers to strictly follow file types declared by your server.",
            "why_dangerous": "Browsers may attempt to 'guess' the file type and execute a harmless-looking uploaded image as dangerous JavaScript code.",
            "how_to_fix": "Set 'X-Content-Type-Options: nosniff' across all server responses.",
            "business_impact": "Medium Risk — Remote script execution via malicious user file uploads."
        },
        "Email Spoofing Vulnerability (Missing / Ineffective DMARC Policy)": {
            "title": "Email Domain Vulnerable to Fraudulent Spoofing",
            "what_is_it": "Your domain lacks strict email authentication rules (DMARC/SPF).",
            "why_dangerous": "Scammers can send convincing fake emails using your exact domain (e.g. CEO@yourcompany.com or billing@yourcompany.com) directly to your customers' inboxes to steal payments.",
            "how_to_fix": "Add a DMARC policy with 'p=quarantine' or 'p=reject' in your DNS records so email providers reject fake emails.",
            "business_impact": "High Risk — Severe business email compromise, invoice fraud, and loss of client trust."
        }
    }

    def translate_finding(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """Convert a single finding to plain English narrative."""
        key = finding.get("title", finding.get("header", ""))
        
        # Check dictionary
        for k, v in self.RISK_DICTIONARY.items():
            if k.lower() in key.lower():
                return {
                    "severity": finding.get("severity", "MEDIUM"),
                    "title": v["title"],
                    "what_is_it": v["what_is_it"],
                    "why_dangerous": v["why_dangerous"],
                    "how_to_fix": v["how_to_fix"],
                    "business_impact": v["business_impact"]
                }

        # Fallback dynamic translation
        return {
            "severity": finding.get("severity", "MEDIUM"),
            "title": finding.get("title", finding.get("header", "Security Misconfiguration")),
            "what_is_it": f"A security configuration issue was detected ({finding.get('cwe', 'Best practice deviation')}).",
            "why_dangerous": "Leaves the website exposed to unintended data leaks or exploitation by automated vulnerability scanners.",
            "how_to_fix": finding.get("recommendation", "Review and apply the recommended security configuration."),
            "business_impact": "Medium Risk — General security posture weakness."
        }

    def generate_executive_brief(self, all_findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate full suite of translated executive findings."""
        return [self.translate_finding(f) for f in all_findings]