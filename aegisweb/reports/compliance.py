"""
Compliance & Regulatory Framework Mapping Engine
Maps technical findings to PCI-DSS v4.0, ISO/IEC 27001:2022, NIST SP 800-53, HIPAA, and GDPR.
"""

from typing import List, Dict, Any


class ComplianceAuditor:
    """Evaluates regulatory compliance posture against global cybersecurity standards."""

    FRAMEWORKS = {
        "PCI-DSS v4.0": {
            "name": "Payment Card Industry Data Security Standard v4.0",
            "controls": {
                "HSTS": "Req 4.1.2: Strong cryptography and security protocols over public networks.",
                "CSP": "Req 6.4.3: Scripts executed in consumer browsers are managed and integrity verified.",
                "SSL": "Req 4.2.1: Strong TLS certificates and deprecated protocols disabled.",
                "Cookies": "Req 8.2.8: Session authentication cookies protected against theft.",
                "DMARC": "Req 5.4.1: Anti-phishing mechanisms and spoofing protection."
            }
        },
        "ISO/IEC 27001:2022": {
            "name": "Information Security Management Standard",
            "controls": {
                "HSTS": "Control A.8.20: Network Security & Encryption in Transit.",
                "CSP": "Control A.8.28: Secure Coding & Web Application Protection.",
                "SSL": "Control A.8.24: Use of Cryptography and Key Management.",
                "Cookies": "Control A.8.5: Secure Authentication and Session Management.",
                "Exposure": "Control A.8.12: Data Leakage Prevention (Confidential Configs)."
            }
        },
        "NIST SP 800-53 Rev. 5": {
            "name": "NIST Security and Privacy Controls for Information Systems",
            "controls": {
                "HSTS": "SC-8: Transmission Confidentiality and Integrity.",
                "CSP": "SI-10: Information Input Validation and Script Execution Control.",
                "SSL": "SC-13: Cryptographic Protection & Modern TLS Standards.",
                "DMARC": "SI-8: Spam and Phishing Protection / Domain Validation.",
                "Exposure": "AC-3: Access Enforcement & Unauthorized File Disclosure."
            }
        },
        "HIPAA Security Rule": {
            "name": "Health Insurance Portability and Accountability Act (45 CFR § 164.312)",
            "controls": {
                "HSTS": "§ 164.312(e)(1): Transmission Security & Encryption.",
                "SSL": "§ 164.312(a)(2)(iv): Encryption and Decryption Standards.",
                "Cookies": "§ 164.312(d): Person or Entity Authentication & Session Tokens."
            }
        },
        "GDPR Article 32": {
            "name": "General Data Protection Regulation (EU 2016/679)",
            "controls": {
                "HSTS": "Article 32(1)(a): Pseudonymisation and Encryption of Personal Data.",
                "CSP": "Article 32(1)(b): Confidentiality, Integrity, and Availability of Processing Systems.",
                "DMARC": "Article 32(1): Measures against Social Engineering & Identity Impersonation."
            }
        }
    }

    def evaluate_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Audit findings against compliance standards and determine readiness percentage."""
        framework_scores = {}
        total_violations = len(findings)

        for fw_key, fw_meta in self.FRAMEWORKS.items():
            violations = []
            for f in findings:
                title = f.get("title", "").lower()
                for c_key, c_desc in fw_meta["controls"].items():
                    if c_key.lower() in title:
                        violations.append({"control": c_desc, "issue": f.get("title")})

            total_controls = len(fw_meta["controls"])
            failed_controls = len(violations)
            readiness_pct = max(10, int(((total_controls - failed_controls) / total_controls) * 100)) if total_controls > 0 else 100
            
            framework_scores[fw_key] = {
                "name": fw_meta["name"],
                "readiness_percentage": readiness_pct,
                "status": "COMPLIANT" if readiness_pct >= 85 else ("PARTIALLY COMPLIANT" if readiness_pct >= 50 else "NON-COMPLIANT"),
                "violations": violations
            }

        return {
            "frameworks": framework_scores,
            "overall_governance_score": int(sum(f["readiness_percentage"] for f in framework_scores.values()) / len(framework_scores))
        }