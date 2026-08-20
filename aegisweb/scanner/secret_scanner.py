"""
Secret & Client-Side API Key Leak Scanner Module
Inspects HTML source and JavaScript bundles for hardcoded credentials, tokens, and API keys.
"""

import re
import urllib3
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Set

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SecretScanner:
    """Scans web pages and referenced JavaScript bundles for exposed API keys and secrets."""

    PATTERNS = {
        "Google API Key": {
            "regex": r"AIza[0-9A-Za-z-_]{35}",
            "severity": "HIGH",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "risk": "Exposed Google Cloud / Maps / Firebase API key found hardcoded in client-side code."
        },
        "AWS Access Key ID": {
            "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "severity": "CRITICAL",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "risk": "Public AWS IAM Access Key identifier found in frontend code."
        },
        "Stripe API Key": {
            "regex": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,34}",
            "severity": "HIGH",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "risk": "Stripe payment gateway key found in source code."
        },
        "GitHub Token": {
            "regex": r"(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}",
            "severity": "CRITICAL",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "risk": "GitHub Personal Access Token or OAuth Token exposed in public code."
        },
        "Slack Webhook URL": {
            "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "severity": "HIGH",
            "cwe": "CWE-200: Exposure of Sensitive Information",
            "owasp": "A01:2021-Broken Access Control",
            "risk": "Incoming Slack webhook URL exposed, allowing unauthorized message posting."
        },
        "Generic Bearer / JWT Token": {
            "regex": r"eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*",
            "severity": "MEDIUM",
            "cwe": "CWE-522: Insufficiently Protected Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "risk": "Hardcoded JSON Web Token (JWT) session credential found."
        },
        "Database Connection String": {
            "regex": r"(?:mongodb(?:\+srv)?|postgres|postgresql|mysql)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+",
            "severity": "CRITICAL",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "risk": "Plaintext database connection string with embedded credentials."
        }
    }

    def __init__(self, max_scripts: int = 10, timeout: int = 5):
        self.max_scripts = max_scripts
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisWeb/1.0"}

    def scan(self, base_url: str, html_body: str = "") -> Dict[str, Any]:
        """Inspect page source and extract scripts to search for secrets."""
        leaks_found: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        scanned_urls: Set[str] = set()

        # 1. Scan root HTML source
        if html_body:
            self._scan_content(html_body, base_url, "HTML Document", leaks_found, findings)

        # 2. Extract and scan linked JavaScript bundles (<script src="...">)
        js_urls = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', html_body, re.IGNORECASE)
        for js_path in js_urls[:self.max_scripts]:
            full_js_url = urljoin(base_url, js_path)
            if full_js_url in scanned_urls:
                continue

            # Only scan same-origin or relevant JS files
            if urlparse(full_js_url).netloc == urlparse(base_url).netloc:
                scanned_urls.add(full_js_url)
                try:
                    resp = requests.get(full_js_url, headers=self.headers, timeout=self.timeout, verify=False)
                    if resp.status_code == 200 and resp.text:
                        self._scan_content(resp.text, full_js_url, "JavaScript Bundle", leaks_found, findings)
                except Exception:
                    pass

        return {
            "total_secrets_found": len(leaks_found),
            "leaks": leaks_found,
            "findings": findings
        }

    def _scan_content(self, text: str, source_url: str, source_type: str, leaks: List[Dict[str, Any]], findings: List[Dict[str, Any]]):
        """Scan raw text content line by line."""
        lines = text.splitlines()
        for line_idx, line in enumerate(lines, 1):
            # Ignore excessively long minified lines for regex performance
            sample = line[:1000]
            for secret_type, meta in self.PATTERNS.items():
                matches = re.findall(meta["regex"], sample)
                for match in matches:
                    # Mask secret for safe display
                    masked = match[:4] + "*" * (len(match) - 8) + match[-4:] if len(match) > 8 else "***"
                    leak_entry = {
                        "type": secret_type,
                        "severity": meta["severity"],
                        "source_url": source_url,
                        "source_type": source_type,
                        "line_number": line_idx,
                        "masked_value": masked,
                        "code_snippet": line.strip()[:140],
                        "risk": meta["risk"]
                    }
                    leaks.append(leak_entry)
                    findings.append({
                        "id": f"SEC-{secret_type.replace(' ', '_').upper()}",
                        "severity": meta["severity"],
                        "title": f"Public Hardcoded Secret: {secret_type}",
                        "cwe": meta["cwe"],
                        "owasp": meta["owasp"],
                        "source_location": f"{source_url} (Line {line_idx})",
                        "code_snippet": line.strip()[:140],
                        "recommendation": f"Revoke and rotate this {secret_type} immediately. Move sensitive credentials to secure backend environment variables (.env)."
                    })