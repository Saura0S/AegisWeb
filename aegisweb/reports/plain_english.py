"""
Plain-English Executive Risk Translator Module
Converts complex cybersecurity findings into clear, business-focused risk narratives with exact file/folder navigation blueprints.
"""

from typing import Dict, Any, List


class PlainEnglishTranslator:
    """Translates technical vulnerabilities into non-technical executive briefs with actionable code navigation."""

    RISK_DICTIONARY = {
        "Public Hardcoded Secret": {
            "title": "Exposed Public API Key / Secret in Frontend Code",
            "what_is_it": "A sensitive API key, access token, or cloud credential was found hardcoded inside your website's public HTML or JavaScript code.",
            "why_dangerous": "Anyone (including automated attacker bots) can inspect your page source, steal this credential, and gain unauthorized access to your cloud services, databases, or third-party APIs.",
            "file_navigation": "📁 Frontend Source Code ➔ Search within your project repository (e.g., `src/`, `public/index.html`, `js/app.js`) ➔ Move secret to root `.env` file.",
            "how_to_fix": "1. Immediately revoke the compromised API key in your cloud provider console.\n2. In your project root, open `.env` and define `API_SECRET_KEY=your_new_key`.\n3. Create a backend API proxy endpoint so frontend JavaScript never touches the raw secret.",
            "exact_code": "# 1. Move to backend .env file:\nAPI_SECRET_KEY=AIzaSyD-YourRotatedSecretKey\n\n# 2. Never commit .env to Git (add to .gitignore)",
            "business_impact": "Critical Risk — Direct database/cloud compromise, data theft, and unexpected API billing charges."
        },
        "Exposed Administrative Portal": {
            "title": "Publicly Reachable Admin Dashboard / Gateway",
            "what_is_it": "An internal administrative login gateway or control panel is openly accessible to anyone on the internet.",
            "why_dangerous": "Attackers can target this interface with automated brute-force attacks, credential stuffing, and authentication bypass exploits to hijack administrative privileges.",
            "file_navigation": "📁 Web Server Config ➔ Open `/etc/nginx/sites-available/default` (or Apache VirtualHost) ➔ Locate `location /admin` directive.",
            "how_to_fix": "1. Restrict the admin route to trusted office/VPN IP addresses.\n2. Enable Multi-Factor Authentication (MFA) on all administrative logins.",
            "exact_code": "# In /etc/nginx/sites-available/default inside server { ... }:\nlocation /admin {\n    allow 203.0.113.10; # Your office static IP\n    deny all;\n}",
            "business_impact": "High Risk — Complete website and database takeover if administrative credentials are compromised."
        },
        "Strict-Transport-Security (HSTS)": {
            "title": "Missing Automatic HTTPS Protection (HSTS)",
            "what_is_it": "Your website doesn't strictly force browsers to only use encrypted HTTPS connections.",
            "why_dangerous": "If a user visits your website from public Wi-Fi (like an airport or coffee shop), an attacker can strip the encryption and intercept logins, credit cards, and private customer data.",
            "file_navigation": "📁 Web Server Configuration ➔ Open `/etc/nginx/sites-available/default` (Nginx) OR `public_html/.htaccess` (Apache) ➔ Inside main HTTPS `server { ... }` block.",
            "how_to_fix": "Open your web server config file, add the HSTS header directive inside your SSL server block, and reload your web server (`sudo nginx -s reload`).",
            "exact_code": "# For Nginx (/etc/nginx/sites-available/default):\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# For Apache (.htaccess):\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            "business_impact": "High Risk — Potential customer data interception and compliance violation (PCI-DSS / GDPR)."
        },
        "Content-Security-Policy (CSP)": {
            "title": "Missing Cross-Site Scripting Shield (CSP)",
            "what_is_it": "Your website lacks a security policy defining which scripts and assets are allowed to load.",
            "why_dangerous": "If a malicious script is injected into your website, it can secretly steal customer passwords, redirect visitors to scams, or hijack user accounts without your knowledge.",
            "file_navigation": "📁 Web Server Configuration ➔ `/etc/nginx/conf.d/security.conf` OR Frontend HTML ➔ `<head>` section in `index.html`.",
            "how_to_fix": "Define a Content-Security-Policy header in your web server that only trusts scripts from your own verified domain.",
            "exact_code": "# For Nginx (/etc/nginx/conf.d/security.conf):\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\" always;",
            "business_impact": "High Risk — Brand reputation damage, malware distribution to visitors, and credential theft."
        },
        "X-Frame-Options": {
            "title": "Vulnerable to Clickjacking (Fake Framing)",
            "what_is_it": "Your website allows other external websites to load your pages inside an invisible iframe overlay.",
            "why_dangerous": "Attackers can trick your logged-in users into clicking buttons (like 'Confirm Payment' or 'Delete Account') while thinking they are clicking a completely different game or video.",
            "file_navigation": "📁 Web Server Configuration ➔ `/etc/nginx/sites-available/default` OR Apache `public_html/.htaccess`.",
            "how_to_fix": "Set 'X-Frame-Options: SAMEORIGIN' across all server responses.",
            "exact_code": "# For Nginx:\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\n\n# For Apache (.htaccess):\nHeader always set X-Frame-Options \"SAMEORIGIN\"",
            "business_impact": "Medium Risk — Unauthorized customer actions, fraudulent transactions, and phishing attacks."
        },
        "X-Content-Type-Options": {
            "title": "MIME-Type Sniffing Exposure",
            "what_is_it": "Your website doesn't tell browsers to strictly follow file types declared by your server.",
            "why_dangerous": "Browsers may attempt to 'guess' the file type and execute a harmless-looking uploaded image as dangerous JavaScript code.",
            "file_navigation": "📁 Web Server Configuration ➔ `/etc/nginx/conf.d/headers.conf` OR `public_html/.htaccess`.",
            "how_to_fix": "Set 'X-Content-Type-Options: nosniff' across all server responses.",
            "exact_code": "# For Nginx:\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# For Apache (.htaccess):\nHeader always set X-Content-Type-Options \"nosniff\"",
            "business_impact": "Medium Risk — Remote script execution via malicious user file uploads."
        },
        "Referrer-Policy": {
            "title": "Missing Referrer-Policy Privacy Shield",
            "what_is_it": "Your server does not control how much sensitive URL data is sent to external sites when users click outgoing links.",
            "why_dangerous": "Sensitive session IDs, reset tokens, or private user IDs in URLs can leak to third-party analytics or external websites.",
            "file_navigation": "📁 Web Server Configuration ➔ `/etc/nginx/sites-available/default` OR `public_html/.htaccess`.",
            "how_to_fix": "Set 'Referrer-Policy: strict-origin-when-cross-origin' in your web server.",
            "exact_code": "# For Nginx:\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n# For Apache (.htaccess):\nHeader always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            "business_impact": "Low-to-Medium Risk — User privacy leak and URL token exposure."
        },
        "Permissions-Policy": {
            "title": "Missing Permissions-Policy (Feature Policy)",
            "what_is_it": "Your server does not explicitly restrict browser features like camera, microphone, or geolocation.",
            "why_dangerous": "Third-party embedded scripts or iframes could attempt to access device sensors without explicit permission boundaries.",
            "file_navigation": "📁 Web Server Configuration ➔ `/etc/nginx/conf.d/security.conf` OR `public_html/.htaccess`.",
            "how_to_fix": "Add the Permissions-Policy header to disable unused browser APIs.",
            "exact_code": "# For Nginx:\nadd_header Permissions-Policy \"geolocation=(), microphone=(), camera=(), payment=()\" always;",
            "business_impact": "Low Risk — Defense-in-depth protection against rogue embedded scripts."
        },
        "Email Spoofing Vulnerability (Missing / Ineffective DMARC Policy)": {
            "title": "Email Domain Vulnerable to Fraudulent Spoofing",
            "what_is_it": "Your domain lacks strict email authentication rules (DMARC/SPF).",
            "why_dangerous": "Scammers can send convincing fake emails using your exact domain (e.g. CEO@yourcompany.com or billing@yourcompany.com) directly to your customers' inboxes to steal payments.",
            "file_navigation": "🌐 Domain DNS Management ➔ Log in to Cloudflare / GoDaddy / Namecheap ➔ Navigate to 'DNS Management' ➔ 'Add Record'.",
            "how_to_fix": "Add a TXT DNS record with hostname `_dmarc` and enforce a quarantine or reject policy.",
            "exact_code": "# In your DNS Provider Management Console:\nRecord Type: TXT\nHost / Name: _dmarc\nValue: v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; sp=reject; aspf=s;\nTTL: Auto / 3600",
            "business_impact": "High Risk — Severe business email compromise, invoice fraud, and loss of client trust."
        },
        "Missing SPF Record in DNS": {
            "title": "Missing SPF (Sender Policy Framework) in DNS",
            "what_is_it": "Your domain lacks an authorized list of mail servers allowed to send email on your behalf.",
            "why_dangerous": "Any rogue mail server on the internet can claim to send legitimate email from your domain without failing basic SPF checks.",
            "file_navigation": "🌐 Domain DNS Management ➔ Cloudflare / Namecheap / Route 53 ➔ 'DNS Records' ➔ Add TXT Record.",
            "how_to_fix": "Add a TXT record for the root domain specifying your authorized mail servers (e.g. Google Workspace, Microsoft 365, SendGrid).",
            "exact_code": "# In your DNS Provider Management Console:\nRecord Type: TXT\nHost / Name: @ (or your domain)\nValue: v=spf1 include:_spf.google.com ~all\nTTL: Auto / 3600",
            "business_impact": "Medium Risk — High email deliverability issues and spam filter rejections."
        }
    }

    def translate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a single finding to plain English narrative with exact file navigation and code."""
        key = finding.get("title", finding.get("header", ""))
        location = finding.get("source_location", "Web Server Headers / DNS Configuration")
        snippet = finding.get("code_snippet", "")
        
        # Check dictionary
        for k, v in self.RISK_DICTIONARY.items():
            if k.lower() in key.lower():
                return {
                    "severity": finding.get("severity", "MEDIUM"),
                    "title": v["title"],
                    "what_is_it": v["what_is_it"],
                    "why_dangerous": v["why_dangerous"],
                    "file_navigation": v.get("file_navigation", f"📁 Location: {location}"),
                    "how_to_fix": v["how_to_fix"],
                    "exact_code": v.get("exact_code", finding.get("recommendation", "")),
                    "business_impact": v["business_impact"],
                    "source_location": location,
                    "code_snippet": snippet
                }

        # Fallback dynamic translation
        return {
            "severity": finding.get("severity", "MEDIUM"),
            "title": finding.get("title", finding.get("header", "Security Misconfiguration")),
            "what_is_it": f"A security configuration issue was detected ({finding.get('cwe', 'Best practice deviation')}).",
            "why_dangerous": "Leaves the website exposed to unintended data leaks or exploitation by automated vulnerability scanners.",
            "file_navigation": f"📁 Configuration Location: {location}",
            "how_to_fix": finding.get("recommendation", "Review and apply the recommended security configuration."),
            "exact_code": finding.get("recommendation", ""),
            "business_impact": "Medium Risk — General security posture weakness.",
            "source_location": location,
            "code_snippet": snippet
        }

    def generate_executive_brief(self, all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate full suite of translated executive findings."""
        return [self.translate_finding(f) for f in all_findings]