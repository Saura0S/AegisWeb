"""
Report Orchestrator & Exporter Module
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, List

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from jinja2 import Environment, FileSystemLoader
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


class ReportGenerator:
    """Handles rendering interactive console output, JSON, Plain-Text, Patches & SPA HTML reports."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.console = Console(legacy_windows=False) if RICH_AVAILABLE else None

    def print_terminal_dashboard(self):
        """Display formatted terminal dashboard with Green Ticks, Red Crosses, and CISO Verdict."""
        if not self.console:
            print(f"\n--- AegisWeb Security Audit: {self.data.get('domain')} ---")
            print(f"Grade: {self.data.get('grade')} ({self.data.get('score_percentage')}%)")
            return

        domain = self.data.get("domain", "")
        grade = self.data.get("grade", "N/A")
        score = self.data.get("score_percentage", 0)
        grade_color = "green" if grade in ["A+", "A"] else ("yellow" if grade in ["B", "C"] else "red")
        compliance_score = self.data.get("compliance", {}).get("overall_governance_score", 0)
        owasp_score = self.data.get("owasp", {}).get("owasp_compliance_score", 0)

        vulnerability_pct = max(0, min(100, 100 - score))
        if vulnerability_pct == 0:
            verdict_badge = "[bold green]0% VULNERABLE (COMPLETELY SAFE / HARDENED)[/]"
            verdict_quote = "Target demonstrates an ironclad defense posture (0% Vulnerability Risk). All critical defensive controls, encryption, and secret protections are fully active."
        elif vulnerability_pct <= 20:
            verdict_badge = f"[bold green]{vulnerability_pct}% VULNERABLE (MINIMAL RISK)[/]"
            verdict_quote = f"Target demonstrates strong security baseline with only {vulnerability_pct}% minor exposure risk. Minor header or policy hardening recommended."
        elif vulnerability_pct <= 45:
            verdict_badge = f"[bold yellow]{vulnerability_pct}% VULNERABLE (MODERATE RISK)[/]"
            verdict_quote = f"Target exhibits {vulnerability_pct}% vulnerability exposure risk. Key attack vectors (e.g. missing security headers or email authentication) require timely mitigation."
        elif vulnerability_pct <= 70:
            verdict_badge = f"[bold red]{vulnerability_pct}% VULNERABLE (HIGH RISK)[/]"
            verdict_quote = f"Target exhibits {vulnerability_pct}% vulnerability exposure risk across multiple core attack surfaces. Immediate remediation is advised following the CISO roadmap."
        else:
            verdict_badge = f"[bold red]{vulnerability_pct}% VULNERABLE (CRITICAL RISK)[/]"
            verdict_quote = f"CRITICAL: Target exhibits {vulnerability_pct}% vulnerability exposure risk. Multiple high-severity misconfigurations or exposed surfaces require emergency triage within 24 hours."

        # Summary Header Panel
        summary_text = (
            f"[bold cyan]Audited Target:[/] {domain}\n"
            f"[bold white]Overall Security Grade:[/] [{grade_color} bold]{grade}[/] ({score}% Posture Score)\n"
            f"[bold white]SSL/TLS Status:[/] [green]{self.data.get('ssl_info', {}).get('protocol_version')}[/] (Expires in {self.data.get('ssl_info', {}).get('days_remaining')} days)\n"
            f"[bold white]Email Spoofing Defense:[/] [cyan]{self.data.get('email_sec', {}).get('dmarc_strength')}[/]\n"
            f"[bold white]Compliance Readiness:[/] [bold purple]{compliance_score}%[/] (PCI-DSS, ISO 27001, NIST, HIPAA)\n"
            f"[bold white]OWASP Top 10 (2021):[/] [bold blue]{owasp_score}%[/] ({self.data.get('owasp', {}).get('status', 'EVALUATED')})\n"
            f"[bold white]Public Secrets / Leaked Keys:[/] [bold {'red' if self.data.get('secret_results', {}).get('total_secrets_found', 0) > 0 else 'green'}]{self.data.get('secret_results', {}).get('total_secrets_found', 0)}[/]"
        )
        self.console.print(Panel(summary_text, title="[bold cyan]🛡️ AegisWeb Enterprise Security Summary[/]", border_style="cyan"))

        # Visual Security Controls Matrix (Green Ticks & Red Crosses)
        check_table = Table(title="[bold green]🛡️ Security Audit Controls Matrix[/]", show_header=True, header_style="bold cyan")
        check_table.add_column("Status", justify="center", width=14)
        check_table.add_column("Security Control Area", style="bold white")
        check_table.add_column("Audit Result & Assessment", style="dim")

        # 1. SSL/TLS
        ssl_info = self.data.get("ssl_info", {})
        if ssl_info.get("has_ssl") and not ssl_info.get("is_expired"):
            check_table.add_row("[bold green]✔ SECURE[/]", "SSL/TLS Encryption", f"{ssl_info.get('protocol_version')} - Valid certificate ({ssl_info.get('days_remaining')} days remaining)")
        else:
            check_table.add_row("[bold red]✖ VULNERABLE[/]", "SSL/TLS Encryption", "Invalid, expired, or missing SSL certificate")

        # 2. Defensive Headers
        headers_audit = self.data.get("headers_audit", {})
        if len(headers_audit.get("missing_headers", [])) == 0:
            check_table.add_row("[bold green]✔ SECURE[/]", "HTTP Defensive Headers", "All core headers (HSTS, CSP, X-Frame, X-Content-Type) active")
        else:
            missing_names = ", ".join([h["header"].split(" ")[0] for h in headers_audit.get("missing_headers", [])[:3]])
            check_table.add_row("[bold red]✖ VULNERABLE[/]", "HTTP Defensive Headers", f"Missing: {missing_names}")

        # 3. Email Spoofing
        email_sec = self.data.get("email_sec", {})
        if not email_sec.get("spoofing_vulnerable", True):
            check_table.add_row("[bold green]✔ SECURE[/]", "Email Spoofing Defense", f"DMARC policy active ({email_sec.get('dmarc_strength')})")
        else:
            check_table.add_row("[bold red]✖ VULNERABLE[/]", "Email Spoofing Defense", "Domain vulnerable to email spoofing / phishing impersonation")

        # 4. Sensitive Files
        exposed = self.data.get("exposed_files", [])
        if len(exposed) == 0:
            check_table.add_row("[bold green]✔ SECURE[/]", "Sensitive Files (.env, .git)", "No configuration or repository files exposed publicly")
        else:
            check_table.add_row("[bold red]✖ VULNERABLE[/]", "Sensitive Files (.env, .git)", f"{len(exposed)} sensitive files accessible to the public!")

        # 5. Secrets & API Keys
        secrets = self.data.get("secret_results", {}).get("leaks", [])
        if len(secrets) == 0:
            check_table.add_row("[bold green]✔ SECURE[/]", "Client-Side Secrets & API Keys", "No hardcoded credentials or private tokens in frontend source")
        else:
            check_table.add_row("[bold red]✖ VULNERABLE[/]", "Client-Side Secrets & API Keys", f"{len(secrets)} hardcoded API keys/tokens leaked in frontend code!")

        # 6. Admin Portals
        admin_portals = self.data.get("admin_portals", [])
        if len(admin_portals) == 0:
            check_table.add_row("[bold green]✔ SECURE[/]", "Administrative Portals", "No public admin gateways openly exposed")
        else:
            check_table.add_row("[bold yellow]✖ VULNERABLE[/]", "Administrative Portals", f"{len(admin_portals)} admin/dashboard gateways publicly reachable")

        self.console.print(check_table)

        # Executive Findings Table
        exec_findings = self.data.get("executive_findings", [])
        if exec_findings:
            table = Table(title="[bold yellow]👔 Executive Risk Findings (Plain-English)[/]", show_header=True, header_style="bold cyan")
            table.add_column("Priority", justify="center")
            table.add_column("Issue Title", style="bold white")
            table.add_column("Location / Source", style="cyan")
            table.add_column("Business Risk", style="dim")

            for f in exec_findings:
                sev = f.get("severity", "MEDIUM")
                sev_style = "bold red" if sev == "CRITICAL" else ("yellow" if sev == "HIGH" else "blue")
                loc = f.get("source_location", "Headers")
                if len(loc) > 30:
                    loc = "..." + loc[-27:]
                table.add_row(f"[{sev_style}]{sev}[/]", f.get("title", ""), loc, f.get("why_dangerous", "")[:50] + "...")

            self.console.print(table)

        # CISO Final Verdict Panel
        verdict_panel_text = (
            f"[bold white]Vulnerability Risk Index:[/] {verdict_badge}\n"
            f"[italic white]\"{verdict_quote}\"[/]\n\n"
            f"[dim]— Evaluated by Lead Security Architect [bold cyan]Saurabh (@Saura0S)[/][/]"
        )
        self.console.print(Panel(verdict_panel_text, title="[bold cyan]👨‍💻 Lead Security Architect Verdict (Saura0S)[/]", border_style="cyan"))

    def _resolve_target_dir(self, dest: str) -> str:
        """Ensure reports are always saved in the website's dedicated folder inside reports/ (e.g. reports/example.com/)."""
        domain = self.data.get("domain", "unknown_target").strip()
        safe_domain = domain.replace(":", "_").replace("/", "_").replace("\\", "_")

        if not dest or dest.strip() in ["reports", "reports/", ".", "./", ""]:
            return os.path.join("reports", safe_domain)

        # If dest is a filepath with an extension, extract dirname
        if os.path.splitext(dest)[1]:
            dest = os.path.dirname(dest) or os.path.join("reports", safe_domain)

        norm = os.path.normpath(dest)
        if not norm.endswith(safe_domain):
            return os.path.join(norm, safe_domain)

        return norm

    def interactive_export_menu(self, default_dir: str):
        """Prompt user interactively to select report save options and target directory."""
        resolved_default = self._resolve_target_dir(default_dir)
        if not self.console:
            self.export_all(resolved_default)
            return

        menu_text = (
            "[bold white][1][/] [bold green]🌟 Complete Executive Suite[/] (SPA HTML + Plain-English Brief + JSON + Patches)\n"
            "[bold white][2][/] [bold cyan]👔 Plain-English Client Summary[/] (.md for non-technical clients)\n"
            "[bold white][3][/] [bold blue]📄 Interactive SPA HTML Audit[/] (Single-Page App with PDF Print)\n"
            "[bold white][4][/] [bold yellow]💻 Technical Engineering JSON[/] (for DevSecOps / CI/CD)\n"
            "[bold white][5][/] [bold magenta]🛠️ Auto-Generated Remediation Patches[/] (Nginx, Apache, Caddy files)\n"
            "[bold white][6][/] [dim]❌ Exit without saving[/]"
        )
        self.console.print(Panel(menu_text, title="[bold cyan]💾 Save Audit Report Selection[/]", border_style="cyan"))

        choice = Prompt.ask("[bold cyan]👉 Select an option[/]", choices=["1", "2", "3", "4", "5", "6"], default="1")

        if choice == "6":
            self.console.print("[dim]Skipped saving reports.[/]")
            return

        # Prompt for destination folder (defaults to reports/<target_domain>)
        dest_input = Prompt.ask("[bold cyan]📁 Enter destination directory to save reports[/]", default=resolved_default)
        dest_dir = self._resolve_target_dir(dest_input)
        os.makedirs(dest_dir, exist_ok=True)

        if choice == "1":
            self.export_all(dest_dir)
        elif choice == "2":
            self.export_plain_text(os.path.join(dest_dir, "executive_summary.md"))
        elif choice == "3":
            self.export_html(os.path.join(dest_dir, "audit_report.html"))
        elif choice == "4":
            self.export_json(os.path.join(dest_dir, "scan_dataset.json"))
        elif choice == "5":
            self.export_patches(dest_dir)

    def export_all(self, target_dir: str):
        """Export HTML, plain-text markdown, JSON, and server patches into the website's dedicated directory."""
        target_dir = self._resolve_target_dir(target_dir)
        os.makedirs(target_dir, exist_ok=True)

        html_file = os.path.join(target_dir, "audit_report.html")
        plain_file = os.path.join(target_dir, "executive_summary.md")
        json_file = os.path.join(target_dir, "scan_dataset.json")
        nginx_file = os.path.join(target_dir, "nginx_patch.conf")
        apache_file = os.path.join(target_dir, "apache_patch.htaccess")
        caddy_file = os.path.join(target_dir, "caddy_patch.Caddyfile")

        self.export_html(html_file, quiet=True)
        self.export_plain_text(plain_file, quiet=True)
        self.export_json(json_file, quiet=True)

        with open(nginx_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("nginx_patch", ""))
        with open(apache_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("apache_patch", ""))
        with open(caddy_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("caddy_patch", ""))

        if self.console:
            tree_text = (
                f"[bold green]✔ All audit reports successfully saved to:[/] [bold cyan]{target_dir}[/]\n"
                f"  ├── 📄 [white]audit_report.html[/] [dim](Interactive SPA & PDF Print)[/]\n"
                f"  ├── 👔 [white]executive_summary.md[/] [dim](Plain-English CISO Brief)[/]\n"
                f"  ├── 💻 [white]scan_dataset.json[/] [dim](Technical CI/CD Dataset)[/]\n"
                f"  ├── 🛠️ [white]nginx_patch.conf[/] [dim](Nginx Remediation Patch)[/]\n"
                f"  ├── 🛠️ [white]apache_patch.htaccess[/] [dim](Apache Remediation Patch)[/]\n"
                f"  └── 🛠️ [white]caddy_patch.Caddyfile[/] [dim](Caddy Remediation Patch)[/]"
            )
            self.console.print(Panel(tree_text, title="[bold cyan]📁 Generated Security Dossier[/]", border_style="green"))
        else:
            print(f"[+] All reports exported to directory: {target_dir}")

    def export_patches(self, target_dir: str):
        """Save Nginx, Apache, and Caddy patch files into target directory."""
        target_dir = self._resolve_target_dir(target_dir)
        os.makedirs(target_dir, exist_ok=True)

        nginx_file = os.path.join(target_dir, "nginx_patch.conf")
        apache_file = os.path.join(target_dir, "apache_patch.htaccess")
        caddy_file = os.path.join(target_dir, "caddy_patch.Caddyfile")
        
        with open(nginx_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("nginx_patch", ""))
        with open(apache_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("apache_patch", ""))
        with open(caddy_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("caddy_patch", ""))

        if self.console:
            self.console.print(f"[bold green]✔[/] Ready-to-paste Nginx patch: [cyan]{nginx_file}[/]")
            self.console.print(f"[bold green]✔[/] Ready-to-paste Apache patch: [cyan]{apache_file}[/]")
            self.console.print(f"[bold green]✔[/] Ready-to-paste Caddy patch: [cyan]{caddy_file}[/]")

    def export_html(self, output_file: str, quiet: bool = False):
        """Generate interactive SPA HTML report with PDF print capabilities."""
        if not output_file.endswith(".html"):
            output_file = os.path.join(output_file, "audit_report.html")

        out_dir = os.path.dirname(output_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        score = self.data.get("score_percentage", 0)
        vulnerability_pct = max(0, min(100, 100 - score))
        
        template_vars = {
            "target_domain": self.data.get("domain", ""),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "grade": self.data.get("grade", "N/A"),
            "score_percentage": score,
            "vulnerability_pct": vulnerability_pct,
            "executive_findings": self.data.get("executive_findings", []),
            "ssl_info": self.data.get("ssl_info", {}),
            "email_sec": self.data.get("email_sec", {}),
            "headers_audit": self.data.get("headers_audit", {}),
            "compliance": self.data.get("compliance", {}),
            "owasp": self.data.get("owasp", {}),
            "secrets": self.data.get("secret_results", {}).get("leaks", []),
            "admin_portals": self.data.get("admin_portals", []),
            "exposed_files_count": len(self.data.get("exposed_files", [])),
            "nginx_patch": self.data.get("nginx_patch", ""),
            "apache_patch": self.data.get("apache_patch", ""),
            "caddy_patch": self.data.get("caddy_patch", "")
        }

        html_out = ""
        if JINJA_AVAILABLE:
            try:
                env = Environment(loader=FileSystemLoader(template_dir))
                template = env.get_template("report_template.html")
                html_out = template.render(template_vars)
            except Exception:
                pass

        if not html_out:
            template_path = os.path.join(template_dir, "report_template.html")
            if os.path.exists(template_path):
                with open(template_path, "r", encoding="utf-8") as f:
                    template_str = f.read()
                if JINJA_AVAILABLE:
                    template = Environment().from_string(template_str)
                    html_out = template.render(template_vars)
                else:
                    html_out = template_str

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_out)

        if self.console and not quiet:
            self.console.print(f"[bold green]✔[/] Interactive SPA HTML report generated: [cyan]{output_file}[/]")

    def export_plain_text(self, output_file: str, quiet: bool = False):
        """Generate client-ready plain English executive markdown/text document with code evidence locations."""
        if not output_file.endswith(".md") and not output_file.endswith(".txt"):
            output_file = os.path.join(output_file, "executive_summary.md")

        out_dir = os.path.dirname(output_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        score = self.data.get("score_percentage", 0)
        vulnerability_pct = max(0, min(100, 100 - score))
        
        if vulnerability_pct == 0:
            verdict_statement = "**0% VULNERABLE (Completely Safe / Hardened)**\n> \"The target demonstrates an ironclad defense posture (0% Vulnerability Risk). All critical defensive controls, encryption, and secret protections are fully active and compliant.\""
        else:
            verdict_statement = f"**{vulnerability_pct}% VULNERABLE**\n> \"Based on automated multi-vector heuristic auditing, the target exhibits a **{vulnerability_pct}% Vulnerability Exposure Risk** across {len(self.data.get('all_findings', []))} identified attack surfaces. Immediate remediation is advised following the CISO 30-day roadmap to reach 0% risk.\""

        lines = [
            f"# Executive Cybersecurity Risk Brief — {self.data.get('domain')}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Overall Security Grade: {self.data.get('grade')} ({score}% Posture Score)",
            f"Compliance Readiness Score: {self.data.get('compliance', {}).get('overall_governance_score', 0)}%",
            "Auditor: @Saura0S (Lead Security Architect | AegisWeb)\n",
            "## 👨‍💻 Final Security Verdict by Saurabh (@Saura0S)",
            f"{verdict_statement}\n",
            "## 📌 Executive Summary",
            "This report summarizes the security posture, business risks, secret leakages, and remediation roadmap identified during the automated audit.\n"
        ]

        for idx, item in enumerate(self.data.get("executive_findings", []), 1):
            lines.append(f"### {idx}. [{item['severity']} Priority] {item['title']}")
            lines.append(f"- **What is this issue?** {item['what_is_it']}")
            lines.append(f"- **Why is this dangerous for your website?** {item['why_dangerous']}")
            lines.append(f"- **📁 Exact File / Config Location Path:** `{item.get('file_navigation', item.get('source_location', 'Web Server / Headers'))}`")
            if item.get("code_snippet"):
                lines.append(f"- **🔍 Code Evidence Snippet:** `{item['code_snippet']}`")
            lines.append(f"- **💡 How to fix it?** {item['how_to_fix']}")
            if item.get("exact_code"):
                lines.append(f"- **🛠️ Exact Code to Apply:**\n```\n{item['exact_code']}\n```")
            lines.append(f"- **💼 Business Impact:** {item['business_impact']}\n")

        lines.append("## 🏆 OWASP Top 10 (2021) Standard Compliance Checklist")
        owasp_data = self.data.get("owasp", {})
        lines.append(f"OWASP Top 10 Posture Score: **{owasp_data.get('owasp_compliance_score', 0)}%** ({owasp_data.get('status', 'EVALUATED')})\n")
        
        for cat_id, cat in owasp_data.get("categories", {}).items():
            status_icon = "✔ PASS" if cat["status"] == "PASS" else "✖ FAIL"
            lines.append(f"- **[{status_icon}] {cat_id}: {cat['title']}**")
            lines.append(f"  - *Overview:* {cat['description']}")
            if cat["violations_count"] > 0:
                lines.append(f"  - *Violations Detected ({cat['violations_count']}):* " + ", ".join([v["title"] for v in cat["violations"]]))
                lines.append(f"  - *Remediation Action:* {cat['remediation']}")
            lines.append("")

        lines.append("## 🗺️ CISO 30-Day Phased Remediation Roadmap")
        lines.append("1. **Phase 1 (First 24 Hours)**: Enforce HTTPS & HSTS, revoke any leaked API keys, and block public access to `.env`/`.git`.")
        lines.append("2. **Phase 2 (Days 2 to 7)**: Deploy strict DMARC (`p=reject`) anti-spoofing policy, configure Content-Security-Policy (CSP) and X-Frame-Options.")
        lines.append("3. **Phase 3 (Days 8 to 30)**: Audit cookie `HttpOnly`/`SameSite` flags, integrate automated CI/CD scans with AegisWeb to maintain 0% vulnerability risk.")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        if self.console and not quiet:
            self.console.print(f"[bold green]✔[/] Plain-English Executive Summary exported: [cyan]{output_file}[/]")

    def export_json(self, output_file: str, quiet: bool = False):
        """Export structured JSON dataset with vulnerability percentage."""
        if not output_file.endswith(".json"):
            output_file = os.path.join(output_file, "scan_dataset.json")

        out_dir = os.path.dirname(output_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        score = self.data.get("score_percentage", 0)
        json_data = dict(self.data)
        json_data["vulnerability_exposure_percentage"] = max(0, min(100, 100 - score))
        json_data["auditor_verdict"] = f"Target exhibits {json_data['vulnerability_exposure_percentage']}% vulnerability exposure risk as evaluated by Saurabh (@Saura0S)."

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        if self.console and not quiet:
            self.console.print(f"[bold green]✔[/] Technical JSON dataset exported: [cyan]{output_file}[/]")