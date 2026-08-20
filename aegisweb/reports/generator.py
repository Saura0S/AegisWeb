"""
Report Orchestrator & Exporter Module
"""

import os
import json
from datetime import datetime
from typing import Dict, Any

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
        """Display formatted terminal dashboard."""
        if not self.console:
            print(f"\n--- AegisWeb Security Audit: {self.data.get('domain')} ---")
            print(f"Grade: {self.data.get('grade')} ({self.data.get('score_percentage')}%)")
            return

        domain = self.data.get("domain", "")
        grade = self.data.get("grade", "N/A")
        score = self.data.get("score_percentage", 0)
        grade_color = "green" if grade in ["A+", "A"] else ("yellow" if grade in ["B", "C"] else "red")
        compliance_score = self.data.get("compliance", {}).get("overall_governance_score", 0)

        summary_text = (
            f"[bold cyan]Audited Target:[/] {domain}\n"
            f"[bold white]Overall Security Grade:[/] [{grade_color} bold]{grade}[/] ({score}% Posture Score)\n"
            f"[bold white]SSL/TLS Status:[/] [green]{self.data.get('ssl_info', {}).get('protocol_version')}[/] (Expires in {self.data.get('ssl_info', {}).get('days_remaining')} days)\n"
            f"[bold white]Email Spoofing Defense:[/] [cyan]{self.data.get('email_sec', {}).get('dmarc_strength')}[/]\n"
            f"[bold white]Compliance Readiness:[/] [bold purple]{compliance_score}%[/] (PCI-DSS, ISO 27001, NIST, HIPAA)\n"
            f"[bold white]Sensitive Files Exposed:[/] [red bold]{len(self.data.get('exposed_files', []))}[/]"
        )
        self.console.print(Panel(summary_text, title="[bold cyan]🛡️ AegisWeb Enterprise Security Summary[/]", border_style="cyan"))

        # Executive Findings Table
        exec_findings = self.data.get("executive_findings", [])
        if exec_findings:
            table = Table(title="[bold yellow]👔 Executive Risk Findings (Plain-English)[/]", show_header=True, header_style="bold cyan")
            table.add_column("Priority", justify="center")
            table.add_column("Issue Title", style="bold white")
            table.add_column("Business Risk", style="dim")

            for f in exec_findings:
                sev = f.get("severity", "MEDIUM")
                sev_style = "bold red" if sev == "CRITICAL" else ("yellow" if sev == "HIGH" else "blue")
                table.add_row(f"[{sev_style}]{sev}[/]", f.get("title", ""), f.get("why_dangerous", "")[:65] + "...")

            self.console.print(table)

    def interactive_export_menu(self, prefix: str):
        """Prompt user interactively to select report save options."""
        if not self.console:
            self.export_all(prefix)
            return

        menu_text = (
            "[bold white][1][/] [bold green]🌟 Complete Executive Suite[/] (SPA HTML + Plain-English Brief + JSON)\n"
            "[bold white][2][/] [bold cyan]👔 Plain-English Client Summary[/] (.md for non-technical clients)\n"
            "[bold white][3][/] [bold blue]📄 Interactive SPA HTML Audit[/] (Single-Page App with PDF Print)\n"
            "[bold white][4][/] [bold yellow]💻 Technical Engineering JSON[/] (for DevSecOps / CI/CD)\n"
            "[bold white][5][/] [bold magenta]🛠️ Auto-Generated Remediation Patches[/] (Nginx & Apache files)\n"
            "[bold white][6][/] [dim]❌ Exit without saving[/]"
        )
        self.console.print(Panel(menu_text, title="[bold cyan]💾 Save Audit Report Selection[/]", border_style="cyan"))

        choice = Prompt.ask("[bold cyan]👉 Select an option[/]", choices=["1", "2", "3", "4", "5", "6"], default="1")

        if choice == "1":
            self.export_all(prefix)
        elif choice == "2":
            self.export_plain_text(f"{prefix}_executive_summary.md")
        elif choice == "3":
            self.export_html(f"{prefix}.html")
        elif choice == "4":
            self.export_json(f"{prefix}.json")
        elif choice == "5":
            self.export_patches(prefix)
        elif choice == "6":
            self.console.print("[dim]Skipped saving reports.[/]")

    def export_all(self, prefix: str):
        """Export HTML, plain-text markdown, JSON, and server patches."""
        self.export_html(f"{prefix}.html")
        self.export_plain_text(f"{prefix}_executive_summary.md")
        self.export_json(f"{prefix}.json")
        self.export_patches(prefix)

    def export_patches(self, prefix: str):
        """Save Nginx and Apache patch files."""
        nginx_file = f"{prefix}_nginx_patch.conf"
        apache_file = f"{prefix}_apache_patch.htaccess"
        
        with open(nginx_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("nginx_patch", ""))
        with open(apache_file, "w", encoding="utf-8") as f:
            f.write(self.data.get("apache_patch", ""))

        if self.console:
            self.console.print(f"[bold green]✔[/] Ready-to-paste Nginx patch exported: [cyan]{nginx_file}[/]")
            self.console.print(f"[bold green]✔[/] Ready-to-paste Apache patch exported: [cyan]{apache_file}[/]")

    def export_html(self, output_file: str):
        """Generate interactive SPA HTML report with PDF print capabilities."""
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        
        template_vars = {
            "target_domain": self.data.get("domain", ""),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "grade": self.data.get("grade", "N/A"),
            "score_percentage": self.data.get("score_percentage", 0),
            "executive_findings": self.data.get("executive_findings", []),
            "ssl_info": self.data.get("ssl_info", {}),
            "email_sec": self.data.get("email_sec", {}),
            "headers_audit": self.data.get("headers_audit", {}),
            "compliance": self.data.get("compliance", {}),
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

        if self.console:
            self.console.print(f"[bold green]✔[/] Interactive SPA HTML report generated: [cyan]{output_file}[/]")

    def export_plain_text(self, output_file: str):
        """Generate client-ready plain English executive markdown/text document."""
        lines = [
            f"# Executive Cybersecurity Risk Brief — {self.data.get('domain')}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Overall Security Grade: {self.data.get('grade')} ({self.data.get('score_percentage')}%)",
            f"Compliance Readiness Score: {self.data.get('compliance', {}).get('overall_governance_score', 0)}%",
            "Auditor: @Saura0S (Lead Security Architect | AegisWeb)\n",
            "## 📌 Executive Summary",
            "This report summarizes the security posture, business risks, and remediation roadmap identified during the automated audit.\n"
        ]

        for idx, item in enumerate(self.data.get("executive_findings", []), 1):
            lines.append(f"### {idx}. [{item['severity']} Priority] {item['title']}")
            lines.append(f"- **What is this issue?** {item['what_is_it']}")
            lines.append(f"- **Why is this dangerous for your website?** {item['why_dangerous']}")
            lines.append(f"- **How to fix it?** {item['how_to_fix']}")
            lines.append(f"- **Business Impact:** {item['business_impact']}\n")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        if self.console:
            self.console.print(f"[bold green]✔[/] Plain-English Executive Summary exported: [cyan]{output_file}[/]")

    def export_json(self, output_file: str):
        """Export structured JSON dataset."""
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

        if self.console:
            self.console.print(f"[bold green]✔[/] Technical JSON dataset exported: [cyan]{output_file}[/]")