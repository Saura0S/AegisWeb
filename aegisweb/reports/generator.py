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
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from jinja2 import Environment, FileSystemLoader
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


class ReportGenerator:
    """Handles rendering interactive console output, JSON, Plain-Text & SPA HTML reports."""

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

        summary_text = (
            f"[bold cyan]Audited Target:[/] {domain}\n"
            f"[bold white]Overall Security Grade:[/] [{grade_color} bold]{grade}[/] ({score}% Score)\n"
            f"[bold white]SSL/TLS Status:[/] [green]{self.data.get('ssl_info', {}).get('protocol_version')}[/] (Expires in {self.data.get('ssl_info', {}).get('days_remaining')} days)\n"
            f"[bold white]Email Spoofing Defense:[/] [cyan]{self.data.get('email_sec', {}).get('dmarc_strength')}[/]\n"
            f"[bold white]Sensitive Files Exposed:[/] [red bold]{len(self.data.get('exposed_files', []))}[/]"
        )
        self.console.print(Panel(summary_text, title="[bold cyan]🛡️ AegisWeb Enterprise Security Summary[/]", border_style="cyan"))

        # Executive Findings Preview
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
            "exposed_files_count": len(self.data.get("exposed_files", [])),
            "nginx_patch": self.data.get("nginx_patch", ""),
            "apache_patch": self.data.get("apache_patch", "")
        }

        if JINJA_AVAILABLE:
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template("report_template.html")
            html_out = template.render(template_vars)
        else:
            template_path = os.path.join(template_dir, "report_template.html")
            with open(template_path, "r", encoding="utf-8") as f:
                html_out = f.read()

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
            "Auditor: @Saura0S (Powered by AegisWeb)\n",
            "## 📌 Executive Summary",
            "This report summarizes the security posture and business risks identified during the automated audit.\n"
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