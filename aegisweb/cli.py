"""
AegisWeb - Enterprise CLI Entrypoint
"""

import sys
import os
import argparse
import time
from urllib.parse import urlparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Force UTF-8 on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from aegisweb.scanner.ssl_checker import SSLChecker
from aegisweb.scanner.headers_auditor import HeadersAuditor
from aegisweb.scanner.cookie_auditor import CookieAuditor
from aegisweb.scanner.email_sec_auditor import EmailSecurityAuditor
from aegisweb.scanner.exposure_checker import ExposureChecker
from aegisweb.scanner.takeover_detector import TakeoverDetector
from aegisweb.scanner.crawler import LightweightCrawler
from aegisweb.reports.plain_english import PlainEnglishTranslator
from aegisweb.reports.patch_generator import PatchGenerator
from aegisweb.reports.generator import ReportGenerator

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

BANNER = r"""[bold cyan]
     _             _    __      __   _     
    /_\  ___  __ _(_)___\ \    / /__| |__  
   / _ \/ -_)/ _` | (_-< \ \/\/ / -_) '_ \ 
  /_/ \_\___|\__, |_/__/  \_/\_/\___|_.__/ 
             |___/                         
[/][bold dim]
  Enterprise Web Vulnerability Auditor & Dual-Report Engine | Built by @Saura0S v1.0.0
[/]"""


def normalize_target(target: str):
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0]
    base_url = f"{parsed.scheme}://{domain}"
    return domain, base_url


def main():
    parser = argparse.ArgumentParser(
        description="AegisWeb — Enterprise Web Vulnerability & Posture Auditor",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL or domain to audit (e.g. example.com)")
    parser.add_argument("--html", action="store_true", help="Generate interactive SPA HTML report with PDF print support")
    parser.add_argument("--plain", action="store_true", help="Export client-ready Plain-English Executive Summary (.md)")
    parser.add_argument("--json", action="store_true", help="Export full technical JSON dataset")
    parser.add_argument("--all-reports", action="store_true", help="Generate HTML, Plain-English, and JSON reports simultaneously")
    parser.add_argument("--crawl", action="store_true", help="Enable internal route & auth portal crawler")
    parser.add_argument("-o", "--output", type=str, default=None, help="Custom output filename or prefix")
    parser.add_argument("--timeout", type=int, default=6, help="Network timeout in seconds (default: 6)")
    parser.add_argument("-v", "--version", action="version", version="AegisWeb v1.0.0 (by @Saura0S)")

    args = parser.parse_args()
    domain, base_url = normalize_target(args.url)

    console = Console(legacy_windows=False) if RICH_AVAILABLE else None

    if console:
        console.print(BANNER)
        console.print(f"[bold cyan]🔍 Target Domain:[/] [white]{domain}[/] | [bold cyan]Base URL:[/] [white]{base_url}[/]\n")
    else:
        print(f"AegisWeb — Auditing {domain} ({base_url})\n")

    start_time = time.time()
    all_findings = []

    # 1. SSL/TLS Audit
    if console:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
            progress.add_task(description="[cyan]1/6 Auditing SSL/TLS encryption & certificate health...", total=None)
            ssl_auditor = SSLChecker(timeout=args.timeout)
            ssl_info = ssl_auditor.audit(domain)
    else:
        print("[*] 1/6 Auditing SSL/TLS certificate...")
        ssl_auditor = SSLChecker(timeout=args.timeout)
        ssl_info = ssl_auditor.audit(domain)

    all_findings.extend(ssl_info.get("findings", []))

    # 2. Fetch HTTP Headers and Cookie Inspection
    headers_dict = {}
    raw_cookies = []
    try:
        resp = requests.get(base_url, timeout=args.timeout, verify=False, allow_redirects=True)
        headers_dict = dict(resp.headers)
        raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
    except Exception:
        pass

    # Defensive Headers Audit
    headers_auditor = HeadersAuditor()
    headers_audit = headers_auditor.audit(headers_dict)
    all_findings.extend(headers_audit.get("missing_headers", []))
    all_findings.extend(headers_audit.get("cors_issues", []))

    # 3. Cookie Audit
    cookie_auditor = CookieAuditor()
    cookie_results = cookie_auditor.audit(raw_cookies)
    all_findings.extend(cookie_results.get("findings", []))

    # 4. Email Security (SPF & DMARC)
    if console:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
            progress.add_task(description="[cyan]3/6 Auditing email spoofing defense (SPF/DMARC)...", total=None)
            email_auditor = EmailSecurityAuditor(timeout=args.timeout)
            email_sec = email_auditor.audit(domain)
    else:
        print("[*] 3/6 Auditing email spoofing defense...")
        email_auditor = EmailSecurityAuditor(timeout=args.timeout)
        email_sec = email_auditor.audit(domain)

    all_findings.extend(email_sec.get("findings", []))

    # 5. Sensitive File Exposure Check
    if console:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
            progress.add_task(description="[cyan]4/6 Scanning for publicly exposed configuration files...", total=None)
            exposure_checker = ExposureChecker(timeout=args.timeout)
            exposure_results = exposure_checker.audit(base_url)
    else:
        print("[*] 4/6 Scanning for exposed sensitive files...")
        exposure_checker = ExposureChecker(timeout=args.timeout)
        exposure_results = exposure_checker.audit(base_url)

    all_findings.extend(exposure_results.get("findings", []))

    # 6. Optional Crawler
    crawl_data = {}
    if args.crawl:
        if console:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
                progress.add_task(description="[cyan]5/6 Crawling internal pages & authentication portals...", total=None)
                crawler = LightweightCrawler(timeout=args.timeout)
                crawl_data = crawler.crawl(base_url)
        else:
            print("[*] 5/6 Crawling internal pages...")
            crawler = LightweightCrawler(timeout=args.timeout)
            crawl_data = crawler.crawl(base_url)

    # 7. Plain-English Executive Translation
    translator = PlainEnglishTranslator()
    executive_findings = translator.generate_executive_brief(all_findings)

    # 8. Patch Generation
    patch_gen = PatchGenerator()
    nginx_patch = patch_gen.generate_nginx_config(headers_audit.get("missing_headers", []))
    apache_patch = patch_gen.generate_apache_config(headers_audit.get("missing_headers", []))

    # Overall Scoring
    total_deductions = sum(25 if f.get("severity") == "CRITICAL" else (15 if f.get("severity") == "HIGH" else (8 if f.get("severity") == "MEDIUM" else 3)) for f in all_findings)
    final_score = max(5, 100 - total_deductions)
    final_grade = "A+" if final_score >= 95 else ("A" if final_score >= 85 else ("B" if final_score >= 70 else ("C" if final_score >= 55 else ("D" if final_score >= 40 else "F"))))

    report_payload = {
        "domain": domain,
        "base_url": base_url,
        "scan_time_seconds": round(time.time() - start_time, 2),
        "grade": final_grade,
        "score_percentage": final_score,
        "ssl_info": ssl_info,
        "headers_audit": headers_audit,
        "cookie_results": cookie_results,
        "email_sec": email_sec,
        "exposed_files": exposure_results.get("exposed_files", []),
        "crawl_data": crawl_data,
        "executive_findings": executive_findings,
        "all_findings": all_findings,
        "nginx_patch": nginx_patch,
        "apache_patch": apache_patch
    }

    # Render Terminal Output
    generator = ReportGenerator(report_payload)
    generator.print_terminal_dashboard()

    # Handle Exports
    prefix = args.output or f"aegisweb_{domain.replace('.', '_')}"
    
    if args.all_reports or args.html or (not args.plain and not args.json and not args.output):
        generator.export_html(f"{prefix}.html")

    if args.all_reports or args.plain:
        generator.export_plain_text(f"{prefix}_executive_summary.md")

    if args.all_reports or args.json:
        generator.export_json(f"{prefix}.json")

    if console:
        console.print(f"\n[bold green]✔[/] AegisWeb Audit Completed in [cyan]{report_payload['scan_time_seconds']}s[/]!\n")


if __name__ == "__main__":
    main()