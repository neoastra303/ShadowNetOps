"""Vulnerability Assessment Tool"""

import time
import random
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich.prompt import Prompt
from rich import box


class VulnScanner:
    def __init__(self, console: Console):
        self.console = console
        self.vulnerabilities = [
            {
                "title": "SQL Injection in Login Form",
                "severity": "CRITICAL",
                "cve": "CVE-2024-1234",
                "description": "Authentication bypass via SQL injection vulnerability",
                "color": "red"
            },
            {
                "title": "Outdated SSL/TLS Configuration",
                "severity": "HIGH",
                "cve": "CVE-2023-5678",
                "description": "Server supports weak cipher suites",
                "color": "red"
            },
            {
                "title": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "cve": "CVE-2024-3456",
                "description": "Reflected XSS in search parameter",
                "color": "red"
            },
            {
                "title": "Missing Security Headers",
                "severity": "MEDIUM",
                "cve": "N/A",
                "description": "X-Frame-Options and CSP headers not configured",
                "color": "yellow"
            },
            {
                "title": "Directory Listing Enabled",
                "severity": "MEDIUM",
                "cve": "N/A",
                "description": "Web server exposes directory contents",
                "color": "yellow"
            },
            {
                "title": "Information Disclosure",
                "severity": "LOW",
                "cve": "CVE-2023-9012",
                "description": "Server version exposed in HTTP headers",
                "color": "cyan"
            },
            {
                "title": "Weak Password Policy",
                "severity": "LOW",
                "cve": "N/A",
                "description": "System allows weak passwords",
                "color": "cyan"
            },
        ]
        
    def scan_vulnerabilities(self, target: str):
        """Simulate vulnerability scanning"""
        self.console.print(Panel(
            f"[bold cyan]Scanning: [green]{target}[/green][/bold cyan]\n"
            "[dim]Checking CVE database and security configurations...[/dim]",
            border_style="cyan"
        ))
        self.console.print()
        
        # Simulate scanning
        found_vulns = []
        for vuln in track(self.vulnerabilities, description="[cyan]Analyzing vulnerabilities..."):
            time.sleep(0.15)
            if random.random() > 0.3:  # 70% chance to find each vulnerability
                found_vulns.append(vuln)
        
        # Display results
        table = Table(
            title="[bold cyan]Vulnerability Assessment Results[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        
        table.add_column("Severity", justify="center", style="bold")
        table.add_column("Title", style="white")
        table.add_column("CVE", style="cyan")
        table.add_column("Description", style="dim")
        
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for vuln in found_vulns:
            severity_display = f"[{vuln['color']}]{vuln['severity']}[/{vuln['color']}]"
            
            table.add_row(
                severity_display,
                vuln["title"],
                vuln["cve"],
                vuln["description"]
            )
            
            if vuln["severity"] == "CRITICAL":
                critical_count += 1
            elif vuln["severity"] == "HIGH":
                high_count += 1
            elif vuln["severity"] == "MEDIUM":
                medium_count += 1
            else:
                low_count += 1
        
        self.console.print(table)
        self.console.print()
        
        # Summary
        self.console.print(Panel(
            f"[bold red]Critical:[/bold red] {critical_count}  "
            f"[bold red]High:[/bold red] {high_count}  "
            f"[bold yellow]Medium:[/bold yellow] {medium_count}  "
            f"[bold cyan]Low:[/bold cyan] {low_count}\n"
            f"[bold]Total:[/bold] {len(found_vulns)} vulnerabilities found",
            title="[bold cyan]Summary[/bold cyan]",
            border_style="cyan"
        ))
        
    def run(self):
        """Run vulnerability assessment"""
        self.console.print("[bold cyan]═══ Vulnerability Assessment ═══[/bold cyan]")
        self.console.print()
        
        target = Prompt.ask(
            "[cyan]Enter target to assess[/cyan]",
            default="example.com"
        )
        
        if not target or target.strip() == "":
            self.console.print("[bold red]✗ Error:[/bold red] Invalid target")
            return
        
        self.console.print()
        self.scan_vulnerabilities(target)
