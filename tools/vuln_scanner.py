"""Vulnerability Assessment Tool"""

import time
import random
import subprocess
import requests
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich.prompt import Prompt
from rich import box
from .base_tool import BaseTool


class VulnScanner(BaseTool):
    def __init__(self, console: Console):
        super().__init__(console)
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
        for vuln in track(self.vulnerabilities, description="[cyan]Analyzing vulnerabilities...\n"):
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
    
    def nmap_vuln_scan(self, target: str):
        """Perform vulnerability scan using nmap scripts"""
        self.console.print(f"[cyan]Running nmap vulnerability scan on [green]{target}[/green][/cyan]")
        
        try:
            result = subprocess.run(['nmap', '--script', 'vuln', target], 
                                  capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                output = result.stdout
                # Parse nmap output to find vulnerabilities
                vuln_lines = []
                for line in output.split('\n'):
                    if 'VULNERABLE' in line or 'http-vuln' in line or 'cve' in line.lower():
                        vuln_lines.append(line.strip())
                
                if vuln_lines:
                    self.console.print(f"[bold green]Found {len(vuln_lines)} potential vulnerabilities:[/bold green]")
                    for line in vuln_lines:
                        self.console.print(f"  [yellow]{line}[/yellow]")
                else:
                    self.console.print("[green]No obvious vulnerabilities detected by nmap scripts.[/green]")
            else:
                self.console.print(f"[red]Nmap vulnerability scan returned code {result.returncode}[/red]")
        except subprocess.TimeoutExpired:
            self.console.print("[red]Nmap scan timed out.[/red]")
        except FileNotFoundError:
            self.console.print("[red]nmap not found. Install nmap for advanced vulnerability scanning.[/red]")
        except Exception as e:
            self.console.print(f"[red]Error during nmap vulnerability scan: {e}[/red]")
    
    def ssl_scan(self, target: str):
        """Perform SSL/TLS security scan using testssl.sh if available"""
        import os
        
        self.console.print(f"[cyan]Running SSL/TLS security scan on [green]{target}[/green][/cyan]")
        
        # First, try to find testssl.sh in common locations
        testssl_locations = [
            '/usr/bin/testssl.sh',
            '/opt/testssl/testssl.sh',
            'testssl.sh'
        ]
        
        testssl_path = None
        for path in testssl_locations:
            if os.path.isfile(path):
                testssl_path = path
                break
        
        if testssl_path:
            try:
                result = subprocess.run([testssl_path, '--severity', 'HIGH', target], 
                                      capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    output = result.stdout
                    # Look for specific security issues in testssl output
                    issues = []
                    for line in output.split('\n'):
                        if 'vulnerable' in line.lower() or 'weak' in line.lower() or 'insecure' in line.lower():
                            issues.append(line.strip())
                    
                    if issues:
                        self.console.print(f"[bold red]Found {len(issues)} SSL/TLS security issues:[/bold red]")
                        for issue in issues:
                            self.console.print(f"  [red]{issue}[/red]")
                    else:
                        self.console.print("[green]No major SSL/TLS security issues detected.[/green]")
                else:
                    self.console.print(f"[red]testssl.sh returned code {result.returncode}[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[red]SSL scan timed out.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error during SSL scan: {e}[/red]")
        else:
            self.console.print("[red]testssl.sh not found. Download from https://github.com/drwetter/testssl.sh for SSL/TLS scanning.[/red]")
    
    def nikto_scan(self, target: str):
        """Perform web vulnerability scan using Nikto"""
        self.console.print(f"[cyan]Running Nikto web vulnerability scan on [green]{target}[/green][/cyan]")
        
        try:
            result = subprocess.run(['nikto', '-h', target], 
                                  capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                output = result.stdout
                # Count potential vulnerabilities found by Nikto
                vuln_count = 0
                for line in output.split('\n'):
                    if '+ OSVDB' in line or 'vulnerability' in line.lower() or 'potential' in line.lower():
                        vuln_count += 1
                
                if vuln_count > 0:
                    self.console.print(f"[bold red]Nikto found {vuln_count} potential vulnerabilities.[/bold red]")
                else:
                    self.console.print("[green]Nikto scan completed - no major vulnerabilities detected.[/green]")
            else:
                self.console.print(f"[red]Nikto scan returned code {result.returncode}[/red]")
        except subprocess.TimeoutExpired:
            self.console.print("[red]Nikto scan timed out.[/red]")
        except FileNotFoundError:
            self.console.print("[red]nikto not found. Install nikto for web vulnerability scanning.[/red]")
        except Exception as e:
            self.console.print(f"[red]Error during Nikto scan: {e}[/red]")
    
    def cve_lookup(self, target: str):
        """Look up known CVEs for the target"""
        # For demo purposes, we'll show what CVE lookup would do
        self.console.print(f"[cyan]Looking up known CVEs for [green]{target}[/green][/cyan]")
        
        # In a real implementation, we would query the CVE database
        # For now, we'll just show some common CVEs that might affect web services
        common_cves = [
            {"cve": "CVE-2023-2023", "product": "Apache", "description": "Information disclosure vulnerability"},
            {"cve": "CVE-2022-2022", "product": "Nginx", "description": "Remote code execution vulnerability"},
            {"cve": "CVE-2021-2021", "product": "OpenSSL", "description": "Memory corruption vulnerability"},
            {"cve": "CVE-2020-2020", "product": "PHP", "description": "Remote code execution in session handling"}
        ]
        
        self.console.print("[yellow]Note: Real CVE lookup requires querying a CVE database API[/yellow]")
        self.console.print("[dim]Here are some common CVEs that might affect web services:[/dim]")
        
        for cve in common_cves:
            self.console.print(f"  [cyan]{cve['cve']}[/cyan] - {cve['product']}: {cve['description']}")
    
    def run(self):
        """Run vulnerability assessment with multiple options"""
        self.display_header("Vulnerability Assessment")
        
        # Add submenu for different types of vulnerability scans
        vuln_table = Table(
            title="[bold cyan]Vulnerability Assessment Options[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        vuln_table.add_column("ID", style="cyan", justify="center")
        vuln_table.add_column("Scan Type", style="green")
        vuln_table.add_column("Description", style="white")
        vuln_table.add_row("1", "General Vulnerability Scan", "Basic vulnerability assessment")
        vuln_table.add_row("2", "Nmap Script Scan", "Scan with nmap vulnerability scripts")
        vuln_table.add_row("3", "SSL/TLS Security Scan", "Check for SSL/TLS misconfigurations")
        vuln_table.add_row("4", "Web Vulnerability Scan", "Scan web applications with Nikto")
        vuln_table.add_row("5", "CVE Lookup", "Lookup known CVEs for target")
        vuln_table.add_row("6", "Back to Main Menu", "Return to main menu")
        
        self.console.print(vuln_table)
        choice = Prompt.ask("Choose a vulnerability assessment method", choices=["1", "2", "3", "4", "5", "6"], default="1")
        
        if choice == "6":
            return
        
        target = Prompt.ask(
            "[cyan]Enter target to assess[/cyan]",
            default="example.com"
        )
        
        if not target or target.strip() == "":
            self.display_result("Invalid target", "error")
            return
        
        # Add consent prompt for educational purpose
        self.console.print("[yellow]⚠[/yellow] This tool performs actual vulnerability scanning for educational purposes only.")
        self.console.print("[yellow]⚠[/yellow] Always ensure you have proper authorization before scanning any system.")
        consent = Prompt.ask("[bold magenta]Do you have explicit written consent to scan this target? (yes/no)[/bold magenta]", default="no")
        if consent.lower() not in ['yes', 'y', 'true']:
            self.display_result("Scan cancelled - explicit consent required", "warning")
            return
        
        self.console.print()
        
        if choice == "1":
            self.scan_vulnerabilities(target)
        elif choice == "2":
            self.nmap_vuln_scan(target)
        elif choice == "3":
            self.ssl_scan(target)
        elif choice == "4":
            self.nikto_scan(target)
        elif choice == "5":
            self.cve_lookup(target)