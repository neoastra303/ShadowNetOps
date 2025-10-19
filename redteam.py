#!/usr/bin/env python3
"""
RedTeam Terminal - Cybersecurity Operations CLI
A cyberpunk-themed terminal tool for penetration testing and security operations
"""

import sys
import re
import subprocess
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from pyfiglet import figlet_format
from colorama import init as colorama_init

# Import tool modules
from tools.network_recon import NetworkRecon
from tools.vuln_scanner import VulnScanner
from tools.password_tester import PasswordTester
from tools.osint_tools import OSINTTools
from tools.social_engineering import SocialEngineeringToolkit
from tools.forensics import ForensicsTools
from tools.reporting import ReportingModule
from tools.misc_utils import MiscUtilities
from tools.dependency_manager import get_dependency_manager

colorama_init()
console = Console()


class RedTeamTerminal:
    def __init__(self):
        self.console = console
        self.network_recon = NetworkRecon(console)
        self.vuln_scanner = VulnScanner(console)
        self.password_tester = PasswordTester(console)
        self.osint_tools = OSINTTools(console)
        self.social_engineering = SocialEngineeringToolkit(console)
        self.forensics = ForensicsTools(console)
        self.reporting = ReportingModule(console)
        self.misc_utils = MiscUtilities(console)
        self.dependency_manager = get_dependency_manager(console)

    def display_banner(self) -> None:
        """Display cyberpunk ASCII art banner"""
        banner = figlet_format("RedTeam", font="slant")
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        self.console.print(
            Panel(
                "Terminal v2.1.0\n"
                "Cybersecurity Operations Platform\n"
                "Network Recon | Vuln Assessment | Password Testing | OSINT",
                title="[bold magenta]RedTeam Terminal[/bold magenta]",
                border_style="cyan",
                box=box.DOUBLE,
            )
        )
        self.console.print()

    def display_menu(self) -> None:
        table = Table(
            title="[bold cyan]Available Tools & Categories[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED,
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool/Category", style="green")
        table.add_column("Description", style="white")
        table.add_row(
            "1", "Network Reconnaissance", "Port scanning, host discovery, service detection, OS fingerprinting"
        )
        table.add_row(
            "2", "Vulnerability Assessment", "CVE scanning, web vulnerability testing, configuration checks"
        )
        table.add_row("3", "Password Strength Tester", "Analyze password security and crack time estimation")
        table.add_row("4", "OSINT Tools", "Email, username, domain, and social media research tools")
        table.add_row(
            "5",
            "Social Engineering Toolkit",
            "Phishing, pretexting, credential harvesting, spear phishing campaigns"
        )
        table.add_row("6", "Forensics", "Disk, memory, network, and log analysis tools")
        table.add_row("7", "Reporting", "Generate and export assessment reports (PDF, JSON, CSV)")
        table.add_row("8", "Miscellaneous Utilities", "Encoding/decoding, hash generation, network utilities")
        table.add_row(
            "9", "Web Attack Tools", "SQLi, XSS, CSRF, subdomain discovery, tech stack detection"
        )
        table.add_row(
            "10",
            "Wireless Attack Tools",
            "WiFi scanning, WPA cracking, Bluetooth analysis, deauth attacks"
        )
        table.add_row("11", "Exit", "Quit the terminal")
        self.console.print(table)
        self.console.print()

    def validate_target(self, target: str) -> bool:
        """Validate target input to prevent command injection and ensure proper format"""
        # Basic validation for IP addresses and domain names
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/(\d|[1-2]\d|3[0-2]))?$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if re.match(ip_pattern, target) or re.match(domain_pattern, target):
            # Additional check to prevent command injection
            dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '||', '&&']
            if any(char in target for char in dangerous_chars):
                return False
            return True
        return False

    def check_dependencies(self, category: str) -> bool:
        """Check if required dependencies for a category are installed"""
        missing_tools = self.dependency_manager.get_missing_tools(category)
        
        if missing_tools:
            self.console.print(f"\n[bold yellow]⚠ Missing tools for {category}:[/bold yellow]")
            for tool in missing_tools:
                self.console.print(f"  - [red]{tool}[/red]")
            
            self.console.print(f"\n[yellow]These tools need to be installed for {category} functionality.[/yellow]")
            
            # Ask user if they want to install the missing tools
            install_choice = Prompt.ask(
                "[bold magenta]Would you like to attempt to install the missing tools? (yes/no)[/bold magenta]", 
                default="no"
            )
            
            if install_choice.lower() in ['yes', 'y', 'true']:
                success = self.dependency_manager.install_missing_tools(category)
                return success
            else:
                self.console.print("[yellow]Please install required tools before proceeding.[/yellow]")
                return False
        else:
            self.console.print(f"\n[bold green]✓ All required tools for {category} are installed![/bold green]")
            return True

    def osint_tools_menu(self) -> None:
        # Check for dependencies before showing the menu
        all_installed = self.check_dependencies('osint')
        if not all_installed:
            self.console.print("[yellow]Some tools may not function without required dependencies.[/yellow]")
            continue_anyway = Prompt.ask("[bold magenta]Continue anyway? (yes/no)[/bold magenta]", default="no")
            if continue_anyway.lower() not in ['yes', 'y', 'true']:
                return
        
        table = Table(
            title="[bold cyan]OSINT Tools[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED,
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white")
        table.add_row("1", "holehe", "Check email address usage across sites")
        table.add_row("2", "h8mail", "Email OSINT and breach lookup")
        table.add_row("3", "sherlock", "Find usernames across social networks")
        table.add_row("4", "theHarvester", "Gather emails, subdomains, hosts, etc.")
        table.add_row("5", "Back", "Return to main menu")
        self.console.print(table)
        choice = Prompt.ask("Choose an OSINT tool", choices=["1", "2", "3", "4", "5"])
        
        if choice == "1":
            email = Prompt.ask("Enter email address to check")
            # Validate email format
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                self.console.print("[red]Invalid email address format[/red]")
                return
            self.console.print(f"[cyan]Running holehe for {email}...[/cyan]")
            try:
                result = subprocess.run(["holehe", email], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from holehe.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running holehe: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]holehe command not found. Please install holehe.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running holehe: {e}[/red]")
        elif choice == "2":
            email = Prompt.ask("Enter email address for breach lookup")
            # Validate email format
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                self.console.print("[red]Invalid email address format[/red]")
                return
            self.console.print(f"[cyan]Running h8mail for {email}...[/cyan]")
            try:
                result = subprocess.run(["h8mail", "-t", email], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from h8mail.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running h8mail: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]h8mail command not found. Please install h8mail.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running h8mail: {e}[/red]")
        elif choice == "3":
            username = Prompt.ask("Enter username to search")
            # Validate username doesn't contain dangerous characters
            if any(char in username for char in [';', '&', '|', '`', '$', '(', ')', '<', '>', '||', '&&']):
                self.console.print("[red]Invalid username format[/red]")
                return
            self.console.print(f"[cyan]Running sherlock for {username}...[/cyan]")
            try:
                result = subprocess.run(["sherlock", username], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from sherlock.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running sherlock: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]sherlock command not found. Please install sherlock.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running sherlock: {e}[/red]")
        elif choice == "4":
            query = Prompt.ask("Enter domain, email, or IP for theHarvester")
            if not self.validate_target(query):
                self.console.print("[red]Invalid query format. Please enter a valid domain, email, or IP.[/red]")
                return
            self.console.print(f"[cyan]Running theHarvester for {query}...[/cyan]")
            try:
                result = subprocess.run(["theHarvester", "-d", query, "-b", "all"], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from theHarvester.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running theHarvester: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]theHarvester command not found. Please install theHarvester.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running theHarvester: {e}[/red]")
        elif choice == "5":
            return

    def web_attack_tools_menu(self) -> None:
        # Check for dependencies before showing the menu
        all_installed = self.check_dependencies('web')
        if not all_installed:
            self.console.print("[yellow]Some tools may not function without required dependencies.[/yellow]")
            continue_anyway = Prompt.ask("[bold magenta]Continue anyway? (yes/no)[/bold magenta]", default="no")
            if continue_anyway.lower() not in ['yes', 'y', 'true']:
                return
        
        table = Table(
            title="[bold cyan]Web Attack Tools[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED,
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white")
        table.add_row("1", "SQL Injection Scanner", "Detect SQLi vulnerabilities (sqlmap)")
        table.add_row("2", "XSS Tester", "Test for XSS flaws (XSStrike)")
        table.add_row("3", "CSRF PoC Generator", "Create CSRF proof-of-concept (demo)")
        table.add_row("4", "Directory Brute Force", "Find hidden directories (ffuf)")
        table.add_row("5", "Nikto Web Scanner", "Comprehensive web server scan")
        table.add_row("6", "Subdomain Scanner", "Find subdomains (subfinder/enumall)")
        table.add_row("7", "Tech Stack Detection", "Identify technologies (whatweb)")
        table.add_row("8", "HTTP Header Analysis", "Analyze security headers")
        table.add_row("9", "Wayback Machine Search", "Find old URLs from web archives")
        table.add_row("10", "Back", "Return to main menu")
        self.console.print(table)
        choice = Prompt.ask("Choose a web attack tool", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"])
        
        if choice == "1":
            url = Prompt.ask("Enter target URL for SQLi scan")
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
            
            self.console.print(f"[cyan]Running sqlmap on {url}...[/cyan]")
            try:
                result = subprocess.run(["sqlmap", "-u", url, "--batch"], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from sqlmap.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running sqlmap: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]sqlmap command not found. Please install sqlmap.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running sqlmap: {e}[/red]")
        elif choice == "2":
            url = Prompt.ask("Enter target URL for XSS test")
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
                
            self.console.print(f"[cyan]Running XSStrike on {url}...[/cyan]")
            try:
                result = subprocess.run(["xsstrike", "-u", url], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from XSStrike.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running XSStrike: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]XSStrike command not found. Please install XSStrike.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running XSStrike: {e}[/red]")
        elif choice == "3":
            url = Prompt.ask("Enter target URL for CSRF PoC")
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
                
            self.console.print(f"[cyan]Generating CSRF PoC for {url}...[/cyan]")
            self.console.print("[green]CSRF PoC generated (demo).[/green]")
        elif choice == "4":
            url = Prompt.ask("Enter target URL for directory brute force")
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
                
            wordlist = Prompt.ask("Enter path to wordlist", default="common.txt")
            self.console.print(f"[cyan]Running ffuf on {url} with wordlist {wordlist}...[/cyan]")
            try:
                result = subprocess.run(["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from ffuf.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running ffuf: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]ffuf command not found. Please install ffuf.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running ffuf: {e}[/red]")
        elif choice == "5":
            url = Prompt.ask("Enter target URL for Nikto scan")
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
                
            self.console.print(f"[cyan]Running Nikto on {url}...[/cyan]")
            try:
                result = subprocess.run(["nikto", "-h", url], capture_output=True, text=True, check=True)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from Nikto.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running Nikto: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]nikto command not found. Please install nikto.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running Nikto: {e}[/red]")
        elif choice == "6":
            domain = Prompt.ask("Enter domain for subdomain discovery")
            # Validate domain format
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, domain):
                self.console.print("[red]Invalid domain format[/red]")
                return
                
            self.console.print(f"[cyan]Running subdomain discovery for {domain}...[/cyan]")
            try:
                # Try subfinder first
                result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    subdomains = result.stdout.strip().split('\n') if result.stdout.strip() else []
                    if subdomains:
                        self.console.print(f"[bold green]Found {len(subdomains)} subdomains:[/bold green]")
                        for subdomain in subdomains:
                            if subdomain.strip():
                                self.console.print(f"  [cyan]{subdomain.strip()}[/cyan]")
                    else:
                        self.console.print("[yellow]No subdomains found or subfinder not available.[/yellow]")
                else:
                    self.console.print("[yellow]Subfinder may not be available or failed.[/yellow]")
            except subprocess.TimeoutExpired:
                self.console.print("[red]Subdomain discovery timed out.[/red]")
            except FileNotFoundError:
                self.console.print("[red]subfinder command not found. Install subfinder for subdomain discovery.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error during subdomain discovery: {e}[/red]")
        elif choice == "7":
            url = Prompt.ask("Enter URL for technology stack detection")
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
                
            self.console.print(f"[cyan]Running technology stack detection on {url}...[/cyan]")
            try:
                result = subprocess.run(["whatweb", url], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    output = result.stdout
                    # Extract and display technology information
                    technologies = []
                    for line in output.split('\n'):
                        if '[' in line and ']' in line:
                            technologies.append(line.strip())
                    
                    if technologies:
                        self.console.print("[bold green]Technologies detected:[/bold green]")
                        for tech in technologies[:5]:  # Show first 5 tech detections
                            self.console.print(f"  [cyan]{tech}[/cyan]")
                    else:
                        self.console.print("[yellow]No clear technology stack detected or whatweb not available.[/yellow]")
                else:
                    self.console.print(f"[red]whatweb returned code {result.returncode}[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[red]Technology detection timed out.[/red]")
            except FileNotFoundError:
                self.console.print("[red]whatweb command not found. Install whatweb for technology detection.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error during technology detection: {e}[/red]")
        elif choice == "8":
            url = Prompt.ask("Enter URL for HTTP header analysis")
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
                
            self.console.print(f"[cyan]Analyzing HTTP headers for {url}...[/cyan]")
            
            try:
                import requests
                response = requests.get(url, timeout=10)
                headers = response.headers
                
                # Check for important security headers
                important_headers = [
                    'Strict-Transport-Security',
                    'Content-Security-Policy', 
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Referrer-Policy',
                    'Permissions-Policy'
                ]
                
                found_headers = []
                missing_headers = []
                
                for header in important_headers:
                    if header in headers:
                        found_headers.append(f"{header}: {headers[header]}")
                    else:
                        missing_headers.append(header)
                
                if found_headers:
                    self.console.print("[bold green]Security headers found:[/bold green]")
                    for header in found_headers:
                        self.console.print(f"  [green]✓ {header}[/green]")
                
                if missing_headers:
                    self.console.print("[bold red]Missing security headers:[/bold red]")
                    for header in missing_headers:
                        self.console.print(f"  [red]✗ {header}[/red]")
                
                if not found_headers and not missing_headers:
                    self.console.print("[yellow]Could not retrieve headers or site not accessible.[/yellow]")
                    
            except requests.RequestException as e:
                self.console.print(f"[red]Error accessing URL: {e}[/red]")
            except Exception as e:
                self.console.print(f"[red]Error during header analysis: {e}[/red]")
        elif choice == "9":
            domain = Prompt.ask("Enter domain for Wayback Machine search")
            # Validate domain format
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, domain):
                self.console.print("[red]Invalid domain format[/red]")
                return
                
            self.console.print(f"[cyan]Searching Wayback Machine for {domain}...[/cyan]")
            self.console.print("[yellow]Note: This would use the Wayback Machine API to find historical URLs[/yellow]")
            
            # In a real implementation, this would use the archive.org API
            # For now, we'll just show what would happen
            self.console.print("[dim]This would fetch historical URLs from archive.org for:")
            self.console.print(f"  https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json")
            self.console.print("This can help find old endpoints, admin panels, or forgotten resources.[/dim]")
        elif choice == "10":
            return

    def wireless_attack_tools_menu(self) -> None:
        # Check for dependencies before showing the menu
        all_installed = self.check_dependencies('wireless')
        if not all_installed:
            self.console.print("[yellow]Some tools may not function without required dependencies.[/yellow]")
            continue_anyway = Prompt.ask("[bold magenta]Continue anyway? (yes/no)[/bold magenta]", default="no")
            if continue_anyway.lower() not in ['yes', 'y', 'true']:
                return
        
        table = Table(
            title="[bold cyan]Wireless Attack Tools[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED,
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white")
        table.add_row("1", "WiFi Scanner", "Scan for nearby WiFi networks (airodump-ng)")
        table.add_row("2", "Handshake Capture", "Capture WPA handshake (airodump-ng)")
        table.add_row("3", "WPA Cracking", "Attempt WPA password cracking (hashcat)")
        table.add_row("4", "Bluetooth Scanner", "Scan for Bluetooth devices (blue_hydra)")
        table.add_row("5", "Wifite Automation", "Automated wireless attacks (wifite)")
        table.add_row("6", "GPS Mapping", "Map wireless networks with GPS coordinates")
        table.add_row("7", "Deauth Attack", "Deauthenticate clients from AP")
        table.add_row("8", "Evil Twin AP", "Create rogue access point")
        table.add_row("9", "Back", "Return to main menu")
        self.console.print(table)
        choice = Prompt.ask("Choose a wireless attack tool", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"])
        
        if choice == "1":
            interface = Prompt.ask("Enter wireless interface (e.g., wlan0)", default="wlan0")
            self.console.print(f"[cyan]Running airodump-ng for WiFi scan on {interface}...[/cyan]")
            try:
                result = subprocess.run(["airodump-ng", interface], capture_output=True, text=True, check=True, timeout=30)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from airodump-ng.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running airodump-ng: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]airodump-ng command not found. Please install aircrack-ng suite.[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[yellow]airodump-ng scan completed (timeout reached).[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error running airodump-ng: {e}[/red]")
        elif choice == "2":
            interface = Prompt.ask("Enter wireless interface (e.g., wlan0)", default="wlan0")
            channel = Prompt.ask("Enter WiFi channel to monitor (e.g., 6)", default="6")
            self.console.print(f"[cyan]Capturing WPA handshake on channel {channel} with airodump-ng...[/cyan]")
            try:
                result = subprocess.run(["airodump-ng", interface, "--channel", channel], capture_output=True, text=True, check=True, timeout=60)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from airodump-ng.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running airodump-ng: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]airodump-ng command not found. Please install aircrack-ng suite.[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[yellow]Handshake capture completed (timeout reached).[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error running airodump-ng: {e}[/red]")
        elif choice == "3":
            self.console.print("[cyan]Running hashcat for WPA cracking...[/cyan]")
            try:
                result = subprocess.run(["hashcat", "--help"], capture_output=True, text=True, check=True)
                self.console.print("[green]Hashcat is available. WPA cracking requires specific .cap files and wordlists.[/green]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running hashcat: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]hashcat command not found. Please install hashcat.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running hashcat: {e}[/red]")
        elif choice == "4":
            self.console.print("[cyan]Running blue_hydra for Bluetooth scan...[/cyan]")
            try:
                result = subprocess.run(["blue_hydra"], capture_output=True, text=True, check=True, timeout=10)
                self.console.print(result.stdout if result.stdout else "[yellow]No Bluetooth devices found or blue_hydra not available.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running blue_hydra: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]blue_hydra command not found. Please install blue_hydra.[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[yellow]Bluetooth scan completed (timeout reached).[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error running blue_hydra: {e}[/red]")
        elif choice == "5":
            interface = Prompt.ask("Enter wireless interface (e.g., wlan0)", default="wlan0")
            self.console.print(f"[cyan]Running wifite automated wireless attack on {interface}...[/cyan]")
            try:
                result = subprocess.run(["wifite", "-i", interface, "--noaireplay"], capture_output=True, text=True, check=True, timeout=120)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from wifite.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running wifite: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]wifite command not found. Please install wifite.[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[yellow]Wifite completed (timeout reached).[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error running wifite: {e}[/red]")
        elif choice == "6":
            self.console.print("[cyan]GPS mapping functionality would track wireless networks with coordinates...[/cyan]")
            self.console.print("[yellow]This requires GPS hardware and kismet with GPS support[/yellow]")
            self.console.print("[dim]In a real implementation, this would use kismet with GPS logging enabled[/dim]")
        elif choice == "7":
            interface = Prompt.ask("Enter wireless interface (e.g., wlan0)", default="wlan0")
            target_bssid = Prompt.ask("Enter target BSSID (AP MAC address)")
            target_channel = Prompt.ask("Enter target channel")
            self.console.print(f"[cyan]Running deauthentication attack on {target_bssid} (channel {target_channel})...[/cyan]")
            try:
                result = subprocess.run([
                    "aireplay-ng", interface, 
                    "--deauth", "10", 
                    "-a", target_bssid, 
                    "-c", "FF:FF:FF:FF:FF:FF"  # Broadcast to all clients
                ], capture_output=True, text=True, check=True, timeout=30)
                self.console.print(result.stdout if result.stdout else "[yellow]Deauth attack completed[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running aireplay-ng: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]aireplay-ng command not found. Please install aircrack-ng suite.[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[yellow]Deauth attack completed (timeout reached).[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error running deauth attack: {e}[/red]")
        elif choice == "8":
            ssid = Prompt.ask("Enter SSID for evil twin AP", default="Free WiFi")
            channel = Prompt.ask("Enter channel for evil twin AP", default="6")
            self.console.print(f"[cyan]Creating evil twin access point '{ssid}' on channel {channel}...[/cyan]")
            self.console.print("[yellow]This would use hostapd to create a rogue AP[/yellow]")
            self.console.print("[dim]Note: This requires proper wireless card support and configuration[/dim]")
        elif choice == "9":
            return

    def run(self) -> None:
        self.display_banner()
        while True:
            self.display_menu()
            choice = Prompt.ask(
                "[bold cyan]redteam@cyber[/bold cyan] [bold magenta]~$[/bold magenta]",
                choices=[str(i) for i in range(1, 12)],
            )
            self.console.print()
            if choice == "1":
                self.network_recon.run()
            elif choice == "2":
                self.vuln_scanner.run()
            elif choice == "3":
                self.password_tester.run()
            elif choice == "4":
                self.osint_tools_menu()
            elif choice == "5":
                self.social_engineering.run()
            elif choice == "6":
                self.forensics.run()
            elif choice == "7":
                self.reporting.run()
            elif choice == "8":
                self.misc_utils.run()
            elif choice == "9":
                self.web_attack_tools_menu()
            elif choice == "10":
                self.wireless_attack_tools_menu()
            elif choice == "11":
                self.console.print(
                    "[bold cyan]Shutting down RedTeam Terminal...[/bold cyan]"
                )
                self.console.print("[bold green]✓[/bold green] Session terminated")
                sys.exit(0)
            self.console.print()
            self.console.print("[dim]─" * 80 + "[/dim]")
            self.console.print()


def main() -> None:
    """Entry point"""
    try:
        terminal = RedTeamTerminal()
        terminal.run()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠[/bold yellow] Interrupted by user")
        console.print("[bold cyan]Shutting down RedTeam Terminal...[/bold cyan]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()