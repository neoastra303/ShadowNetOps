#!/usr/bin/env python3
"""
ShadowNetOps - Advanced Network Security Operations & Red Teaming Platform
"""

import sys
import re
import subprocess
import os
import hashlib
import base64
import urllib.parse
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
from tools.malware_analysis import MalwareAnalysisTools
from tools.reverse_engineering import ReverseEngineeringTools
from tools.cryptography_tools import CryptographyTools
from tools.base_tool import URL_PATTERN, DOMAIN_PATTERN, BaseTool

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
        
        # Initialize new tools
        self.malware_analysis = MalwareAnalysisTools(console)
        self.reverse_engineering = ReverseEngineeringTools(console)
        self.cryptography_tools = CryptographyTools(console)

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
            title="[bold cyan]⚡ Available Tools & Categories ⚡[/bold cyan]",
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
        table.add_row("4", "OSINT Tools", "Email, username, domain, phone number, social media research")
        table.add_row(
            "5",
            "Social Engineering Toolkit",
            "Phishing, pretexting, credential harvesting, spear phishing campaigns"
        )
        table.add_row("6", "Forensics", "Disk, memory, network, log, steganography analysis")
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
        table.add_row(
            "11",
            "Malware Analysis",
            "Static and dynamic malware analysis tools"
        )
        table.add_row(
            "12",
            "Reverse Engineering",
            "Binary analysis, disassembly, decompilation tools"
        )
        table.add_row(
            "13",
            "Cryptography Tools",
            "Encryption, decryption, cryptographic analysis"
        )
        table.add_row("14", "Exit", "Quit the terminal")
        self.console.print(table)
        self.console.print()

    def validate_target(self, target: str) -> bool:
        return BaseTool.validate_target(target)

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
            if not URL_PATTERN.match(url):
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
            if not URL_PATTERN.match(url):
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
            if not URL_PATTERN.match(url):
                self.console.print("[red]Invalid URL format[/red]")
                return
                
            self.console.print(f"[cyan]Generating CSRF PoC for {url}...[/cyan]")
            self.console.print("[green]CSRF PoC generated (demo).[/green]")
        elif choice == "4":
            url = Prompt.ask("Enter target URL for directory brute force")
            if not URL_PATTERN.match(url):
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
            if not URL_PATTERN.match(url):
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
            if not DOMAIN_PATTERN.match(domain):
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
            if not URL_PATTERN.match(url):
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
            if not URL_PATTERN.match(url):
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
            if not DOMAIN_PATTERN.match(domain):
                self.console.print("[red]Invalid domain format[/red]")
                return
                
            self.console.print(f"[cyan]Searching Wayback Machine for {domain}...[/cyan]")
            try:
                import requests
                resp = requests.get(
                    f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10",
                    timeout=15
                )
                if resp.status_code == 200 and len(resp.json()) > 1:
                    results = resp.json()[1:11]
                    self.console.print(f"[bold green]Found {len(results)} historical URLs:[/bold green]")
                    for entry in results:
                        self.console.print(f"  [cyan]{entry[2]}[/cyan]")
                else:
                    self.console.print("[yellow]No archived URLs found or API unavailable.[/yellow]")
            except Exception:
                self.console.print("[yellow]Wayback Machine API unavailable. Try again later.[/yellow]")
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
        table.add_row("9", "WiFi Phishing Portal", "Create captive portal for credential harvesting")
        table.add_row("10", "PMKID Capture", "Capture PMKID for offline cracking")
        table.add_row("11", "WPS PIN Attack", "Bruteforce WPS PINs (reaver)")
        table.add_row("12", "WiFi Signal Jammer", "Jam WiFi signals in range")
        table.add_row("13", "Back", "Return to main menu")
        self.console.print(table)
        choice = Prompt.ask("Choose a wireless attack tool", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"])
        
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
            ssid = Prompt.ask("Enter SSID for phishing portal", default="Free WiFi")
            self.console.print(f"[cyan]Creating phishing portal for '{ssid}'...[/cyan]")
            self.console.print("[yellow]This would use fluxion or similar tools to create a captive portal")
            self.console.print("[dim]In a real implementation, this would serve a fake login page to capture credentials")
        elif choice == "10":
            interface = Prompt.ask("Enter wireless interface (e.g., wlan0)", default="wlan0")
            self.console.print(f"[cyan]Capturing PMKID on {interface}...[/cyan]")
            self.console.print("[yellow]This would use hcxdumptool to capture PMKID for offline cracking")
            self.console.print("[dim]PMKID capture allows for faster WPA cracking without waiting for handshakes")
        elif choice == "11":
            target_bssid = Prompt.ask("Enter target BSSID for WPS attack")
            interface = Prompt.ask("Enter wireless interface (e.g., wlan0)", default="wlan0")
            self.console.print(f"[cyan]Running WPS PIN attack on {target_bssid}...[/cyan]")
            try:
                result = subprocess.run(["reaver", "-i", interface, "-b", target_bssid, "-vv"], 
                                      capture_output=True, text=True, check=True, timeout=300)
                self.console.print(result.stdout if result.stdout else "[yellow]No output from reaver.[/yellow]")
            except subprocess.CalledProcessError as e:
                self.console.print(f"[red]Error running reaver: {e}[/red]")
            except FileNotFoundError:
                self.console.print("[red]reaver command not found. Please install reaver.[/red]")
            except subprocess.TimeoutExpired:
                self.console.print("[yellow]WPS attack completed (timeout reached).[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error running WPS attack: {e}[/red]")
        elif choice == "12":
            interface = Prompt.ask("Enter wireless interface (e.g., wlan0)", default="wlan0")
            self.console.print(f"[cyan]Jamming WiFi signals on {interface}...[/cyan]")
            self.console.print("[yellow]This would use mdk4 or similar tools to jam WiFi signals")
            self.console.print("[red]WARNING: Signal jamming may be illegal in your jurisdiction!")
        elif choice == "13":
            return

    def run(self) -> None:
        self.display_banner()
        while True:
            self.display_menu()
            choice = Prompt.ask(
                "[bold cyan]redteam@cyber[/bold cyan] [bold magenta]~$[/bold magenta]",
                choices=[str(i) for i in range(1, 15)],
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
                self.malware_analysis_menu()
            elif choice == "12":
                self.reverse_engineering_menu()
            elif choice == "13":
                self.cryptography_tools_menu()
            elif choice == "14":
                self.console.print(
                    "[bold cyan]Shutting down RedTeam Terminal...[/bold cyan]"
                )
                self.console.print("[bold green]✓[/bold green] Session terminated")
                sys.exit(0)
            self.console.print()
            self.console.print("[dim]─" * 80 + "[/dim]")
            self.console.print()
    
    def malware_analysis_menu(self) -> None:
        """Malware analysis tools menu"""
        table = Table(
            title="[bold cyan]Malware Analysis Tools[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED,
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white")
        table.add_row("1", "Static Analysis", "Analyze malware without executing (YARA, PE analysis)")
        table.add_row("2", "Dynamic Analysis", "Analyze malware behavior in sandbox (Cuckoo, ANY.RUN)")
        table.add_row("3", "String Extraction", "Extract strings and potential IOCs from binaries")
        table.add_row("4", "YARA Rule Scanner", "Scan files with custom YARA rules")
        table.add_row("5", "PE Header Analysis", "Analyze Portable Executable headers")
        table.add_row("6", "Network Traffic Analysis", "Monitor malware network communications")
        table.add_row("7", "Memory Dump Analysis", "Analyze malware memory artifacts")
        table.add_row("8", "Back", "Return to main menu")
        self.console.print(table)
        choice = Prompt.ask("Choose a malware analysis tool", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
        
        if choice == "1":
            file_path = Prompt.ask("Enter file path for static analysis")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Running static analysis on [green]{file_path}[/green]...[/cyan]")
                result = subprocess.run(["file", file_path], capture_output=True, text=True, timeout=15)
                self.console.print(f"[bold]File type:[/bold] {result.stdout.strip()}")
                self.console.print("[yellow]Full static analysis would also check: file signatures, packer detection, entropy analysis[/yellow]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "2":
            self.console.print("[cyan]Dynamic analysis requires a sandbox environment (Cuckoo, ANY.RUN).[/cyan]")
            self.console.print("[yellow]In a real scenario: submit the sample to a sandbox, observe behavior, network calls, process actions.[/yellow]")
        elif choice == "3":
            file_path = Prompt.ask("Enter file path for string extraction")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Extracting strings from [green]{file_path}[/green]...[/cyan]")
                try:
                    result = subprocess.run(["strings", file_path], capture_output=True, text=True, check=True, timeout=30)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        self.console.print(f"[bold green]Found {len(lines)} strings in {file_path}:[/bold green]")
                        for line in lines[:20]:
                            if len(line) > 4:
                                self.console.print(f"  [cyan]{line}[/cyan]")
                    else:
                        self.console.print(f"[red]Strings command failed with code {result.returncode}[/red]")
                except subprocess.TimeoutExpired:
                    self.console.print("[red]String extraction timed out.[/red]")
                except FileNotFoundError:
                    self.console.print("[red]strings command not found. Install binutils for string extraction.[/red]")
                except Exception as e:
                    self.console.print(f"[red]Error during string extraction: {e}[/red]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "4":
            rule_path = Prompt.ask("Enter YARA rule file path", default="rules.yar")
            target_path = Prompt.ask("Enter target file/directory to scan")
            if os.path.isfile(rule_path) and os.path.exists(target_path):
                self.console.print(f"[cyan]Scanning [green]{target_path}[/green] with rules [green]{rule_path}[/green]...[/cyan]")
                try:
                    result = subprocess.run(["yara", rule_path, target_path], capture_output=True, text=True, timeout=60)
                    if result.stdout.strip():
                        self.console.print("[bold red]YARA matches found:[/bold red]")
                        self.console.print(result.stdout)
                    else:
                        self.console.print("[green]No YARA matches.[/green]")
                except FileNotFoundError:
                    self.console.print("[red]yara command not found. Install YARA.[/red]")
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
            else:
                self.console.print("[red]Invalid rule file or target path.[/red]")
        elif choice == "5":
            file_path = Prompt.ask("Enter PE file path for header analysis")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Analyzing PE headers in [green]{file_path}[/green]...[/cyan]")
                try:
                    with open(file_path, 'rb') as f:
                        magic = f.read(2)
                    if magic == b'MZ':
                        self.console.print("[green]Valid MZ header detected (PE file).[/green]")
                    else:
                        self.console.print(f"[yellow]File signature: {magic.hex()} (may not be a PE file)[/yellow]")
                except Exception as e:
                    self.console.print(f"[red]Error reading file: {e}[/red]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "6":
            interface = Prompt.ask("Enter network interface to monitor", default="eth0")
            self.console.print(f"[cyan]Starting packet capture on {interface} for 10 seconds...[/cyan]")
            try:
                result = subprocess.run(["tcpdump", "-i", interface, "-c", "10", "-nn"],
                                      capture_output=True, text=True, timeout=15)
                self.console.print(result.stdout if result.stdout.strip() else "[yellow]No packets captured.[/yellow]")
            except FileNotFoundError:
                self.console.print("[red]tcpdump not found. Install it for network traffic analysis.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
        elif choice == "7":
            mem_path = Prompt.ask("Enter memory dump file path")
            if os.path.isfile(mem_path):
                self.console.print(f"[cyan]Analyzing memory dump [green]{mem_path}[/green]...[/cyan]")
                self.console.print("[yellow]Memory analysis would check for: injected processes, network connections, registry artifacts[/yellow]")
                self.console.print("[yellow]Install Volatility for full memory forensics: pip install volatility3[/yellow]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "8":
            return
    
    def reverse_engineering_menu(self) -> None:
        """Reverse engineering tools menu"""
        table = Table(
            title="[bold cyan]Reverse Engineering Tools[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED,
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white")
        table.add_row("1", "Disassembler", "Disassemble binaries (IDA Pro, Ghidra, Radare2)")
        table.add_row("2", "Debugger", "Debug executables (GDB, x64dbg, OllyDbg)")
        table.add_row("3", "Decompiler", "Decompile binaries to source code")
        table.add_row("4", "Binary Analysis", "Analyze binary file formats and structures")
        table.add_row("5", "Function Recognition", "Identify standard library functions")
        table.add_row("6", "String Decryption", "Decrypt obfuscated strings in binaries")
        table.add_row("7", "Packer Detection", "Detect executable packers and protectors")
        table.add_row("8", "Back", "Return to main menu")
        self.console.print(table)
        choice = Prompt.ask("Choose a reverse engineering tool", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
        
        if choice == "1":
            file_path = Prompt.ask("Enter binary path to disassemble")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Attempting to disassemble [green]{file_path}[/green]...[/cyan]")
                try:
                    result = subprocess.run(["objdump", "-d", file_path], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        self.console.print(f"[bold]Disassembly ({len(lines)} lines):[/bold]")
                        for line in lines[:25]:
                            self.console.print(f"  [dim]{line}[/dim]")
                    else:
                        self.console.print("[yellow]objdump failed. Try installing binutils or using a dedicated tool.[/yellow]")
                except FileNotFoundError:
                    self.console.print("[red]objdump not found. Install binutils.[/red]")
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "2":
            binary = Prompt.ask("Enter binary path to debug")
            if os.path.isfile(binary):
                self.console.print(f"[cyan]Use GDB to debug [green]{binary}[/green]: gdb {binary}[/cyan]")
                self.console.print("[yellow]GDB commands: break main, run, next, step, info registers, x/s $rsp[/yellow]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "3":
            file_path = Prompt.ask("Enter binary path to decompile")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Attempting decompilation of [green]{file_path}[/green]...[/cyan]")
                try:
                    result = subprocess.run(["objdump", "-d", file_path], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        self.console.print(f"[bold green]Disassembly output:[/bold green]")
                        self.console.print("[yellow]For full decompilation, use Ghidra or IDA Pro.[/yellow]")
                except FileNotFoundError:
                    self.console.print("[red]objdump not found. Install binutils.[/red]")
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "4":
            file_path = Prompt.ask("Enter binary file path for analysis")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Analyzing binary [green]{file_path}[/green]...[/cyan]")
                result = subprocess.run(["file", file_path], capture_output=True, text=True, timeout=15)
                self.console.print(f"[bold]Type:[/bold] {result.stdout.strip()}")
                result2 = subprocess.run(["xxd", file_path, "-l", "512"], capture_output=True, text=True, timeout=15)
                self.console.print(f"[bold]Hex dump (first 512 bytes):[/bold]")
                for line in result2.stdout.split('\n')[:8]:
                    self.console.print(f"  [dim]{line}[/dim]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "5":
            self.console.print("[cyan]Function recognition identifies library calls in disassembled code.[/cyan]")
            self.console.print("[yellow]Uses FLIRT signatures (IDA Pro) or manual analysis of call instructions.[/yellow]")
        elif choice == "6":
            text = Prompt.ask("Enter hex-encoded or obfuscated string to decode")
            try:
                decoded = bytes.fromhex(text).decode('utf-8', errors='replace')
                self.console.print(f"[green]Decoded: {decoded}[/green]")
            except ValueError:
                self.console.print("[yellow]Not valid hex. Try XOR brute-force:[yellow]")
                key = Prompt.ask("Enter single-byte XOR key (0-255)", default="0x41")
                try:
                    key_byte = int(key, 16 if 'x' in key else 10) & 0xFF
                    decoded = bytes(b ^ key_byte for b in text.encode()).decode('utf-8', errors='replace')
                    self.console.print(f"[green]XOR decoded: {decoded}[/green]")
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
        elif choice == "7":
            file_path = Prompt.ask("Enter binary path to check for packers")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Checking [green]{file_path}[/green] for packers...[/cyan]")
                result = subprocess.run(["file", file_path], capture_output=True, text=True, timeout=15)
                if "UPX" in result.stdout:
                    self.console.print("[red]UPX packer detected![/red]")
                else:
                    self.console.print("[green]No known packer signature detected via file command.[/green]")
                self.console.print("[yellow]For comprehensive packer detection, use PEiD, Detect It Easy, or ExeInfoPE.[/yellow]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "8":
            return
    
    def cryptography_tools_menu(self) -> None:
        """Cryptography tools menu"""
        table = Table(
            title="[bold cyan]Cryptography Tools[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED,
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white")
        table.add_row("1", "Hash Calculator", "Calculate various hash algorithms (MD5, SHA1, SHA256)")
        table.add_row("2", "Encryption/Decryption", "Encrypt/decrypt with various algorithms")
        table.add_row("3", "Encoding/Decoding", "Encode/decode with Base64, Hex, URL encoding")
        table.add_row("4", "Cryptanalysis", "Analyze cryptographic implementations for weaknesses")
        table.add_row("5", "Certificate Analysis", "Analyze SSL/TLS certificates")
        table.add_row("6", "Key Generation", "Generate cryptographic keys")
        table.add_row("7", "Digital Signatures", "Create and verify digital signatures")
        table.add_row("8", "Back", "Return to main menu")
        self.console.print(table)
        choice = Prompt.ask("Choose a cryptography tool", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
        
        if choice == "1":
            file_path = Prompt.ask("Enter file path for hash calculation")
            if os.path.isfile(file_path):
                self.console.print(f"[cyan]Calculating hashes for [green]{file_path}[/green]...[/cyan]")
                
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    md5_hash = hashlib.md5(data).hexdigest()
                    sha1_hash = hashlib.sha1(data).hexdigest()
                    sha256_hash = hashlib.sha256(data).hexdigest()
                    
                    self.console.print(f"[bold]MD5:[/bold]    {md5_hash}")
                    self.console.print(f"[bold]SHA1:[/bold]   {sha1_hash}")
                    self.console.print(f"[bold]SHA256:[/bold] {sha256_hash}")
                    
                except Exception as e:
                    self.console.print(f"[red]Error calculating hashes: {e}[/red]")
            else:
                self.console.print("[red]Invalid file path.[/red]")
        elif choice == "2":
            self.console.print("[cyan]Encryption/Decryption[/cyan]")
            mode = Prompt.ask("Encrypt or Decrypt?", choices=["encrypt", "decrypt"], default="encrypt")
            text = Prompt.ask("Enter text")
            key = Prompt.ask("Enter encryption password (min 16 chars)", default="defaultpassword123")
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import pad, unpad
                import hashlib
                key_bytes = hashlib.sha256(key.encode()).digest()
                if mode == "encrypt":
                    from Crypto.Random import get_random_bytes
                    iv = get_random_bytes(16)
                    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                    ct = cipher.encrypt(pad(text.encode(), AES.block_size))
                    result = base64.b64encode(iv + ct).decode()
                    self.console.print(f"[bold green]Encrypted (AES-256-CBC):[/bold green] {result}")
                else:
                    raw = base64.b64decode(text)
                    iv, ct = raw[:16], raw[16:]
                    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
                    self.console.print(f"[bold green]Decrypted:[/bold green] {pt}")
            except ImportError:
                self.console.print("[yellow]pycryptodome not installed. Install with: pip install pycryptodome[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
        elif choice == "3":
            text = Prompt.ask("Enter text for encoding/decoding")
            self.console.print(f"[cyan]Encoding [green]{text}[/green]...[/cyan]")
            
            b64_encoded = base64.b64encode(text.encode()).decode()
            hex_encoded = text.encode().hex()
            url_encoded = urllib.parse.quote(text)
            
            self.console.print(f"[bold]Base64:[/bold] {b64_encoded}")
            self.console.print(f"[bold]Hex:[/bold]    {hex_encoded}")
            self.console.print(f"[bold]URL:[/bold]    {url_encoded}")
            
            self.console.print()
            decode_text = Prompt.ask("Enter string to decode (or press Enter to skip)", default="")
            if decode_text:
                self.console.print("[cyan]Attempting auto-decode...[/cyan]")
                try:
                    self.console.print(f"  [bold]Base64:[/bold] {base64.b64decode(decode_text).decode('utf-8', errors='replace')}")
                except Exception:
                    pass
                try:
                    self.console.print(f"  [bold]Hex:[/bold]    {bytes.fromhex(decode_text).decode('utf-8', errors='replace')}")
                except Exception:
                    pass
        elif choice == "4":
            hash_val = Prompt.ask("Enter hash value to analyze")
            self.console.print(f"[cyan]Analyzing hash [green]{hash_val}[/green]...[/cyan]")
            length = len(hash_val)
            if length == 32:
                self.console.print("[bold]Possible algorithm: MD5[/bold]")
            elif length == 40:
                self.console.print("[bold]Possible algorithm: SHA1[/bold]")
            elif length == 56:
                self.console.print("[bold]Possible algorithm: SHA224[/bold]")
            elif length == 64:
                self.console.print("[bold]Possible algorithm: SHA256[/bold]")
            elif length == 96:
                self.console.print("[bold]Possible algorithm: SHA384[/bold]")
            elif length == 128:
                self.console.print("[bold]Possible algorithm: SHA512[/bold]")
            else:
                self.console.print(f"[yellow]Unknown hash type (length: {length} hex chars)[/yellow]")
        elif choice == "5":
            host = Prompt.ask("Enter hostname to check SSL certificate")
            self.console.print(f"[cyan]Checking SSL certificate for [green]{host}[/green]...[/cyan]")
            try:
                import ssl
                import socket
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                    s.settimeout(10)
                    s.connect((host, 443))
                    cert = s.getpeercert()
                    self.console.print(f"[bold]Subject:[/bold] {dict(cert['subject'][0][0])}")
                    self.console.print(f"[bold]Issuer:[/bold] {dict(cert['issuer'][0][0])}")
                    self.console.print(f"[bold]Valid from:[/bold] {cert['notBefore']}")
                    self.console.print(f"[bold]Valid until:[/bold] {cert['notAfter']}")
            except Exception as e:
                self.console.print(f"[red]Could not retrieve certificate: {e}[/red]")
        elif choice == "6":
            key_type = Prompt.ask("Key type", choices=["RSA", "AES"], default="RSA")
            if key_type == "RSA":
                self.console.print("[cyan]Generating RSA key pair...[/cyan]")
                try:
                    from Crypto.PublicKey import RSA
                    key = RSA.generate(2048)
                    self.console.print("[green]RSA 2048-bit key generated![/green]")
                    self.console.print(f"[bold]Private key:[/bold]")
                    self.console.print(key.export_key().decode()[:200] + "...")
                    self.console.print(f"[bold]Public key:[/bold]")
                    self.console.print(key.publickey().export_key().decode()[:200] + "...")
                except ImportError:
                    self.console.print("[yellow]Install pycryptodome for key generation.[/yellow]")
            else:
                import hashlib
                pw = Prompt.ask("Enter passphrase for AES key")
                key = hashlib.sha256(pw.encode()).digest()
                self.console.print(f"[green]AES-256 key generated: {key.hex()[:48]}...[/green]")
        elif choice == "7":
            data = Prompt.ask("Enter data to sign (or verify)", default="test message")
            sig_type = Prompt.ask("Action", choices=["sign", "verify"], default="sign")
            if sig_type == "sign":
                import hashlib
                self.console.print(f"[bold]SHA256 hash:[/bold] {hashlib.sha256(data.encode()).hexdigest()}")
                self.console.print("[yellow]In production, this would use RSA/ECDSA signing with a private key.[/yellow]")
            else:
                hash_val = Prompt.ask("Enter expected hash")
                computed = hashlib.sha256(data.encode()).hexdigest()
                match = computed == hash_val
                self.console.print(f"[bold]Computed hash:[/bold] {computed}")
                self.console.print(f"[{'green' if match else 'red'}]Hash {'matches' if match else 'does not match'}![/{'green' if match else 'red'}]")
        elif choice == "8":
            return


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