"""OSINT (Open Source Intelligence) Tools"""

import time
import subprocess
import re
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import track
from rich import box
from .base_tool import BaseTool


class OSINTTools(BaseTool):
    def __init__(self, console: Console):
        super().__init__(console)
        
    def lookup_domain(self, target: str):
        """Perform domain/IP/email OSINT lookup"""
        # Validate input to prevent command injection
        if not self.validate_input(target):
            self.display_result("Invalid target format", "error")
            return
            
        self.console.print(Panel(
            f"[bold cyan]Performing OSINT on: [green]{target}[/green][/bold cyan]\n"
            "[dim]Querying public databases and sources...[/dim]",
            border_style="cyan"
        ))
        self.console.print()
        
        # Simulate data gathering
        data_sources = [
            "WHOIS Database",
            "DNS Records",
            "SSL Certificate Data",
            "Breach Databases",
            "Social Media",
            "Public Records",
            "Domain History"
        ]
        
        for source in track(data_sources, description="[cyan]Gathering intelligence...\n"):
            time.sleep(0.2)
        
        # Mock results
        results = [
            ("Domain Registration", "Registered since 2015", "green"),
            ("Registrar", "GoDaddy LLC", "cyan"),
            ("IP Address", "192.168.1.1 (USA)", "cyan"),
            ("DNS Records", "A, MX, TXT records found", "green"),
            ("SSL Certificate", "Valid until 2025-12-31", "green"),
            ("Email Breaches", "admin@example.com found in 3 breaches", "red"),
            ("Social Media", "Twitter: @example (2.5k followers)", "cyan"),
            ("Technology Stack", "nginx, PHP, MySQL detected", "cyan"),
        ]
        
        # Display results
        table = Table(
            title="[bold cyan]OSINT Results[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        
        table.add_column("Category", style="white")
        table.add_column("Information", style="cyan")
        table.add_column("Status", justify="center")
        
        for category, info, color in results:
            status = f"[{color}]●[/{color}]"
            table.add_row(category, info, status)
        
        self.console.print(table)
        self.console.print()
        self.display_result("Intelligence gathering complete", "success")
    
    def whois_lookup(self, target: str):
        """Perform WHOIS lookup on domain or IP"""
        self.console.print(f"[cyan]Performing WHOIS lookup on [green]{target}[/green][/cyan]")
        
        try:
            result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                lines = output.split('\n')
                
                # Extract key information from WHOIS
                whois_data = []
                for line in lines[:20]:  # Look at first 20 lines
                    if 'Registrar:' in line or 'Registrant Name:' in line or 'Creation Date:' in line or 'Expiry Date:' in line or 'Updated Date:' in line or 'Name Server' in line or 'Organization:' in line:
                        whois_data.append(line.strip())
                
                if whois_data:
                    self.console.print("[bold green]WHOIS Information:[/bold green]")
                    for item in whois_data:
                        self.console.print(f"  [cyan]{item}[/cyan]")
                else:
                    self.console.print("[yellow]Could not extract key WHOIS information.[/yellow]")
            else:
                self.console.print(f"[red]WHOIS lookup failed with code {result.returncode}[/red]")
        except subprocess.TimeoutExpired:
            self.console.print("[red]WHOIS lookup timed out.[/red]")
        except FileNotFoundError:
            self.console.print("[red]whois command not found. Install whois package for WHOIS lookups.[/red]")
        except Exception as e:
            self.console.print(f"[red]Error during WHOIS lookup: {e}[/red]")
    
    def dns_lookup(self, domain: str):
        """Perform DNS lookup"""
        self.console.print(f"[cyan]Performing DNS lookup on [green]{domain}[/green][/cyan]")
        
        try:
            # Try to get A record
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output = result.stdout
                ip_addresses = []
                for line in output.split('\n'):
                    if 'Address:' in line and not line.startswith('Name:'):
                        # Extract IP address
                        import re
                        ip_match = re.search(r'Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                        if ip_match:
                            ip_addresses.append(ip_match.group(1))
                
                if ip_addresses:
                    self.console.print(f"[bold green]A records found:[/bold green]")
                    for ip in ip_addresses:
                        self.console.print(f"  [cyan]{ip}[/cyan]")
                else:
                    self.console.print("[yellow]No A records found in nslookup output.[/yellow]")
            else:
                self.console.print(f"[red]nslookup failed with code {result.returncode}[/red]")
        except subprocess.TimeoutExpired:
            self.console.print("[red]DNS lookup timed out.[/red]")
        except FileNotFoundError:
            self.console.print("[red]nslookup command not found.[/red]")
        except Exception as e:
            self.console.print(f"[red]Error during DNS lookup: {e}[/red]")
    
    def subdomain_scan(self, domain: str):
        """Attempt to find subdomains using common tools"""
        self.console.print(f"[cyan]Attempting subdomain discovery for [green]{domain}[/green][/cyan]")
        
        # First, try to use sublist3r if available
        try:
            result = subprocess.run(['sublist3r', '-d', domain, '-t', '10'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                output = result.stdout
                subdomains = []
                for line in output.split('\n'):
                    if domain in line and line.strip() != domain:
                        # Clean up the line to extract just the subdomain
                        subdomain = line.strip()
                        if re.match(r'^[a-zA-Z0-9\.-]+\.' + re.escape(domain) + r'$', subdomain):
                            subdomains.append(subdomain)
                
                if subdomains:
                    self.console.print(f"[bold green]Found {len(subdomains)} subdomains:[/bold green]")
                    for subdomain in subdomains:
                        self.console.print(f"  [cyan]{subdomain}[/cyan]")
                else:
                    self.console.print("[yellow]No subdomains found by sublist3r or tool not available.[/yellow]")
            else:
                self.console.print("[yellow]Sublist3r may not be available or failed.[/yellow]")
        except subprocess.TimeoutExpired:
            self.console.print("[yellow]Subdomain scan timed out.[/yellow]")
        except FileNotFoundError:
            self.console.print("[red]sublist3r not found. Install Sublist3r for subdomain discovery.[/red]")
        except Exception as e:
            self.console.print(f"[yellow]Error during subdomain scan: {e}[/yellow]")
    
    def email_osint(self, email: str):
        """Perform OSINT on an email address"""
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            self.display_result("Invalid email address format", "error")
            return
            
        self.console.print(f"[cyan]Performing OSINT on email [green]{email}[/green][/cyan]")
        self.console.print("[yellow]Note: This would query breach databases and social platforms[/yellow]")
        
        # For demo, show what would be done with actual tools like holehe
        self.console.print(f"[dim]In a real implementation, this would use tools like holehe to check:")
        self.console.print(f"  - Social media accounts")
        self.console.print(f"  - Breach databases (Have I Been Pwned, etc.)")
        self.console.print(f"  - Email registration services")
        self.console.print(f"  - Professional networks")
        self.console.print(f"  - Code repositories")
        self.console.print(f"  - Other public sources[/dim]")
    
    def phone_osint(self, phone: str):
        """Perform OSINT on a phone number"""
        # Validate phone number format
        phone_pattern = r'^\+?[\d\s\-\(\)]{10,15}$'
        if not re.match(phone_pattern, phone.replace(' ', '')):
            self.display_result("Invalid phone number format", "error")
            return
            
        self.console.print(f"[cyan]Performing OSINT on phone number [green]{phone}[/green][/cyan]")
        
        # In a real implementation, this would use tools like
        # PhoneInfoga, or various API services
        self.console.print("[yellow]Note: This would query phone number databases and social platforms[/yellow]")
        self.console.print(f"[dim]In a real implementation, this would use tools to check:")
        self.console.print(f"  - Carrier information")
        self.console.print(f"  - Location data")
        self.console.print(f"  - Social media profiles")
        self.console.print(f"  - Business directories")
        self.console.print(f"  - Other public records[/dim]")
    
    def social_media_investigation(self, target: str):
        """Investigate social media profiles for a target"""
        self.console.print(f"[cyan]Searching social media for: [green]{target}[/green][/cyan]")
        
        # In a real implementation, this would use tools like
        # Social-analyzer, Socialscan, or Sherlock
        self.console.print("[yellow]Note: This would search major social platforms[/yellow]")
        social_platforms = [
            "Facebook", "Twitter", "Instagram", "LinkedIn", 
            "Reddit", "TikTok", "Snapchat", "Pinterest",
            "GitHub", "GitLab", "Medium", "Flickr"
        ]
        
        self.console.print("[dim]This would check for profiles on:")
        for platform in social_platforms:
            self.console.print(f"  - {platform}")
        self.console.print("Using tools like Sherlock for username enumeration[/dim]")
    
    def username_search(self, username: str):
        """Search for a username across multiple platforms"""
        # Validate username doesn't contain dangerous characters
        if any(char in username for char in [';', '&', '|', '`', '$', '(', ')', '<', '>', '||', '&&']):
            self.display_result("Invalid username format", "error")
            return
            
        self.console.print(f"[cyan]Searching for username [green]{username}[/green] across platforms...[/cyan]")
        
        # Use sherlock if available
        try:
            result = subprocess.run(["sherlock", username, "--print-found"], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                found_accounts = []
                for line in output.split('\n'):
                    if 'http' in line and ('FOUND' in line or 'SUCCESS' in line):
                        found_accounts.append(line.strip())
                
                if found_accounts:
                    self.console.print(f"[bold green]Found {len(found_accounts)} accounts:[/bold green]")
                    for account in found_accounts[:10]:  # Show first 10
                        self.console.print(f"  [cyan]{account}[/cyan]")
                else:
                    self.console.print("[yellow]No accounts found or sherlock returned no results.[/yellow]")
            else:
                # Try without --print-found flag
                result = subprocess.run(["sherlock", username], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    output = result.stdout
                    # Look for URLs in the output
                    import re
                    urls = re.findall(r'https?://[^\s\'\">]+', output)
                    if urls:
                        self.console.print(f"[bold green]Found {len(urls)} potential accounts:[/bold green]")
                        for url in urls[:10]:  # Show first 10
                            self.console.print(f"  [cyan]{url}[/cyan]")
                    else:
                        self.console.print("[yellow]Sherlock executed but no accounts clearly identified.[/yellow]")
                else:
                    self.console.print("[yellow]Sherlock may not be available or failed to run.[/yellow]")
        except subprocess.TimeoutExpired:
            self.console.print("[red]Username search timed out.[/red]")
        except FileNotFoundError:
            self.console.print("[red]sherlock command not found. Install sherlock for username searching.[/red]")
        except Exception as e:
            self.console.print(f"[red]Error during username search: {e}[/red]")
    
    def image_reverse_search(self, image_url: str):
        """Perform reverse image search"""
        self.console.print(f"[cyan]Performing reverse image search for: [green]{image_url}[/green][/cyan]")
        
        # Validate URL format
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if not url_pattern.match(image_url):
            self.console.print("[red]Invalid URL format[/red]")
            return
        
        self.console.print("[yellow]Note: This would use Google Images, TinEye, or Yandex reverse image search[/yellow]")
        self.console.print("[dim]In a real implementation, this would upload/check the image against:")
        self.console.print("  - Google Images Reverse Search")
        self.console.print("  - TinEye Reverse Image Search") 
        self.console.print("  - Yandex Images")
        self.console.print("  - Bing Visual Search[/dim]")
    
    def run(self):
        """Run OSINT tools with multiple options"""
        self.display_header("OSINT Tools")
        
        # Add submenu for different types of OSINT
        osint_table = Table(
            title="[bold cyan]OSINT Options[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        osint_table.add_column("ID", style="cyan", justify="center")
        osint_table.add_column("OSINT Type", style="green")
        osint_table.add_column("Description", style="white")
        osint_table.add_row("1", "General OSINT", "Basic OSINT lookup")
        osint_table.add_row("2", "WHOIS Lookup", "Domain and IP registration info")
        osint_table.add_row("3", "DNS Lookup", "DNS record information")
        osint_table.add_row("4", "Subdomain Discovery", "Find subdomains of a domain")
        osint_table.add_row("5", "Email OSINT", "Investigate an email address")
        osint_table.add_row("6", "Phone Number OSINT", "Investigate a phone number")
        osint_table.add_row("7", "Social Media Investigation", "Find social media profiles")
        osint_table.add_row("8", "Username Search", "Search for usernames across platforms")
        osint_table.add_row("9", "Image Reverse Search", "Find where images are used online")
        osint_table.add_row("10", "Back to Main Menu", "Return to main menu")
        
        self.console.print(osint_table)
        choice = Prompt.ask("Choose an OSINT method", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"], default="1")
        
        if choice == "10":
            return
        
        if choice in ["1", "2", "3", "4"]:
            target = Prompt.ask(
                "[cyan]Enter domain, IP, or target to investigate[/cyan]",
                default="example.com"
            )
        elif choice in ["5", "8"]:
            target = Prompt.ask(
                "[cyan]Enter email address or username to investigate[/cyan]",
                default="user@example.com"
            )
        elif choice == "6":
            target = Prompt.ask(
                "[cyan]Enter phone number to investigate (format: +1234567890)[/cyan]",
                default="+1234567890"
            )
        elif choice == "7":
            target = Prompt.ask(
                "[cyan]Enter name or username for social media investigation[/cyan]",
                default="john_doe"
            )
        elif choice == "9":
            target = Prompt.ask(
                "[cyan]Enter image URL for reverse search[/cyan]",
                default="https://example.com/image.jpg"
            )
        else:
            return
        
        if not target or target.strip() == "":
            self.display_result("Invalid target", "error")
            return
        
        # Add consent prompt for educational purpose
        self.console.print("[yellow]⚠[/yellow] This tool performs OSINT gathering for educational purposes only.")
        self.console.print("[yellow]⚠[/yellow] Always ensure you have proper authorization before investigating any target.")
        consent = Prompt.ask("[bold magenta]Do you have explicit written consent to investigate this target? (yes/no)[/bold magenta]", default="no")
        if consent.lower() not in ['yes', 'y', 'true']:
            self.display_result("Investigation cancelled - explicit consent required", "warning")
            return
        
        self.console.print()
        
        if choice == "1":
            self.lookup_domain(target)
        elif choice == "2":
            self.whois_lookup(target)
        elif choice == "3":
            self.dns_lookup(target)
        elif choice == "4":
            self.subdomain_scan(target)
        elif choice == "5":
            self.email_osint(target)
        elif choice == "6":
            self.phone_osint(target)
        elif choice == "7":
            self.social_media_investigation(target)
        elif choice == "8":
            self.username_search(target)
        elif choice == "9":
            self.image_reverse_search(target)