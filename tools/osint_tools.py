"""OSINT (Open Source Intelligence) Tools"""

import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import track
from rich import box


class OSINTTools:
    def __init__(self, console: Console):
        self.console = console
        
    def lookup_domain(self, target: str):
        """Simulate domain/IP/email OSINT lookup"""
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
        
        for source in track(data_sources, description="[cyan]Gathering intelligence..."):
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
        self.console.print("[bold green]✓[/bold green] Intelligence gathering complete")
        
    def run(self):
        """Run OSINT tools"""
        self.console.print("[bold cyan]═══ OSINT Tools ═══[/bold cyan]")
        self.console.print()
        
        self.console.print("[dim]Available lookup types:[/dim]")
        self.console.print("  [cyan]•[/cyan] Domain (e.g., example.com)")
        self.console.print("  [cyan]•[/cyan] IP Address (e.g., 192.168.1.1)")
        self.console.print("  [cyan]•[/cyan] Email (e.g., user@example.com)")
        self.console.print()
        
        target = Prompt.ask(
            "[cyan]Enter target to investigate[/cyan]",
            default="example.com"
        )
        
        if not target or target.strip() == "":
            self.console.print("[bold red]✗ Error:[/bold red] Invalid target")
            return
        
        self.console.print()
        self.lookup_domain(target)
