"""Network Reconnaissance Tool"""

import time
import random
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich.prompt import Prompt
from rich import box


class NetworkRecon:
    def __init__(self, console: Console):
        self.console = console
        
    def scan_ports(self, target: str):
        """Simulate port scanning"""
        common_ports = [
            (22, "SSH", "open"),
            (80, "HTTP", "open"),
            (443, "HTTPS", "open"),
            (21, "FTP", random.choice(["open", "closed"])),
            (25, "SMTP", random.choice(["closed", "filtered"])),
            (3306, "MySQL", random.choice(["open", "closed"])),
            (5432, "PostgreSQL", random.choice(["open", "closed"])),
            (8080, "HTTP-Proxy", random.choice(["open", "filtered"])),
            (3389, "RDP", random.choice(["closed", "filtered"])),
            (27017, "MongoDB", random.choice(["open", "closed"])),
        ]
        
        self.console.print(Panel(
            f"[bold cyan]Scanning target: [green]{target}[/green][/bold cyan]",
            border_style="cyan"
        ))
        self.console.print()
        
        results = []
        for port, service, status in track(common_ports, description="[cyan]Scanning ports..."):
            time.sleep(0.1)  # Simulate scanning
            results.append((port, service, status))
        
        # Display results
        table = Table(
            title="[bold cyan]Port Scan Results[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        
        table.add_column("Port", style="cyan", justify="center")
        table.add_column("Service", style="white")
        table.add_column("Status", justify="center")
        
        open_count = 0
        for port, service, status in results:
            if status == "open":
                status_display = f"[bold green]{status.upper()}[/bold green]"
                open_count += 1
            elif status == "closed":
                status_display = f"[dim]{status.upper()}[/dim]"
            else:
                status_display = f"[yellow]{status.upper()}[/yellow]"
            
            table.add_row(str(port), service, status_display)
        
        self.console.print(table)
        self.console.print()
        self.console.print(f"[bold green]✓[/bold green] Scan complete: {open_count} open ports found")
        
    def run(self):
        """Run network reconnaissance"""
        self.console.print("[bold cyan]═══ Network Reconnaissance ═══[/bold cyan]")
        self.console.print()
        
        target = Prompt.ask(
            "[cyan]Enter target IP or domain[/cyan]",
            default="192.168.1.1"
        )
        
        if not target or target.strip() == "":
            self.console.print("[bold red]✗ Error:[/bold red] Invalid target")
            return
        
        self.console.print()
        self.scan_ports(target)
