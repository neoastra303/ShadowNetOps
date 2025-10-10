#!/usr/bin/env python3
"""
RedTeam Terminal - Cybersecurity Operations CLI
A cyberpunk-themed terminal tool for penetration testing and security operations
"""

import sys
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

colorama_init()
console = Console()


class RedTeamTerminal:
    def __init__(self):
        self.console = console
        self.network_recon = NetworkRecon(console)
        self.vuln_scanner = VulnScanner(console)
        self.password_tester = PasswordTester(console)
        self.osint_tools = OSINTTools(console)
        
    def display_banner(self):
        """Display cyberpunk ASCII art banner"""
        banner = figlet_format("RedTeam", font="slant")
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        self.console.print(Panel(
            "[bold magenta]Terminal v2.1.0[/bold magenta]\n"
            "[cyan]Cybersecurity Operations Platform[/cyan]\n"
            "[dim]Network Recon | Vuln Assessment | Password Testing | OSINT[/dim]",
            border_style="cyan",
            box=box.DOUBLE
        ))
        self.console.print()

    def display_menu(self):
        """Display main menu"""
        table = Table(
            title="[bold cyan]⚡ Available Tools ⚡[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white")
        
        table.add_row("1", "Network Reconnaissance", "Port scanning and network discovery")
        table.add_row("2", "Vulnerability Assessment", "CVE database and security scanning")
        table.add_row("3", "Password Strength Tester", "Analyze password security")
        table.add_row("4", "OSINT Tools", "Open-source intelligence gathering")
        table.add_row("5", "Exit", "Quit the terminal")
        
        self.console.print(table)
        self.console.print()

    def run(self):
        """Main application loop"""
        self.display_banner()
        
        while True:
            self.display_menu()
            
            choice = Prompt.ask(
                "[bold cyan]redteam@cyber[/bold cyan] [bold magenta]~$[/bold magenta]",
                choices=["1", "2", "3", "4", "5"]
            )
            
            self.console.print()
            
            if choice == "1":
                self.network_recon.run()
            elif choice == "2":
                self.vuln_scanner.run()
            elif choice == "3":
                self.password_tester.run()
            elif choice == "4":
                self.osint_tools.run()
            elif choice == "5":
                self.console.print("[bold cyan]Shutting down RedTeam Terminal...[/bold cyan]")
                self.console.print("[bold green]✓[/bold green] Session terminated")
                sys.exit(0)
            
            self.console.print()
            self.console.print("[dim]─" * 80 + "[/dim]")
            self.console.print()


def main():
    """Entry point"""
    try:
        terminal = RedTeamTerminal()
        terminal.run()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠[/bold yellow] Interrupted by user")
        console.print("[bold cyan]Shutting down RedTeam Terminal...[/bold cyan]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
