#!/usr/bin/env python3
"""
Quick demo of RedTeam Terminal capabilities
Run this to see what the application can do without interactive input
"""

from rich.console import Console
from rich.panel import Panel
from rich import box
from pyfiglet import figlet_format
import time

console = Console()

# Display banner
banner = figlet_format("RedTeam", font="slant")
console.print(f"[bold cyan]{banner}[/bold cyan]")
console.print(Panel(
    "[bold magenta]Terminal v2.1.0 - Demo Mode[/bold magenta]\n"
    "[cyan]Cybersecurity Operations Platform[/cyan]",
    border_style="cyan",
    box=box.DOUBLE
))
console.print()

# Demonstrate each tool
console.print("[bold cyan]🔍 Demonstrating Network Reconnaissance[/bold cyan]")
console.print()
time.sleep(1)

from tools.network_recon import NetworkRecon
from tools.vuln_scanner import VulnScanner
from tools.password_tester import PasswordTester

# Network Recon Demo
recon = NetworkRecon(console)
console.print("[cyan]Simulating port scan on 192.168.1.1...[/cyan]")
recon.scan_ports("192.168.1.1")
console.print()
console.print("[dim]─" * 80 + "[/dim]")
console.print()

time.sleep(2)

# Vulnerability Demo
console.print("[bold cyan]🛡️ Demonstrating Vulnerability Assessment[/bold cyan]")
console.print()
vuln = VulnScanner(console)
console.print("[cyan]Scanning example.com for vulnerabilities...[/cyan]")
vuln.scan_vulnerabilities("example.com")
console.print()
console.print("[dim]─" * 80 + "[/dim]")
console.print()

time.sleep(2)

# Password Demo
console.print("[bold cyan]🔑 Demonstrating Password Strength Test[/bold cyan]")
console.print()
pwd = PasswordTester(console)
console.print("[cyan]Testing password: 'MyP@ssw0rd123!'[/cyan]")
console.print()
checks, strength, color, crack_time, percentage = pwd.analyze_password("MyP@ssw0rd123!")

console.print(Panel(
    f"[bold {color}]Strength: {strength}[/bold {color}]\n"
    f"Estimated crack time: [{color}]{crack_time}[/{color}]",
    border_style=color
))
console.print()
console.print("[dim]─" * 80 + "[/dim]")
console.print()

# Final message
console.print(Panel(
    "[bold green]✓ Demo Complete![/bold green]\n\n"
    "[cyan]To run the full interactive terminal:[/cyan]\n"
    "  [bold]python redteam.py[/bold]\n\n"
    "[dim]All tools include interactive prompts and full functionality[/dim]",
    title="[bold cyan]RedTeam Terminal[/bold cyan]",
    border_style="cyan"
))
