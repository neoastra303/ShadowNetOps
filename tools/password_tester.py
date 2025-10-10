"""Password Strength Tester"""

import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.prompt import Prompt
from rich import box


class PasswordTester:
    def __init__(self, console: Console):
        self.console = console
        
    def analyze_password(self, password: str):
        """Analyze password strength"""
        checks = {
            "Length (≥12 chars)": len(password) >= 12,
            "Uppercase letters": bool(re.search(r'[A-Z]', password)),
            "Lowercase letters": bool(re.search(r'[a-z]', password)),
            "Numbers": bool(re.search(r'[0-9]', password)),
            "Special characters": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        score = sum(checks.values())
        
        # Determine strength
        if score == 0:
            strength = "Very Weak"
            color = "red"
            crack_time = "Instant"
            percentage = 0
        elif score == 1:
            strength = "Weak"
            color = "red"
            crack_time = "Minutes"
            percentage = 20
        elif score == 2:
            strength = "Fair"
            color = "yellow"
            crack_time = "Hours"
            percentage = 40
        elif score == 3:
            strength = "Good"
            color = "magenta"
            crack_time = "Days"
            percentage = 60
        elif score == 4:
            strength = "Strong"
            color = "cyan"
            crack_time = "Months"
            percentage = 80
        else:
            strength = "Very Strong"
            color = "green"
            crack_time = "Years"
            percentage = 100
        
        return checks, strength, color, crack_time, percentage
    
    def run(self):
        """Run password strength tester"""
        self.console.print("[bold cyan]═══ Password Strength Tester ═══[/bold cyan]")
        self.console.print()
        
        password = Prompt.ask(
            "[cyan]Enter password to test[/cyan]",
            password=True
        )
        
        if not password:
            self.console.print("[bold red]✗ Error:[/bold red] No password provided")
            return
        
        self.console.print()
        
        checks, strength, color, crack_time, percentage = self.analyze_password(password)
        
        # Display strength meter
        self.console.print(Panel(
            f"[bold {color}]Strength: {strength}[/bold {color}]",
            border_style=color
        ))
        self.console.print()
        
        # Progress bar
        with Progress(
            TextColumn("[bold cyan]Strength Score"),
            BarColumn(bar_width=40),
            TextColumn("[bold]{task.percentage:>3.0f}%"),
            console=self.console
        ) as progress:
            task = progress.add_task("", total=100)
            progress.update(task, completed=percentage)
        
        self.console.print()
        
        # Requirements table
        table = Table(
            title="[bold cyan]Security Requirements[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        
        table.add_column("Requirement", style="white")
        table.add_column("Status", justify="center")
        
        for requirement, passed in checks.items():
            status = "[bold green]✓ PASS[/bold green]" if passed else "[bold red]✗ FAIL[/bold red]"
            table.add_row(requirement, status)
        
        self.console.print(table)
        self.console.print()
        
        # Summary
        self.console.print(Panel(
            f"[bold cyan]Estimated crack time:[/bold cyan] [{color}]{crack_time}[/{color}]\n"
            f"[dim]Note: This is a simplified estimation based on common attack vectors[/dim]",
            border_style="cyan"
        ))
