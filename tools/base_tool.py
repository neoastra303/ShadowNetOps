"""
Abstract base class for all RedTeam Terminal tools
"""

from abc import ABC, abstractmethod
from rich.console import Console
from typing import Optional


class BaseTool(ABC):
    """
    Abstract base class for all RedTeam tools
    All tool modules should inherit from this class
    """
    
    def __init__(self, console: Console):
        self.console = console
    
    @abstractmethod
    def run(self) -> None:
        """
        Execute the tool's main functionality
        This method must be implemented by all subclasses
        """
        pass
    
    def display_header(self, title: str) -> None:
        """Display a consistent header for the tool"""
        self.console.print(f"[bold cyan]═══ {title} ═══[/bold cyan]")
        self.console.print()
    
    def display_result(self, result: str, status: str = "info") -> None:
        """Display a standardized result message"""
        if status == "success":
            self.console.print(f"[bold green]✓[/bold green] {result}")
        elif status == "warning":
            self.console.print(f"[bold yellow]⚠[/bold yellow] {result}")
        elif status == "error":
            self.console.print(f"[bold red]✗[/bold red] {result}")
        else:
            self.console.print(f"[bold blue]ℹ[/bold blue] {result}")
    
    def validate_input(self, input_value: str) -> bool:
        """
        Validate user input to prevent command injection and other attacks
        Override this method in subclasses for specific validation rules
        """
        # Default validation: check for dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '||', '&&']
        return not any(char in input_value for char in dangerous_chars)