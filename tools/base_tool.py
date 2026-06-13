"""
Abstract base class for all ShadowNetOps tools
"""

import re
from abc import ABC, abstractmethod
from rich.console import Console
from typing import Optional
import questionary
from questionary import Style


CYBER_STYLE = Style([
    ("qmark", "fg:ansicyan bold"),
    ("question", "bold"),
    ("pointer", "fg:ansicyan bold"),
    ("highlighted", "fg:ansicyan bold"),
    ("selected", "fg:ansigreen bold"),
    ("separator", "fg:ansicyan"),
    ("instruction", "fg:ansiwhite"),
    ("answer", "fg:ansigreen bold"),
])


URL_PATTERN = re.compile(
    r'^https?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
    r'localhost|'
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
)

IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/(\d|[1-2]\d|3[0-2]))?$')

DANGEROUS_CHARS = [';', '&', '|', '`', '$', '(', ')', '<', '>', '||', '&&']


class BaseTool(ABC):
    """
    Abstract base class for all ShadowNetOps tools
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
        return not any(char in input_value for char in DANGEROUS_CHARS)
    
    @staticmethod
    def validate_url(url: str) -> bool:
        return bool(URL_PATTERN.match(url))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        return bool(DOMAIN_PATTERN.match(domain))
    
    @staticmethod
    def validate_target(target: str) -> bool:
        if IP_PATTERN.match(target) or DOMAIN_PATTERN.match(target):
            return not any(char in target for char in DANGEROUS_CHARS)
        return False