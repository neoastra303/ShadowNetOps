"""
Dependency Manager for RedTeam Terminal
Handles checking for and installing required external tools
"""

import subprocess
import sys
import os
from typing import List, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt


class DependencyManager:
    """
    Dependency manager for checking and installing required tools
    """
    
    def __init__(self, console: Console):
        self.console = console
        # Define required tools for different tool categories
        self.required_tools = {
            'osint': ['holehe', 'h8mail', 'sherlock', 'theharvester', 'sublist3r', 'social-analyzer', 'phoneinfoga'],
            'web': ['sqlmap', 'xsstrike', 'ffuf', 'nikto', 'whatweb', 'subfinder'],
            'wireless': ['airodump-ng', 'aircrack-ng', 'hashcat', 'wifite', 'blue_hydra'],
            'forensics': ['autopsy', 'sleuthkit', 'volatility', 'tcpdump', 'tshark'],
            'misc': ['nmap', 'netdiscover', 'enum4linux']
        }
    
    def check_tool_exists(self, tool_name: str) -> bool:
        """
        Check if a tool exists in the system
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool exists, False otherwise
        """
        try:
            cmd = ['where'] if sys.platform.startswith('win') else ['which']
            result = subprocess.run(cmd + [tool_name],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_missing_tools(self, tool_category: str) -> List[str]:
        """
        Get a list of missing tools for a specific category
        
        Args:
            tool_category: Category of tools to check
            
        Returns:
            List of missing tool names
        """
        if tool_category not in self.required_tools:
            return []
        
        missing_tools = []
        for tool in self.required_tools[tool_category]:
            if not self.check_tool_exists(tool):
                missing_tools.append(tool)
        
        return missing_tools
    
    def display_missing_tools(self, tool_category: str) -> bool:
        """
        Display missing tools for a category and return if any are missing
        
        Args:
            tool_category: Category of tools to check
            
        Returns:
            True if all tools are present, False if any are missing
        """
        missing_tools = self.get_missing_tools(tool_category)
        
        if missing_tools:
            self.console.print(f"\n[bold yellow]⚠ Missing tools for {tool_category}:[/bold yellow]")
            for tool in missing_tools:
                self.console.print(f"  - [red]{tool}[/red]")
            
            self.console.print(f"\n[yellow]These tools need to be installed for {tool_category} functionality.[/yellow]")
            self.console.print("[yellow]Please install them using your system's package manager or from their official sources.[/yellow]")
            
            # Provide installation guidance based on OS
            self.show_installation_guide(tool_category, missing_tools)
            return False
        else:
            self.console.print(f"\n[bold green]✓ All required tools for {tool_category} are installed![/bold green]")
            return True
    
    def show_installation_guide(self, tool_category: str, missing_tools: List[str]) -> None:
        """
        Show installation instructions for missing tools based on the OS
        """
        os_name = sys.platform
        self.console.print(f"\n[bold cyan]Installation Guide for {os_name}:[/bold cyan]")
        
        # Create a table showing installation commands
        table = Table(title="[bold]Installation Commands[/bold]", 
                     show_header=True, 
                     header_style="bold magenta",
                     border_style="cyan")
        table.add_column("Tool", style="cyan")
        table.add_column("Installation Command", style="white")
        
        for tool in missing_tools:
            if os_name.startswith('linux'):
                if tool in ['nmap', 'netdiscover', 'tcpdump', 'tshark']:
                    table.add_row(tool, f"sudo apt install {tool} # Debian/Ubuntu")
                    table.add_row("", f"sudo yum install {tool} # RHEL/CentOS")
                elif tool in ['sqlmap', 'nikto', 'theharvester', 'whatweb', 'subfinder', 'wifite']:
                    table.add_row(tool, f"sudo apt install {tool}")
                elif tool in ['sherlock', 'holehe', 'h8mail', 'sublist3r']:
                    table.add_row(tool, f"pip install {tool.replace('-', '_')}")
                elif tool in ['airodump-ng', 'aircrack-ng']:
                    table.add_row(tool, f"sudo apt install aircrack-ng")
                elif tool in ['autopsy', 'sleuthkit']:
                    table.add_row(tool, f"sudo apt install sleuthkit")
            elif os_name.startswith('darwin'):  # macOS
                if tool in ['nmap', 'netdiscover', 'tcpdump', 'tshark']:
                    table.add_row(tool, f"brew install {tool}")
                elif tool in ['sqlmap', 'nikto', 'theharvester', 'whatweb', 'subfinder']:
                    table.add_row(tool, f"brew install {tool}")
                elif tool in ['sherlock', 'holehe', 'h8mail', 'sublist3r']:
                    table.add_row(tool, f"pip install {tool.replace('-', '_')}")
            elif os_name.startswith('win'):  # Windows
                table.add_row(tool, f"Download from official source or use: pip install {tool}")
        
        self.console.print(table)
        
        # Provide general installation notes
        self.console.print("\n[bold]Note:[/bold]")
        self.console.print("[yellow]• Some tools may require additional dependencies[/yellow]")
        self.console.print("[yellow]• Consider using a security-focused Linux distribution like Kali Linux[/yellow]")
        self.console.print("[yellow]• Always download tools from official sources for security[/yellow]")
    
    def install_tool(self, tool_name: str) -> bool:
        """
        Show installation instructions for a tool (removed auto-install for security)
        """
        self.console.print(f"[yellow]Auto-install is disabled for security. Please install '{tool_name}' manually.[/yellow]")
        self.console.print(f"[yellow]See: {self.get_tool_url(tool_name)}[/yellow]")
        return False
    
    def get_tool_url(self, tool_name: str) -> str:
        """Return installation URL/reference for a tool"""
        pip_tools = {'sherlock', 'holehe', 'h8mail', 'sublist3r', 'xsstrike', 'blue_hydra'}
        apt_tools = {'nmap', 'sqlmap', 'nikto', 'whatweb', 'wifite', 'tcpdump', 'tshark', 'aircrack-ng', 'reaver'}
        
        if tool_name in pip_tools:
            return f"pip install {tool_name.replace('-', '_')}"
        elif tool_name in apt_tools:
            return "sudo apt install " + ('aircrack-ng' if tool_name in ('airodump-ng', 'aircrack-ng') else tool_name)
        elif tool_name == 'theharvester':
            return "sudo apt install theharvester  # or: git clone https://github.com/laramies/theHarvester.git"
        elif tool_name == 'subfinder':
            return "sudo apt install subfinder  # or: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        elif tool_name == 'hashcat':
            return "sudo apt install hashcat  # or: https://hashcat.net/hashcat/"
        elif tool_name in ('autopsy', 'sleuthkit'):
            return "sudo apt install sleuthkit  # or: https://www.sleuthkit.org/autopsy/download.php"
        else:
            return f"https://github.com/search?q={tool_name}"
    
    def install_missing_tools(self, tool_category: str) -> bool:
        """
        Show installation guide for missing tools (auto-install removed for security)
        
        Args:
            tool_category: Category of tools to install
            
        Returns:
            Always returns False (user must install manually)
        """
        missing_tools = self.get_missing_tools(tool_category)
        
        if not missing_tools:
            self.console.print(f"[bold green]✓ All required tools for {tool_category} are already installed![/bold green]")
            return True
        
        self.console.print(f"[bold yellow]To install missing tools for {tool_category}, run:[/bold yellow]")
        for tool in missing_tools:
            self.console.print(f"  [cyan]{tool}:[/cyan] {self.get_tool_url(tool)}")
        
        self.console.print("[yellow]Auto-install is disabled for security. Please install manually.[/yellow]")
        return False
    
    def check_all_dependencies(self) -> Dict[str, List[str]]:
        """
        Check all dependencies across all categories
        
        Returns:
            Dictionary mapping categories to lists of missing tools
        """
        all_missing = {}
        for category in self.required_tools:
            missing = self.get_missing_tools(category)
            if missing:
                all_missing[category] = missing
        
        return all_missing
    
    def display_all_dependencies_status(self) -> None:
        """
        Display the status of all dependencies across categories
        """
        self.console.print("[bold cyan]Dependency Check Results:[/bold cyan]\n")
        
        for category in self.required_tools:
            self.display_missing_tools(category)
            self.console.print()  # Add space between categories


# Global dependency manager instance
def get_dependency_manager(console: Console) -> DependencyManager:
    """
    Get a dependency manager instance
    
    Args:
        console: Rich console instance
        
    Returns:
        DependencyManager instance
    """
    return DependencyManager(console)