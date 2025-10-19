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
            # For Windows, we need to handle the command differently
            if sys.platform.startswith('win'):
                result = subprocess.run(['where', tool_name], 
                                      stdout=subprocess.DEVNULL, 
                                      stderr=subprocess.DEVNULL,
                                      shell=True)
            else:
                result = subprocess.run(['which', tool_name], 
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
        Attempt to install a single tool based on the OS
        """
        os_name = sys.platform
        try:
            if os_name.startswith('linux'):
                # For apt-based systems
                if tool_name in ['nmap', 'netdiscover', 'tcpdump', 'tshark', 'sqlmap', 'nikto', 'theharvester', 'whatweb', 'subfinder', 'wifite']:
                    result = subprocess.run(['sudo', 'apt', 'install', '-y', tool_name], 
                                          capture_output=True, text=True)
                    return result.returncode == 0
                elif tool_name in ['airodump-ng', 'aircrack-ng']:
                    result = subprocess.run(['sudo', 'apt', 'install', '-y', 'aircrack-ng'], 
                                          capture_output=True, text=True)
                    return result.returncode == 0
                elif tool_name in ['autopsy', 'sleuthkit']:
                    result = subprocess.run(['sudo', 'apt', 'install', '-y', 'sleuthkit'], 
                                          capture_output=True, text=True)
                    return result.returncode == 0
                elif tool_name in ['sherlock', 'holehe', 'h8mail', 'sublist3r']:
                    result = subprocess.run(['pip', 'install', tool_name.replace('-', '_')], 
                                          capture_output=True, text=True)
                    return result.returncode == 0
            elif os_name.startswith('darwin'):  # macOS
                if tool_name in ['nmap', 'tcpdump', 'tshark', 'sqlmap', 'nikto', 'theharvester', 'whatweb', 'subfinder']:
                    result = subprocess.run(['brew', 'install', tool_name], 
                                          capture_output=True, text=True)
                    return result.returncode == 0
                elif tool_name in ['sherlock', 'holehe', 'h8mail', 'sublist3r']:
                    result = subprocess.run(['pip', 'install', tool_name.replace('-', '_')], 
                                          capture_output=True, text=True)
                    return result.returncode == 0
        except Exception as e:
            self.console.print(f"[red]Error installing {tool_name}: {e}[/red]")
            return False
        
        return False
    
    def install_missing_tools(self, tool_category: str) -> bool:
        """
        Install all missing tools for a category
        
        Args:
            tool_category: Category of tools to install
            
        Returns:
            True if all tools were successfully installed, False otherwise
        """
        missing_tools = self.get_missing_tools(tool_category)
        
        if not missing_tools:
            self.console.print(f"[bold green]✓ All required tools for {tool_category} are already installed![/bold green]")
            return True
        
        self.console.print(f"[bold yellow]Installing missing tools for {tool_category}:[/bold yellow]")
        
        installed_count = 0
        for tool in missing_tools:
            self.console.print(f"[cyan]Installing {tool}...[/cyan]")
            success = self.install_tool(tool)
            if success:
                self.console.print(f"[bold green]✓ {tool} installed successfully[/bold green]")
                installed_count += 1
            else:
                self.console.print(f"[bold red]✗ Failed to install {tool}[/bold red]")
        
        self.console.print(f"[bold]Installation complete: {installed_count}/{len(missing_tools)} tools installed[/bold]")
        
        # Re-check to see if any tools are still missing
        still_missing = self.get_missing_tools(tool_category)
        if still_missing:
            self.console.print(f"[yellow]Still missing tools: {', '.join(still_missing)}[/yellow]")
            return False
        else:
            self.console.print(f"[bold green]✓ All tools for {tool_category} are now installed![/bold green]")
            return True
    
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