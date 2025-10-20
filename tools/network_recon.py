"""Network Reconnaissance Tool"""

import time
import socket
import threading
from typing import List, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.prompt import Prompt
from rich import box
from .base_tool import BaseTool
try:
    from ..config_manager import get_config_manager
except ImportError:
    # Fallback for when run directly
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config_manager import get_config_manager


class NetworkRecon(BaseTool):
    def __init__(self, console: Console):
        super().__init__(console)
        self.open_ports = []
        self.lock = threading.Lock()
        self.config_manager = get_config_manager()
        
    def scan_port(self, target: str, port: int, timeout: float = 1.0) -> Tuple[int, str, str]:
        """Scan a single port on the target"""
        # Check if we're in simulation mode
        simulation_mode = self.config_manager.get_boolean('NETWORK_RECON', 'simulation_mode', fallback=True)
        
        if simulation_mode:
            # In simulation mode, return known results for common ports
            service = self.get_common_service(port)
            # Simulate results - return open for some known ports, closed for others
            if port in [22, 80, 443, 3389, 3306, 5432]:
                return port, service, "open"
            else:
                return port, service, "closed"
        else:
            # In real mode, perform actual scanning
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                service = self.get_common_service(port)
                if result == 0:
                    return port, service, "open"
                else:
                    return port, service, "closed"
            except socket.gaierror:
                return port, "Unknown", "error"
            except Exception:
                return port, "Unknown", "filtered"
    
    def get_common_service(self, port: int) -> str:
        """Get common service name for a port"""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet", 
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            9200: "Elasticsearch",
            27017: "MongoDB",
            27018: "MongoDB",
        }
        return common_services.get(port, f"Port-{port}")
    
    def scan_ports_threaded(self, target: str, ports: List[int], timeout: float = 1.0) -> List[Tuple[int, str, str]]:
        """Scan multiple ports using threading"""
        results = []
        
        def scan_worker(port):
            port_num, service, status = self.scan_port(target, port, timeout)
            with self.lock:
                results.append((port_num, service, status))
        
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_worker, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads to prevent overwhelming the system
            if len(threads) >= 50:  # Limit to 50 concurrent connections
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        # Sort results by port number
        results.sort(key=lambda x: x[0])
        return results
    
    def scan_ports(self, target: str) -> None:
        """Perform port scanning"""
        # Validate input to prevent command injection
        if not self.validate_input(target):
            self.display_result("Invalid target format", "error")
            return
        
        # Check if we're in simulation mode
        simulation_mode = self.config_manager.get_boolean('NETWORK_RECON', 'simulation_mode', fallback=True)
        
        if simulation_mode:
            self.console.print("[yellow]Running in simulation mode - showing example results[/yellow]")
        else:
            self.console.print("[green]Running in real mode - performing actual network scanning[/green]")
        
        # Default common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 27018]
        
        self.console.print(Panel(
            f"[bold cyan]Scanning target: [green]{target}[/green][/bold cyan]",
            border_style="cyan"
        ))
        self.console.print()
        
        # Use progress bar to show scanning progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning ports...", total=len(common_ports))
            
            results = []
            for i, port in enumerate(common_ports):
                port_num, service, status = self.scan_port(target, port)
                results.append((port, service, status))
                progress.update(scan_task, advance=1)
                if not simulation_mode:
                    time.sleep(0.01)  # Small delay to avoid overwhelming the target
        
        # Alternative: Use threaded scanning for better performance
        # results = self.scan_ports_threaded(target, common_ports)
        
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
            if status == "closed":
                status_display = f"[dim]{status.upper()}[/dim]"
            elif status == "error":
                status_display = f"[red]{status.upper()}[/red]"
            elif status == "filtered":
                status_display = f"[yellow]{status.upper()}[/yellow]"
            else:
                status_display = f"[bold green]{status.upper()}[/bold green]"
                open_count += 1
            
            table.add_row(str(port), service, status_display)
        
        self.console.print(table)
        self.console.print()
        self.display_result(f"Scan complete: {open_count} open ports found", "success")
        
    def run(self) -> None:
        """Run network reconnaissance"""
        self.display_header("Network Reconnaissance")
        
        # Add submenu for different types of network reconnaissance
        recon_table = Table(
            title="[bold cyan]Network Reconnaissance Options[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        recon_table.add_column("ID", style="cyan", justify="center")
        recon_table.add_column("Recon Type", style="green")
        recon_table.add_column("Description", style="white")
        recon_table.add_row("1", "Port Scanning", "Scan for open ports and services")
        recon_table.add_row("2", "Host Discovery", "Discover live hosts on a network")
        recon_table.add_row("3", "Banner Grabbing", "Retrieve service banners")
        recon_table.add_row("4", "OS Detection", "Detect operating system")
        recon_table.add_row("5", "Traceroute", "Trace network path to target")
        recon_table.add_row("6", "Back to Main Menu", "Return to main menu")
        
        self.console.print(recon_table)
        choice = Prompt.ask("Choose a reconnaissance method", choices=["1", "2", "3", "4", "5", "6"], default="1")
        
        if choice == "6":
            return
        
        target = Prompt.ask(
            "[cyan]Enter target IP or domain[/cyan]",
            default="127.0.0.1"
        )
        
        if not target or target.strip() == "":
            self.display_result("Invalid target", "error")
            return
        
        # Add consent prompt for educational purpose
        self.console.print("[yellow]⚠[/yellow] This tool performs actual network reconnaissance for educational purposes only.")
        self.console.print("[yellow]⚠[/yellow] Always ensure you have proper authorization before scanning any network.")
        consent = Prompt.ask("[bold magenta]Do you have explicit written consent to scan this target? (yes/no)[/bold magenta]", default="no")
        if consent.lower() not in ['yes', 'y', 'true']:
            self.display_result("Scan cancelled - explicit consent required", "warning")
            return
        
        self.console.print()
        
        if choice == "1":
            self.scan_ports(target)
        elif choice == "2":
            self.host_discovery(target)
        elif choice == "3":
            self.banner_grabbing(target)
        elif choice == "4":
            self.os_detection(target)
        elif choice == "5":
            self.traceroute(target)
    
    def host_discovery(self, target: str) -> None:
        """Discover live hosts on a network"""
        import subprocess
        import ipaddress
        
        # Check if we're in simulation mode
        simulation_mode = self.config_manager.get_boolean('NETWORK_RECON', 'simulation_mode', fallback=True)
        
        if simulation_mode:
            self.console.print("[yellow]Running in simulation mode - showing example results[/yellow]")
            # In simulation mode, show example results instead of performing actual network operations
            if '/' in target:
                self.console.print(f"[cyan]Simulating host discovery in network: [green]{target}[/green][/cyan]")
                self.console.print("[bold green]Found 3 live hosts:[/bold green]")
                self.console.print("  - 192.168.1.1")
                self.console.print("  - 192.168.1.10")
                self.console.print("  - 192.168.1.254")
            else:
                self.console.print(f"[cyan]Simulating ping to target: [green]{target}[/green][/cyan]")
                self.console.print(f"[bold green]Host {target} is alive![/bold green]")
            return
        
        # Validate target for network discovery
        try:
            # Check if it's a network range
            if '/' in target:
                network = ipaddress.IPv4Network(target, strict=False)
                self.console.print(f"[cyan]Discovering hosts in network: [green]{target}[/green][/cyan]")
                
                # Try to use nmap for host discovery if available
                try:
                    result = subprocess.run(['nmap', '-sn', str(network), '-oG', '-'], 
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        # Parse hosts from nmap grepable output
                        lines = result.stdout.split('\n')
                        hosts = []
                        for line in lines:
                            if 'Status: Up' in line:
                                match = re.search(r'Host: (\S+)', line)
                                if match:
                                    hosts.append(match.group(1))
                        
                        if hosts:
                            self.console.print(f"[bold green]Found {len(hosts)} live hosts:[/bold green]")
                            for host in hosts:
                                self.console.print(f"  - {host}")
                        else:
                            self.console.print("[yellow]No live hosts found in the network.[/yellow]")
                    else:
                        self.console.print("[red]Nmap failed to discover hosts.[/red]")
                except subprocess.TimeoutExpired:
                    self.console.print("[red]Nmap scan timed out.[/red]")
                except FileNotFoundError:
                    self.console.print("[red]nmap not found. Install nmap for network discovery.[/red]")
                except Exception as e:
                    self.console.print(f"[red]Error during host discovery: {e}[/red]")
            else:
                # Single host - just ping
                self.console.print(f"[cyan]Pinging target: [green]{target}[/green][/cyan]")
                try:
                    import platform
                    param = '-n' if platform.system().lower() == 'windows' else '-c'
                    result = subprocess.run(['ping', param, '1', target], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.console.print(f"[bold green]Host {target} is alive![/bold green]")
                    else:
                        self.console.print(f"[red]Host {target} appears to be down.[/red]")
                except subprocess.TimeoutExpired:
                    self.console.print(f"[red]Ping to {target} timed out.[/red]")
                except FileNotFoundError:
                    self.console.print("[red]ping command not found.[/red]")
                except Exception as e:
                    self.console.print(f"[red]Error pinging host: {e}[/red]")
        except ValueError:
            self.console.print("[red]Invalid network format. Use CIDR notation (e.g., 192.168.1.0/24).[/red]")
    
    def banner_grabbing(self, target: str) -> None:
        """Grab service banners from open ports"""
        # Check if we're in simulation mode
        simulation_mode = self.config_manager.get_boolean('NETWORK_RECON', 'simulation_mode', fallback=True)
        
        if simulation_mode:
            self.console.print("[yellow]Running in simulation mode - showing example results[/yellow]")
            self.console.print(f"[cyan]Simulating banner grabbing from [green]{target}[/green][/cyan]")
            self.console.print("[yellow]Note: This shows example banners that might be returned[/yellow]")
            self.console.print("  [cyan]Port 22 (SSH):[/cyan] SSH-2.0-OpenSSH_8.4p1")
            self.console.print("  [cyan]Port 80 (HTTP):[/cyan] Apache/2.4.41 (Ubuntu)")
            self.console.print("  [cyan]Port 443 (HTTPS):[/cyan] nginx/1.18.0")
            return
        
        # For demo purposes, we'll show what banner grabbing would do
        self.console.print(f"[cyan]Attempting to grab banners from [green]{target}[/green][/cyan]")
        self.console.print("[yellow]Note: Actual banner grabbing requires specific service connections[/yellow]")
        
        # In a real implementation, we would connect to common ports and try to get service banners
        # For now, we'll just show what we would do
        common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 9200, 27017, 27018]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # 3 second timeout
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    service = self.get_common_service(port)
                    self.console.print(f"[green]Port {port} ({service}): Connection successful - banner grabbing would occur here[/green]")
                else:
                    # Port is closed, skip
                    pass
                
                sock.close()
            except socket.gaierror:
                self.console.print(f"[red]Error resolving hostname for {target}[/red]")
                break
            except Exception:
                # Connection failed, skip
                continue
    
    def os_detection(self, target: str) -> None:
        """Detect operating system of target"""
        import subprocess
        
        # Check if we're in simulation mode
        simulation_mode = self.config_manager.get_boolean('NETWORK_RECON', 'simulation_mode', fallback=True)
        
        if simulation_mode:
            self.console.print("[yellow]Running in simulation mode - showing example results[/yellow]")
            self.console.print(f"[cyan]Simulating OS detection for [green]{target}[/green][/cyan]")
            self.console.print("[bold green]Detected OS: Linux 5.x (Ubuntu 20.04)[/bold green]")
            self.console.print("[green]OS Accuracy: 95%[/green]")
            return
        
        self.console.print(f"[cyan]Attempting OS detection for [green]{target}[/green][/cyan]")
        
        try:
            # Try to use nmap for OS detection if available
            result = subprocess.run(['nmap', '-O', target], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                # Look for OS detection results in nmap output
                output = result.stdout
                if "OS details:" in output:
                    os_match = re.search(r"OS details: (.+)", output)
                    if os_match:
                        os_details = os_match.group(1)
                        self.console.print(f"[bold green]Detected OS: {os_details}[/bold green]")
                    else:
                        self.console.print("[yellow]OS detection inconclusive or no match found.[/yellow]")
                        self.console.print("[dim]Nmap output may contain additional information.[/dim]")
                else:
                    self.console.print("[yellow]No OS detection results found in nmap output.[/yellow]")
            else:
                self.console.print("[red]Nmap OS detection failed or no results.[/red]")
        except subprocess.TimeoutExpired:
            self.console.print("[red]Nmap OS detection timed out.[/red]")
        except FileNotFoundError:
            self.console.print("[red]nmap not found. Install nmap for OS detection.[/red]")
        except Exception as e:
            self.console.print(f"[red]Error during OS detection: {e}[/red]")
    
    def traceroute(self, target: str) -> None:
        """Trace network path to target"""
        import subprocess
        import platform
        
        # Check if we're in simulation mode
        simulation_mode = self.config_manager.get_boolean('NETWORK_RECON', 'simulation_mode', fallback=True)
        
        if simulation_mode:
            self.console.print("[yellow]Running in simulation mode - showing example results[/yellow]")
            self.console.print(f"[cyan]Simulating traceroute to [green]{target}[/green][/cyan]")
            self.console.print("[cyan]Hop 1:[/cyan] 192.168.1.1 (1.23ms)")
            self.console.print("[cyan]Hop 2:[/cyan] 10.0.0.1 (2.45ms)")
            self.console.print("[cyan]Hop 3:[/cyan] 172.16.0.1 (5.67ms)")
            self.console.print("[cyan]Hop 4:[/cyan] 203.0.113.1 (12.34ms)")
            self.console.print("[bold green]Traceroute completed with 4 hops.[/bold green]")
            return
        
        self.console.print(f"[cyan]Tracing route to [green]{target}[/green][/cyan]")
        
        try:
            if platform.system().lower() == 'windows':
                # Use 'tracert' on Windows
                result = subprocess.run(['tracert', target], 
                                      capture_output=True, text=True, timeout=60)
            else:
                # Use 'traceroute' on Unix-like systems
                result = subprocess.run(['traceroute', target], 
                                      capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Display only the hops that have valid IP addresses
                lines = result.stdout.split('\n')
                hop_count = 0
                for line in lines:
                    if line.strip() and not line.startswith('Tracing') and not line.startswith('traceroute'):
                        hop_count += 1
                        self.console.print(f"[cyan]Hop {hop_count}:[/cyan] {line}")
                
                if hop_count > 0:
                    self.console.print(f"[bold green]Traceroute completed with {hop_count} hops.[/bold green]")
                else:
                    self.console.print("[red]Traceroute completed but no hops detected.[/red]")
            else:
                self.console.print("[red]Traceroute failed or no results.[/red]")
        except subprocess.TimeoutExpired:
            self.console.print("[red]Traceroute timed out.[/red]")
        except FileNotFoundError:
            cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
            self.console.print(f"[red]{cmd} command not found.[/red]")
        except Exception as e:
            self.console.print(f"[red]Error during traceroute: {e}[/red]")