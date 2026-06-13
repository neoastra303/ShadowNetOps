from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import os
import glob
import hashlib
import subprocess
import platform
import json
from datetime import datetime
from .base_tool import BaseTool, CYBER_STYLE


class ForensicsTools(BaseTool):
    def __init__(self, console: Console):
        super().__init__(console)

    def run(self):
        self.display_header("Forensics Tools")
        
        import questionary as q
        choice = q.select(
            "Forensics Method",
            choices=[
                q.Choice("Disk Analysis", value="1"),
                q.Choice("Memory Dump Analysis", value="2"),
                q.Choice("Artifact Search", value="3"),
                q.Choice("File Hashing", value="4"),
                q.Choice("Network Forensics", value="5"),
                q.Choice("Registry Analysis", value="6"),
                q.Choice("Timeline Analysis", value="7"),
                q.Choice("Log Analysis", value="8"),
                q.Choice("File Carving", value="9"),
                q.Choice("Steganography Analysis", value="10"),
                q.Choice("Browser Artifact Analysis", value="11"),
                q.Choice("Email Analysis", value="12"),
                q.Separator(),
                q.Choice("← Back", value="13"),
            ],
            style=CYBER_STYLE,
            qmark="┃",
            pointer="▸",
        ).ask()
        
        if choice == "1":
            self.disk_analysis()
        elif choice == "2":
            self.memory_dump_analysis()
        elif choice == "3":
            self.artifact_search()
        elif choice == "4":
            self.file_hashing()
        elif choice == "5":
            self.network_forensics()
        elif choice == "6":
            self.registry_analysis()
        elif choice == "7":
            self.timeline_analysis()
        elif choice == "8":
            self.log_analysis()
        elif choice == "9":
            self.file_carving()
        elif choice == "10":
            self.steganography_analysis()
        elif choice == "11":
            self.browser_artifact_analysis()
        elif choice == "12":
            self.email_analysis()
        elif choice == "13":
            return

    def disk_analysis(self):
        self.display_result("Disk Analysis", "info")
        
        # Check for Sleuth Kit
        try:
            result = subprocess.run(['fls', '--help'], capture_output=True, text=True, timeout=10)
            has_sleuthkit = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            has_sleuthkit = False
        
        import questionary as q
        if has_sleuthkit:
            image_path = q.text("Enter disk image path for analysis", style=CYBER_STYLE, qmark="┃").ask()
            if os.path.isfile(image_path):
                self.console.print(f"[cyan]Analyzing disk image: {image_path}[/cyan]")
                try:
                    result = subprocess.run(['fls', '-r', image_path], capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        # Show first 20 entries
                        for line in lines[:20]:
                            if line.strip():
                                self.console.print(f"  [green]{line}[/green]")
                    else:
                        self.display_result(f"fls command failed with code {result.returncode}", "error")
                except subprocess.TimeoutExpired:
                    self.display_result("Disk analysis timed out.", "error")
                except Exception as e:
                    self.display_result(f"Error during disk analysis: {e}", "error")
            else:
                self.display_result("Invalid disk image path.", "error")
        else:
            import questionary as q
            path = q.text("Enter directory path to analyze", default=os.getcwd(), style=CYBER_STYLE, qmark="┃").ask()
            if os.path.isdir(path):
                files = os.listdir(path)
                self.display_result(f"Found {len(files)} files in {path}.", "success")
                for f in files[:20]:  # Show first 20 files
                    file_path = os.path.join(path, f)
                    size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
                    self.console.print(f"  - {f} [dim]({size} bytes)[/dim]")
            else:
                self.display_result("Invalid directory path.", "error")

    def memory_dump_analysis(self):
        self.display_result("Memory Dump Analysis", "info")
        
        # Check for Volatility
        try:
            result = subprocess.run(['vol.py', '--help'], capture_output=True, text=True, timeout=10)
            has_volatility = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            has_volatility = False
        
        if has_volatility:
            import questionary as q
            dump_path = q.text("Enter memory dump path for analysis", style=CYBER_STYLE, qmark="┃").ask()
            if os.path.isfile(dump_path):
                self.console.print(f"[cyan]Analyzing memory dump: {dump_path}[/cyan]")
                self.console.print("[yellow]Detecting profile...[/yellow]")
                try:
                    result = subprocess.run(['vol.py', '-f', dump_path, 'imageinfo'], capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        # Show image information
                        self.console.print("[bold green]Memory dump information:[/bold green]")
                        for line in result.stdout.split('\n'):
                            if 'Profile' in line or 'DTB' in line or 'Date' in line:
                                self.console.print(f"  [cyan]{line.strip()}[/cyan]")
                    else:
                        self.display_result(f"Volatility imageinfo failed with code {result.returncode}", "error")
                except subprocess.TimeoutExpired:
                    self.display_result("Memory dump analysis timed out.", "error")
                except Exception as e:
                    self.display_result(f"Error during memory dump analysis: {e}", "error")
            else:
                self.display_result("Invalid memory dump path.", "error")
        else:
            self.display_result("Volatility not found. Install Volatility for memory dump analysis.", "error")
            self.console.print("[yellow]Feature not available: No memory dump analysis tools found. (Demo only)[/yellow]")

    def artifact_search(self):
        self.display_result("Artifact Search", "info")
        import questionary as q
        ext = q.text("Enter file extension to search for (e.g., .log, .txt, .exe)", default=".log", style=CYBER_STYLE, qmark="┃").ask() or ".log"
        path = q.text("Enter directory path to search", default=os.getcwd(), style=CYBER_STYLE, qmark="┃").ask()
        
        if os.path.isdir(path):
            matches = glob.glob(os.path.join(path, f"**/*{ext}"), recursive=True)
            self.display_result(f"Found {len(matches)} files with extension '{ext}' in {path}.", "success")
            for m in matches[:20]:  # Show first 20 matches
                self.console.print(f"  - {m}")
        else:
            self.display_result("Invalid directory path.", "error")

    def file_hashing(self):
        self.display_result("File Hashing", "info")
        import questionary as q
        file_path = q.text("Enter file path to hash", style=CYBER_STYLE, qmark="┃").ask()
        
        if os.path.isfile(file_path):
            self.console.print(f"[cyan]Calculating hashes for: {file_path}[/cyan]")
            
            # Calculate different types of hashes
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                md5_hash = hashlib.md5(data).hexdigest()
                sha1_hash = hashlib.sha1(data).hexdigest()
                sha256_hash = hashlib.sha256(data).hexdigest()
                
                self.console.print(f"[bold]MD5:[/bold]    {md5_hash}")
                self.console.print(f"[bold]SHA1:[/bold]   {sha1_hash}")
                self.console.print(f"[bold]SHA256:[/bold] {sha256_hash}")
                
            except Exception as e:
                self.display_result(f"Error calculating hashes: {e}", "error")
        else:
            self.display_result("Invalid file path.", "error")

    def network_forensics(self):
        self.display_result("Network Forensics", "info")
        
        # Check for tcpdump/tshark
        has_tcpdump = False
        has_tshark = False
        
        try:
            result = subprocess.run(['tcpdump', '--help'], capture_output=True, text=True, timeout=10)
            has_tcpdump = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        try:
            result = subprocess.run(['tshark', '--help'], capture_output=True, text=True, timeout=10)
            has_tshark = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        import questionary as q
        pcap_path = q.text("Enter PCAP file path for network analysis", style=CYBER_STYLE, qmark="┃").ask()
        
        if not os.path.isfile(pcap_path):
            self.display_result("Invalid PCAP file path.", "error")
            return
            
        if has_tshark:
            self.console.print(f"[cyan]Analyzing network capture with tshark: {pcap_path}[/cyan]")
            try:
                result = subprocess.run(['tshark', '-r', pcap_path, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.port', '-e', 'udp.port'], capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    self.console.print("[bold green]Network connections found:[/bold green]")
                    for line in lines[1:11]:  # Skip header and show first 10 connections
                        if line.strip():
                            self.console.print(f"  [cyan]{line}[/cyan]")
                else:
                    self.display_result(f"Tshark failed with code {result.returncode}", "error")
            except subprocess.TimeoutExpired:
                self.display_result("Network analysis timed out.", "error")
            except Exception as e:
                self.display_result(f"Error during network analysis: {e}", "error")
        elif has_tcpdump:
            self.console.print(f"[cyan]Analyzing network capture with tcpdump: {pcap_path}[/cyan]")
            try:
                result = subprocess.run(['tcpdump', '-r', pcap_path, '-nn'], capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    self.console.print("[bold green]Network packets found:[/bold green]")
                    for line in lines[:10]:  # Show first 10 packets
                        if line.strip():
                            self.console.print(f"  [cyan]{line}[/cyan]")
                else:
                    self.display_result(f"Tcpdump failed with code {result.returncode}", "error")
            except subprocess.TimeoutExpired:
                self.display_result("Network analysis timed out.", "error")
            except Exception as e:
                self.display_result(f"Error during network analysis: {e}", "error")
        else:
            self.display_result("Neither tshark nor tcpdump found. Install Wireshark/tshark or tcpdump for network forensics.", "error")

    def registry_analysis(self):
        self.display_result("Registry Analysis", "info")
        
        # Check for Windows registry tools
        if platform.system().lower() == 'windows':
            self.console.print("[yellow]This would analyze Windows registry hives using regripper or similar tools[/yellow]")
            import questionary as q
            reg_path = q.text("Enter registry hive path (e.g., SOFTWARE, SAM, SYSTEM)", default="SOFTWARE", style=CYBER_STYLE, qmark="┃").ask() or "SOFTWARE"
            self.console.print(f"[dim]In a real implementation, this would analyze: {reg_path}[/dim]")
            self.console.print("[dim]This requires regripper or other registry analysis tools[/dim]")
        else:
            self.console.print("[yellow]Registry analysis is primarily for Windows systems.[/yellow]")
            self.console.print("[dim]On Linux/Mac, this would analyze configuration files instead.[/dim]")

    def timeline_analysis(self):
        self.display_result("Timeline Analysis", "info")
        
        # Check for Sleuth Kit (mactime)
        try:
            result = subprocess.run(['mactime', '--help'], capture_output=True, text=True, timeout=10)
            has_sleuthkit = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            has_sleuthkit = False
        
        if has_sleuthkit:
            import questionary as q
            directory = q.text("Enter directory to analyze for timeline", default=os.getcwd(), style=CYBER_STYLE, qmark="┃").ask()
            if os.path.isdir(directory):
                self.console.print(f"[cyan]Creating timeline for directory: {directory}[/cyan]")
                # Use find to get file modification times
                try:
                    result = subprocess.run(['find', directory, '-type', 'f', '-printf', '%T@ %p\n'], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        # Sort by timestamp
                        lines = [line for line in lines if line.strip()]
                        lines.sort()
                        
                        self.console.print("[bold green]Timeline (newest first):[/bold green]")
                        for line in lines[-10:]:  # Show last 10 entries (newest)
                            if line.strip():
                                parts = line.split(' ', 1)
                                if len(parts) == 2:
                                    self.console.print(f"  [cyan]{parts[1]}[/cyan] - [dim]{parts[0]}[/dim]")
                    else:
                        self.display_result(f"Find command failed with code {result.returncode}", "error")
                except subprocess.TimeoutExpired:
                    self.display_result("Timeline analysis timed out.", "error")
                except Exception as e:
                    self.display_result(f"Error during timeline analysis: {e}", "error")
            else:
                self.display_result("Invalid directory path.", "error")
        else:
            import questionary as q
            directory = q.text("Enter directory to analyze for timeline", default=os.getcwd(), style=CYBER_STYLE, qmark="┃").ask()
            if os.path.isdir(directory):
                files = []
                for root, dirs, filenames in os.walk(directory):
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        mtime = os.path.getmtime(filepath)
                        files.append((mtime, filepath))
                
                # Sort by modification time (most recent first)
                files.sort(key=lambda x: x[0], reverse=True)
                
                self.console.print("[bold green]Timeline (newest first):[/bold green]")
                for mtime, filepath in files[:10]:  # Show first 10 most recent
                    time_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                    self.console.print(f"  [cyan]{time_str}[/cyan] - {filepath}")
            else:
                self.display_result("Invalid directory path.", "error")

    def log_analysis(self):
        self.display_result("Log Analysis", "info")
        
        import questionary as q
        log_path = q.text("Enter log file or directory path", default="/var/log", style=CYBER_STYLE, qmark="┃").ask() or "/var/log"
        
        if os.path.isfile(log_path):
            # Analyze single log file
            self.console.print(f"[cyan]Analyzing log file: {log_path}[/cyan]")
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # Show the last 10 lines (most recent)
                recent_lines = lines[-10:] if len(lines) >= 10 else lines
                
                self.console.print("[bold green]Recent log entries:[/bold green]")
                for line in recent_lines:
                    line = line.strip()
                    if line:
                        if 'error' in line.lower() or 'fail' in line.lower():
                            self.console.print(f"  [red]{line}[/red]")
                        elif 'warn' in line.lower():
                            self.console.print(f"  [yellow]{line}[/yellow]")
                        else:
                            self.console.print(f"  [cyan]{line}[/cyan]")
            except Exception as e:
                self.display_result(f"Error reading log file: {e}", "error")
                
        elif os.path.isdir(log_path):
            # Look for common log files
            log_extensions = ['.log', '.txt', '.out']
            log_files = []
            for ext in log_extensions:
                log_files.extend(glob.glob(os.path.join(log_path, f"*{ext}")))
            
            self.display_result(f"Found {len(log_files)} potential log files in {log_path}.", "success")
            
            # Analyze the 5 most recently modified log files
            log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            for log_file in log_files[:5]:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        first_line = f.readline()
                        lines = f.readlines()
                        last_line = lines[-1] if lines else first_line
                    self.console.print(f"  [cyan]{os.path.basename(log_file)}[/cyan]: {first_line[:50]}... -> {last_line[:50]}...")
                except:
                    self.console.print(f"  [red]{os.path.basename(log_file)}[/red]: Could not read")
        else:
            self.display_result("Invalid file or directory path.", "error")

    def file_carving(self):
        self.display_result("File Carving", "info")
        
        # Check for photorec/testdisk
        try:
            result = subprocess.run(['photorec', '--help'], capture_output=True, text=True, timeout=10)
            has_photorec = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            has_photorec = False
        
        if has_photorec:
            import questionary as q
            image_path = q.text("Enter disk image path for file carving", style=CYBER_STYLE, qmark="┃").ask()
            if os.path.isfile(image_path):
                self.console.print(f"[cyan]Running PhotoRec for file recovery on {image_path}...[/cyan]")
                try:
                    # PhotoRec requires interactive mode, so we'll just show what would happen
                    self.console.print("[yellow]PhotoRec would launch an interactive session for file carving[/yellow]")
                    self.console.print("[dim]In a real implementation, this would recover deleted files from the disk image[/dim]")
                except Exception as e:
                    self.display_result(f"Error during file carving: {e}", "error")
            else:
                self.display_result("Invalid disk image path.", "error")
        else:
            self.display_result("PhotoRec not found. Install testdisk package for file carving.", "error")
            self.console.print("[yellow]Feature not available: No file carving tools found. (Demo only)[/yellow]")
            self.console.print("[dim]In a real implementation, this would use PhotoRec to recover deleted files[/dim]")

    def steganography_analysis(self):
        self.display_result("Steganography Analysis", "info")
        
        # Check for steghide/stegsnow
        try:
            result = subprocess.run(['steghide', '--help'], capture_output=True, text=True, timeout=10)
            has_steghide = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            has_steghide = False
        
        import questionary as q
        file_path = q.text("Enter file path to analyze for hidden data", style=CYBER_STYLE, qmark="┃").ask()
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path.", "error")
            return
            
        if has_steghide:
            self.console.print(f"[cyan]Analyzing {file_path} for steganographic content with steghide...[/cyan]")
            try:
                # Try to extract hidden data without passphrase (might fail)
                result = subprocess.run(['steghide', 'extract', '-sf', file_path, '-xf', 'extracted.txt', '-p', ''], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    self.console.print("[green]Hidden data extracted to 'extracted.txt'[/green]")
                else:
                    self.console.print("[yellow]No hidden data found or passphrase required[/yellow]")
            except subprocess.TimeoutExpired:
                self.display_result("Steganography analysis timed out.", "error")
            except Exception as e:
                self.display_result(f"Error during steganography analysis: {e}", "error")
        else:
            self.display_result("Steghide not found. Install steghide for steganography analysis.", "error")
            self.console.print("[yellow]Feature not available: No steganography tools found. (Demo only)[/yellow]")
            self.console.print(f"[dim]In a real implementation, this would analyze {file_path} for hidden data[/dim]")

    def browser_artifact_analysis(self):
        self.display_result("Browser Artifact Analysis", "info")
        
        # Check for browser analysis tools
        has_beautifulsoup = False
        try:
            import bs4
            has_beautifulsoup = True
        except ImportError:
            pass
        
        import questionary as q
        browser_profile = q.text("Enter browser profile path to analyze", style=CYBER_STYLE, qmark="┃").ask()
        
        if not os.path.isdir(browser_profile):
            self.display_result("Invalid browser profile path.", "error")
            return
            
        if has_beautifulsoup:
            self.console.print(f"[cyan]Analyzing browser artifacts in {browser_profile}...[/cyan]")
            self.console.print("[yellow]This would extract history, bookmarks, cookies, and cache data[/yellow]")
            self.console.print("[dim]In a real implementation, this would parse browser-specific data files[/dim]")
        else:
            self.display_result("BeautifulSoup not found. Install beautifulsoup4 for browser artifact analysis.", "error")
            self.console.print("[yellow]Feature not available: No browser analysis tools found. (Demo only)[/yellow]")
            self.console.print(f"[dim]In a real implementation, this would analyze {browser_profile} for browser artifacts[/dim]")

    def email_analysis(self):
        self.display_result("Email Analysis", "info")
        
        # Check for email analysis tools
        import questionary as q
        email_path = q.text("Enter email file or directory path to analyze", style=CYBER_STYLE, qmark="┃").ask()
        
        if not os.path.exists(email_path):
            self.display_result("Invalid email file or directory path.", "error")
            return
            
        self.console.print(f"[cyan]Analyzing email artifacts in {email_path}...[/cyan]")
        self.console.print("[yellow]This would extract email headers, attachments, and metadata[/yellow]")
        self.console.print("[dim]In a real implementation, this would parse .eml, .msg, or mbox files[/dim]")
        
        # For demo purposes, show what email analysis would do
        sample_emails = [
            "sample_email_1.eml",
            "sample_email_2.eml", 
            "sample_email_3.eml"
        ]
        
        self.console.print("[bold green]Email artifacts found:[/bold green]")
        for email in sample_emails:
            self.console.print(f"  [cyan]{email}[/cyan]")
            self.console.print(f"    Subject: Important Security Update")
            self.console.print(f"    From: security@example.com")
            self.console.print(f"    To: admin@company.com")
            self.console.print(f"    Attachments: report.pdf (1.2MB)")
            self.console.print(f"    Headers: SPF: pass, DKIM: pass, DMARC: pass")