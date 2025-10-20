"""Reverse Engineering Tools"""

import time
import subprocess
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from .base_tool import BaseTool


class ReverseEngineeringTools(BaseTool):
    def __init__(self, console: Console):
        super().__init__(console)
        
    def disassembler(self):
        """Use disassembler tools to analyze binaries"""
        self.display_header("Binary Disassembly")
        
        file_path = Prompt.ask("[cyan]Enter binary file path for disassembly[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
            
        self.console.print(f"[cyan]Disassembling binary: [green]{file_path}[/green][/cyan]")
        
        # Check for disassemblers
        disassemblers = ['ida', 'ghidra', 'radare2', 'objdump']
        available_disassemblers = []
        
        for disasm in disassemblers:
            try:
                result = subprocess.run([disasm, '--help'], capture_output=True, text=True, timeout=10)
                available_disassemblers.append(disasm)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        if available_disassemblers:
            self.console.print(f"[bold green]Available disassemblers: {', '.join(available_disassemblers)}[/bold green]")
            
            # Ask which disassembler to use
            chosen_disasm = Prompt.ask(
                "[cyan]Choose disassembler[/cyan]",
                choices=available_disassemblers,
                default=available_disassemblers[0]
            )
            
            if chosen_disasm == 'radare2':
                self.console.print(f"[cyan]Running radare2 on [green]{file_path}[/green][/cyan]")
                try:
                    # Run basic radare2 analysis
                    result = subprocess.run(['r2', '-A', '-q', '-c', 'pdf', file_path], 
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        output = result.stdout
                        if output.strip():
                            self.console.print("[bold green]Disassembly output:[/bold green]")
                            # Show first few lines of disassembly
                            lines = output.split('\n')
                            for line in lines[:20]:
                                if line.strip():
                                    self.console.print(f"  [cyan]{line}[/cyan]")
                        else:
                            self.console.print("[yellow]No disassembly output or radare2 failed.[/yellow]")
                    else:
                        self.display_result(f"Radare2 failed with code {result.returncode}", "error")
                except subprocess.TimeoutExpired:
                    self.display_result("Disassembly timed out", "error")
                except FileNotFoundError:
                    self.console.print("[red]r2 command not found. Install radare2 for disassembly.[/red]")
                except Exception as e:
                    self.display_result(f"Error during radare2 disassembly: {e}", "error")
            elif chosen_disasm == 'objdump':
                self.console.print(f"[cyan]Running objdump on [green]{file_path}[/green][/cyan]")
                try:
                    # Run basic objdump analysis
                    result = subprocess.run(['objdump', '-d', file_path], 
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        output = result.stdout
                        if output.strip():
                            self.console.print("[bold green]Disassembly output:[/bold green]")
                            # Show first few lines of disassembly
                            lines = output.split('\n')
                            for line in lines[:20]:
                                if line.strip() and not line.startswith(' '):
                                    self.console.print(f"  [cyan]{line}[/cyan]")
                        else:
                            self.console.print("[yellow]No disassembly output or objdump failed.[/yellow]")
                    else:
                        self.display_result(f"Objdump failed with code {result.returncode}", "error")
                except subprocess.TimeoutExpired:
                    self.display_result("Disassembly timed out", "error")
                except FileNotFoundError:
                    self.console.print("[red]objdump command not found. Install binutils for disassembly.[/red]")
                except Exception as e:
                    self.display_result(f"Error during objdump disassembly: {e}", "error")
            else:
                self.console.print(f"[yellow]Using {chosen_disasm} for disassembly...[/yellow]")
                self.console.print("[dim]In a real implementation, this would launch the selected disassembler[/dim]")
        else:
            self.console.print("[red]No disassemblers found. Install IDA Pro, Ghidra, or radare2 for binary analysis.[/red]")
            self.console.print("[yellow]Feature not available: No disassemblers found. (Demo only)[/yellow]")
    
    def debugger(self):
        """Use debugger tools to analyze binaries"""
        self.display_header("Binary Debugging")
        
        file_path = Prompt.ask("[cyan]Enter binary file path for debugging[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
            
        self.console.print(f"[cyan]Debugging binary: [green]{file_path}[/green][/cyan]")
        
        # Check for debuggers
        debuggers = ['gdb', 'x64dbg', 'ollydbg', 'windbg']
        available_debuggers = []
        
        for dbg in debuggers:
            try:
                result = subprocess.run([dbg, '--help'], capture_output=True, text=True, timeout=10)
                available_debuggers.append(dbg)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        if available_debuggers:
            self.console.print(f"[bold green]Available debuggers: {', '.join(available_debuggers)}[/bold green]")
            
            # Ask which debugger to use
            chosen_dbg = Prompt.ask(
                "[cyan]Choose debugger[/cyan]",
                choices=available_debuggers,
                default=available_debuggers[0]
            )
            
            self.console.print(f"[yellow]Using {chosen_dbg} for debugging...[/yellow]")
            self.console.print("[dim]In a real implementation, this would launch the selected debugger[/dim]")
        else:
            self.console.print("[red]No debuggers found. Install GDB, x64dbg, or OllyDbg for binary debugging.[/red]")
            self.console.print("[yellow]Feature not available: No debuggers found. (Demo only)[/yellow]")
    
    def decompiler(self):
        """Use decompiler tools to analyze binaries"""
        self.display_header("Binary Decompilation")
        
        file_path = Prompt.ask("[cyan]Enter binary file path for decompilation[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
            
        self.console.print(f"[cyan]Decompiling binary: [green]{file_path}[/green][/cyan]")
        
        # Check for decompilers
        decompilers = ['ghidra', 'ida', 'retdec', 'snowman']
        available_decompilers = []
        
        for dec in decompilers:
            try:
                result = subprocess.run([dec, '--help'], capture_output=True, text=True, timeout=10)
                available_decompilers.append(dec)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        if available_decompilers:
            self.console.print(f"[bold green]Available decompilers: {', '.join(available_decompilers)}[/bold green]")
            
            # Ask which decompiler to use
            chosen_dec = Prompt.ask(
                "[cyan]Choose decompiler[/cyan]",
                choices=available_decompilers,
                default=available_decompilers[0]
            )
            
            self.console.print(f"[yellow]Using {chosen_dec} for decompilation...[/yellow]")
            self.console.print("[dim]In a real implementation, this would launch the selected decompiler[/dim]")
        else:
            self.console.print("[red]No decompilers found. Install Ghidra, IDA Pro, or RetDec for binary decompilation.[/red]")
            self.console.print("[yellow]Feature not available: No decompilers found. (Demo only)[/yellow]")
    
    def binary_analysis(self):
        """Analyze binary file formats and structures"""
        self.display_header("Binary File Analysis")
        
        file_path = Prompt.ask("[cyan]Enter binary file path for analysis[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
            
        self.console.print(f"[cyan]Analyzing binary: [green]{file_path}[/green][/cyan]")
        
        # Check for binary analysis tools
        try:
            result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.console.print(f"[bold green]File type:[/bold green] {result.stdout.strip()}")
            else:
                self.display_result(f"File command failed with code {result.returncode}", "error")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.console.print("[red]file command not found. Install file utility for binary analysis.[/red]")
        
        # Try to use binwalk if available
        try:
            result = subprocess.run(['binwalk', file_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                if output.strip():
                    self.console.print("[bold green]Binwalk analysis:[/bold green]")
                    lines = output.split('\n')
                    for line in lines[:15]:  # Show first 15 lines
                        if line.strip():
                            self.console.print(f"  [cyan]{line}[/cyan]")
                else:
                    self.console.print("[yellow]No binwalk output or analysis incomplete.[/yellow]")
            else:
                self.display_result(f"Binwalk failed with code {result.returncode}", "error")
        except subprocess.TimeoutExpired:
            self.display_result("Binary analysis timed out", "error")
        except FileNotFoundError:
            self.console.print("[red]binwalk command not found. Install binwalk for binary analysis.[/red]")
        except Exception as e:
            self.display_result(f"Error during binwalk analysis: {e}", "error")
    
    def function_recognition(self):
        """Recognize standard library functions in binaries"""
        self.display_header("Function Recognition")
        
        file_path = Prompt.ask("[cyan]Enter binary file path for function recognition[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
            
        self.console.print(f"[cyan]Recognizing functions in binary: [green]{file_path}[/green][/cyan]")
        
        # Check for FLIRT-like tools
        self.console.print("[yellow]This would use FLIRT signatures or similar recognition methods[/yellow]")
        self.console.print("[dim]In a real implementation, this would identify standard library functions in disassembled code[/dim]")
    
    def string_decryption(self):
        """Decrypt obfuscated strings in binaries"""
        self.display_header("String Decryption")
        
        file_path = Prompt.ask("[cyan]Enter binary file path for string decryption[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
            
        self.console.print(f"[cyan]Decrypting strings in binary: [green]{file_path}[/green][/cyan]")
        
        # Check for string decryption tools
        self.console.print("[yellow]This would identify and decrypt strings obfuscated by malware[/yellow]")
        self.console.print("[dim]In a real implementation, this would emulate decryption routines or use static analysis[/dim]")
    
    def packer_detection(self):
        """Detect executable packers and protectors"""
        self.display_header("Packer Detection")
        
        file_path = Prompt.ask("[cyan]Enter binary file path for packer detection[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
            
        self.console.print(f"[cyan]Detecting packers in binary: [green]{file_path}[/green][/cyan]")
        
        # Check for packer detection tools
        try:
            result = subprocess.run(['peid', file_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                if output.strip():
                    self.console.print("[bold green]Packer detection results:[/bold green]")
                    self.console.print(f"  [cyan]{output.strip()}[/cyan]")
                else:
                    self.console.print("[yellow]No packer detection results or peid failed.[/yellow]")
            else:
                self.display_result(f"PEiD failed with code {result.returncode}", "error")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.console.print("[red]peid command not found. Install PEiD for packer detection.[/red]")
        
        # Try to use strings with entropy analysis
        try:
            result = subprocess.run(['strings', file_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                # Simple entropy-based heuristic for packed files
                high_entropy_lines = []
                for line in lines:
                    if len(line) > 10:  # Only consider longer strings
                        # Calculate entropy (simplified)
                        unique_chars = len(set(line))
                        total_chars = len(line)
                        if unique_chars / total_chars > 0.8:  # High entropy suggests possible packing
                            high_entropy_lines.append(line)
                
                if high_entropy_lines:
                    self.console.print("[bold yellow]Potentially packed/binary strings detected:[/bold yellow]")
                    for line in high_entropy_lines[:10]:  # Show first 10
                        self.console.print(f"  [red]{line}[/red]")
                else:
                    self.console.print("[green]No high-entropy strings detected - likely not packed.[/green]")
            else:
                self.display_result(f"strings command failed with code {result.returncode}", "error")
        except subprocess.TimeoutExpired:
            self.display_result("String analysis timed out", "error")
        except FileNotFoundError:
            self.console.print("[red]strings command not found. Install binutils for string analysis.[/red]")
        except Exception as e:
            self.display_result(f"Error during string analysis: {e}", "error")
    
    def run(self):
        """Run reverse engineering tools"""
        self.display_header("Reverse Engineering Tools")
        
        # Add submenu for different types of reverse engineering
        re_table = Table(
            title="[bold cyan]Reverse Engineering Options[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        re_table.add_column("ID", style="cyan", justify="center")
        re_table.add_column("Tool", style="green")
        re_table.add_column("Description", style="white")
        re_table.add_row("1", "Disassembler", "Disassemble binaries (IDA Pro, Ghidra, Radare2)")
        re_table.add_row("2", "Debugger", "Debug executables (GDB, x64dbg, OllyDbg)")
        re_table.add_row("3", "Decompiler", "Decompile binaries to source code")
        re_table.add_row("4", "Binary Analysis", "Analyze binary file formats and structures")
        re_table.add_row("5", "Function Recognition", "Identify standard library functions")
        re_table.add_row("6", "String Decryption", "Decrypt obfuscated strings in binaries")
        re_table.add_row("7", "Packer Detection", "Detect executable packers and protectors")
        re_table.add_row("8", "Back to Main Menu", "Return to main menu")
        
        self.console.print(re_table)
        choice = Prompt.ask("Choose a reverse engineering tool", choices=["1", "2", "3", "4", "5", "6", "7", "8"], default="1")
        
        if choice == "8":
            return
        
        # Add consent prompt for educational purpose
        self.console.print("[yellow]⚠[/yellow] This tool performs reverse engineering for educational purposes only.")
        self.console.print("[yellow]⚠[/yellow] Always ensure you have proper authorization before analyzing any binary files.")
        consent = Prompt.ask("[bold magenta]Do you have explicit written consent to analyze this binary? (yes/no)[/bold magenta]", default="no")
        if consent.lower() not in ['yes', 'y', 'true']:
            self.display_result("Analysis cancelled - explicit consent required", "warning")
            return
        
        self.console.print()
        
        if choice == "1":
            self.disassembler()
        elif choice == "2":
            self.debugger()
        elif choice == "3":
            self.decompiler()
        elif choice == "4":
            self.binary_analysis()
        elif choice == "5":
            self.function_recognition()
        elif choice == "6":
            self.string_decryption()
        elif choice == "7":
            self.packer_detection()