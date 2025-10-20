"""Cryptography Tools"""

import time
import subprocess
import os
import re
import hashlib
import base64
import urllib.parse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
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


class CryptographyTools(BaseTool):
    def __init__(self, console: Console):
        super().__init__(console)
        self.config_manager = get_config_manager()
        
    def hash_calculator(self):
        """Calculate various hash algorithms"""
        self.display_header("Hash Calculator")
        
        file_path = Prompt.ask("[cyan]Enter file path for hash calculation[/cyan]")
        
        if not os.path.isfile(file_path):
            self.display_result("Invalid file path", "error")
            return
        
        # Check if we're in simulation mode
        simulation_mode = self.config_manager.get_boolean('CRYPTOGRAPHY_TOOLS', 'simulation_mode', fallback=True)
        
        if simulation_mode:
            self.console.print("[yellow]Running in simulation mode - showing example results[/yellow]")
            self.console.print(f"[cyan]Simulating hash calculation for [green]{file_path}[/green][/cyan]")
            
            # Show example hashes for simulation
            example_hashes = {
                'MD5': '5d41402abc4b2a76b9719d911017c592',
                'SHA1': '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed',
                'SHA256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
                'SHA512': 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae31e6d1385c1e3c43a1a8d7e8a8e247e238522834e03244e5541c71b2c34b2353b'
            }
            
            self.console.print("[bold green]Calculated hashes:[/bold green]")
            for algo, hash_val in example_hashes.items():
                self.console.print(f"  [cyan]{algo}:[/cyan] {hash_val}")
        else:
            self.console.print(f"[cyan]Calculating hashes for [green]{file_path}[/green][/cyan]")
            
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                # Calculate various hashes
                hashes = {
                    'MD5': hashlib.md5(data).hexdigest(),
                    'SHA1': hashlib.sha1(data).hexdigest(),
                    'SHA256': hashlib.sha256(data).hexdigest(),
                    'SHA512': hashlib.sha512(data).hexdigest(),
                    'RIPEMD160': None
                }
                
                # Try to calculate RIPEMD160 if available
                try:
                    ripemd160 = hashlib.new('ripemd160')
                    ripemd160.update(data)
                    hashes['RIPEMD160'] = ripemd160.hexdigest()
                except ValueError:
                    # RIPEMD160 not available in this Python build
                    pass
                
                # Display hashes
                self.console.print("[bold green]Calculated hashes:[/bold green]")
                for algo, hash_val in hashes.items():
                    if hash_val:
                        self.console.print(f"  [cyan]{algo}:[/cyan] {hash_val}")
                    else:
                        self.console.print(f"  [dim]{algo}:[/dim] [red]Not available[/red]")
                        
            except Exception as e:
                self.display_result(f"Error calculating hashes: {e}", "error")
    
    def encryption_decryption(self):
        """Encrypt/decrypt with various algorithms"""
        self.display_header("Encryption/Decryption")
        
        self.console.print("[cyan]Encryption/Decryption functionality...[/cyan]")
        self.console.print("[yellow]Note: This requires cryptographic libraries like pycryptodome[/yellow]")
        self.console.print("[dim]In a real implementation, this would encrypt/decrypt data with AES, RSA, or other algorithms[/dim]")
        
        # Check for pycryptodome
        try:
            import Crypto
            has_crypto = True
        except ImportError:
            has_crypto = False
        
        if has_crypto:
            self.console.print("[green]pycryptodome is available for cryptographic operations[/green]")
            
            # Ask for operation type
            operation = Prompt.ask(
                "[cyan]Choose operation[/cyan]",
                choices=["encrypt", "decrypt"],
                default="encrypt"
            )
            
            # Ask for algorithm
            algo = Prompt.ask(
                "[cyan]Choose algorithm[/cyan]",
                choices=["AES", "RSA", "DES", "Blowfish"],
                default="AES"
            )
            
            # Ask for data
            data = Prompt.ask("[cyan]Enter data to encrypt/decrypt[/cyan]")
            
            self.console.print(f"[yellow]Performing {operation} with {algo} on: {data}[/yellow]")
            self.console.print("[dim]In a real implementation, this would perform actual cryptographic operations[/dim]")
        else:
            self.console.print("[red]pycryptodome not found. Install pycryptodome for cryptographic operations.[/red]")
            self.console.print("[yellow]Feature not available: No cryptographic libraries found. (Demo only)[/yellow]")
    
    def encoding_decoding(self):
        """Encode/decode with various algorithms"""
        self.display_header("Encoding/Decoding")
        
        text = Prompt.ask("[cyan]Enter text for encoding/decoding[/cyan]")
        self.console.print(f"[cyan]Encoding/Decoding [green]{text}[/green][/cyan]")
        
        # Show various encodings
        try:
            # Base64 encoding
            b64_encoded = base64.b64encode(text.encode()).decode()
            b64_decoded = base64.b64decode(b64_encoded).decode()
            
            # Hex encoding
            hex_encoded = text.encode().hex()
            hex_decoded = bytes.fromhex(hex_encoded).decode()
            
            # URL encoding
            url_encoded = urllib.parse.quote(text)
            url_decoded = urllib.parse.unquote(url_encoded)
            
            # Display encodings
            self.console.print("[bold green]Encodings:[/bold green]")
            self.console.print(f"  [cyan]Base64:[/cyan] {b64_encoded}")
            self.console.print(f"  [cyan]Hex:[/cyan]    {hex_encoded}")
            self.console.print(f"  [cyan]URL:[/cyan]    {url_encoded}")
            
            self.console.print("[bold green]Decodings:[/bold green]")
            self.console.print(f"  [cyan]Base64 → Text:[/cyan] {b64_decoded}")
            self.console.print(f"  [cyan]Hex → Text:[/cyan]    {hex_decoded}")
            self.console.print(f"  [cyan]URL → Text:[/cyan]    {url_decoded}")
            
        except Exception as e:
            self.display_result(f"Error during encoding/decoding: {e}", "error")
    
    def cryptanalysis(self):
        """Analyze cryptographic implementations for weaknesses"""
        self.display_header("Cryptanalysis")
        
        self.console.print("[cyan]Running cryptanalysis...[/cyan]")
        self.console.print("[yellow]Note: This requires specialized cryptographic analysis tools[/yellow]")
        self.console.print("[dim]In a real implementation, this would analyze cryptographic implementations for weaknesses[/dim]")
        
        # Check for cryptanalysis tools
        crypto_tools = ['john', 'hashcat', 'openssl']
        available_tools = []
        
        for tool in crypto_tools:
            try:
                result = subprocess.run([tool, '--help'], capture_output=True, text=True, timeout=10)
                available_tools.append(tool)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        if available_tools:
            self.console.print(f"[bold green]Available cryptanalysis tools: {', '.join(available_tools)}[/bold green]")
            
            # Ask which tool to use
            chosen_tool = Prompt.ask(
                "[cyan]Choose cryptanalysis tool[/cyan]",
                choices=available_tools,
                default=available_tools[0]
            )
            
            if chosen_tool == 'hashcat':
                self.console.print("[yellow]Running hashcat for password cracking...[/yellow]")
                self.console.print("[dim]In a real implementation, this would attempt to crack password hashes[/dim]")
            elif chosen_tool == 'john':
                self.console.print("[yellow]Running John the Ripper for password cracking...[/yellow]")
                self.console.print("[dim]In a real implementation, this would attempt to crack password hashes[/dim]")
            elif chosen_tool == 'openssl':
                self.console.print("[yellow]Running OpenSSL for cryptographic analysis...[/yellow]")
                self.console.print("[dim]In a real implementation, this would check certificates, keys, and protocols[/dim]")
        else:
            self.console.print("[red]No cryptanalysis tools found. Install john, hashcat, or openssl for cryptographic analysis.[/red]")
            self.console.print("[yellow]Feature not available: No cryptanalysis tools found. (Demo only)[/yellow]")
    
    def certificate_analysis(self):
        """Analyze SSL/TLS certificates"""
        self.display_header("Certificate Analysis")
        
        self.console.print("[cyan]Analyzing SSL/TLS certificates...[/cyan]")
        self.console.print("[yellow]Note: This requires OpenSSL or similar tools[/yellow]")
        self.console.print("[dim]In a real implementation, this would check certificate validity, expiration, and security[/dim]")
        
        # Check for OpenSSL
        try:
            result = subprocess.run(['openssl', 'version'], capture_output=True, text=True, timeout=10)
            has_openssl = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            has_openssl = False
        
        if has_openssl:
            domain = Prompt.ask("[cyan]Enter domain for certificate analysis[/cyan]")
            
            # Validate domain format
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, domain):
                self.display_result("Invalid domain format", "error")
                return
                
            self.console.print(f"[cyan]Analyzing certificate for [green]{domain}[/green][/cyan]")
            
            try:
                # Connect to domain and get certificate info
                result = subprocess.run(['openssl', 's_client', '-connect', f'{domain}:443', '-servername', domain], 
                                      input='', capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    cert_info = result.stderr  # Certificate info is in stderr
                    
                    # Extract key information
                    key_lines = []
                    for line in cert_info.split('\n'):
                        if 'subject=' in line or 'issuer=' in line or 'notBefore=' in line or 'notAfter=' in line:
                            key_lines.append(line.strip())
                    
                    if key_lines:
                        self.console.print("[bold green]Certificate information:[/bold green]")
                        for line in key_lines:
                            self.console.print(f"  [cyan]{line}[/cyan]")
                    else:
                        self.console.print("[yellow]Could not extract certificate information.[/yellow]")
                else:
                    self.display_result(f"OpenSSL failed with code {result.returncode}", "error")
            except subprocess.TimeoutExpired:
                self.display_result("Certificate analysis timed out", "error")
            except Exception as e:
                self.display_result(f"Error during certificate analysis: {e}", "error")
        else:
            self.console.print("[red]openssl command not found. Install OpenSSL for certificate analysis.[/red]")
            self.console.print("[yellow]Feature not available: No certificate analysis tools found. (Demo only)[/yellow]")
    
    def key_generation(self):
        """Generate cryptographic keys"""
        self.display_header("Key Generation")
        
        self.console.print("[cyan]Generating cryptographic keys...[/cyan]")
        self.console.print("[yellow]Note: This requires cryptographic libraries or tools[/yellow]")
        self.console.print("[dim]In a real implementation, this would generate RSA, ECC, or symmetric keys[/dim]")
        
        # Check for key generation tools
        keygen_tools = ['ssh-keygen', 'openssl', 'gpg']
        available_tools = []
        
        for tool in keygen_tools:
            try:
                result = subprocess.run([tool, '--help'], capture_output=True, text=True, timeout=10)
                available_tools.append(tool)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        if available_tools:
            self.console.print(f"[bold green]Available key generation tools: {', '.join(available_tools)}[/bold green]")
            
            # Ask which tool to use
            chosen_tool = Prompt.ask(
                "[cyan]Choose key generation tool[/cyan]",
                choices=available_tools,
                default=available_tools[0]
            )
            
            if chosen_tool == 'ssh-keygen':
                self.console.print("[yellow]Generating SSH key pair with ssh-keygen...[/yellow]")
                self.console.print("[dim]In a real implementation, this would generate RSA/Ed25519 SSH keys[/dim]")
            elif chosen_tool == 'openssl':
                self.console.print("[yellow]Generating cryptographic keys with OpenSSL...[/yellow]")
                self.console.print("[dim]In a real implementation, this would generate RSA/ECC/DSA keys[/dim]")
            elif chosen_tool == 'gpg':
                self.console.print("[yellow]Generating PGP keys with GPG...[/yellow]")
                self.console.print("[dim]In a real implementation, this would generate PGP key pairs[/dim]")
        else:
            self.console.print("[red]No key generation tools found. Install ssh-keygen, OpenSSL, or GPG for key generation.[/red]")
            self.console.print("[yellow]Feature not available: No key generation tools found. (Demo only)[/yellow]")
    
    def digital_signatures(self):
        """Create and verify digital signatures"""
        self.display_header("Digital Signatures")
        
        self.console.print("[cyan]Creating digital signatures...[/cyan]")
        self.console.print("[yellow]Note: This requires cryptographic tools like GPG or OpenSSL[/yellow]")
        self.console.print("[dim]In a real implementation, this would create and verify RSA/DSA/ECDSA signatures[/dim]")
        
        # Check for signature tools
        sig_tools = ['gpg', 'openssl']
        available_tools = []
        
        for tool in sig_tools:
            try:
                result = subprocess.run([tool, '--help'], capture_output=True, text=True, timeout=10)
                available_tools.append(tool)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        if available_tools:
            self.console.print(f"[bold green]Available signature tools: {', '.join(available_tools)}[/bold green]")
            
            # Ask which tool to use
            chosen_tool = Prompt.ask(
                "[cyan]Choose signature tool[/cyan]",
                choices=available_tools,
                default=available_tools[0]
            )
            
            if chosen_tool == 'gpg':
                self.console.print("[yellow]Using GPG for digital signatures...[/yellow]")
                self.console.print("[dim]In a real implementation, this would sign and verify files with PGP signatures[/dim]")
            elif chosen_tool == 'openssl':
                self.console.print("[yellow]Using OpenSSL for digital signatures...[/yellow]")
                self.console.print("[dim]In a real implementation, this would sign and verify files with RSA/DSA/ECDSA signatures[/dim]")
        else:
            self.console.print("[red]No signature tools found. Install GPG or OpenSSL for digital signatures.[/red]")
            self.console.print("[yellow]Feature not available: No signature tools found. (Demo only)[/yellow]")
    
    def run(self):
        """Run cryptography tools"""
        self.display_header("Cryptography Tools")
        
        # Add submenu for different types of cryptography tools
        crypto_table = Table(
            title="[bold cyan]Cryptography Tools[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            box=box.ROUNDED
        )
        crypto_table.add_column("ID", style="cyan", justify="center")
        crypto_table.add_column("Tool", style="green")
        crypto_table.add_column("Description", style="white")
        crypto_table.add_row("1", "Hash Calculator", "Calculate various hash algorithms (MD5, SHA1, SHA256)")
        crypto_table.add_row("2", "Encryption/Decryption", "Encrypt/decrypt with various algorithms")
        crypto_table.add_row("3", "Encoding/Decoding", "Encode/decode with Base64, Hex, URL encoding")
        crypto_table.add_row("4", "Cryptanalysis", "Analyze cryptographic implementations for weaknesses")
        crypto_table.add_row("5", "Certificate Analysis", "Analyze SSL/TLS certificates")
        crypto_table.add_row("6", "Key Generation", "Generate cryptographic keys")
        crypto_table.add_row("7", "Digital Signatures", "Create and verify digital signatures")
        crypto_table.add_row("8", "Back to Main Menu", "Return to main menu")
        
        self.console.print(crypto_table)
        choice = Prompt.ask("Choose a cryptography tool", choices=["1", "2", "3", "4", "5", "6", "7", "8"], default="1")
        
        if choice == "8":
            return
        
        # Add consent prompt for educational purpose
        self.console.print("[yellow]⚠[/yellow] This tool performs cryptographic operations for educational purposes only.")
        self.console.print("[yellow]⚠[/yellow] Always ensure you have proper authorization before analyzing any cryptographic materials.")
        consent = Prompt.ask("[bold magenta]Do you have explicit written consent to analyze this cryptographic material? (yes/no)[/bold magenta]", default="no")
        if consent.lower() not in ['yes', 'y', 'true']:
            self.display_result("Analysis cancelled - explicit consent required", "warning")
            return
        
        self.console.print()
        
        if choice == "1":
            self.hash_calculator()
        elif choice == "2":
            self.encryption_decryption()
        elif choice == "3":
            self.encoding_decoding()
        elif choice == "4":
            self.cryptanalysis()
        elif choice == "5":
            self.certificate_analysis()
        elif choice == "6":
            self.key_generation()
        elif choice == "7":
            self.digital_signatures()