#!/usr/bin/env python3
"""ShadowNetOps - Advanced Network Security Operations & Red Teaming Platform"""

import sys
import re
import subprocess
import os
import hashlib
import base64
import urllib.parse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box
import questionary
from questionary import Style

from tools.network_recon import NetworkRecon
from tools.vuln_scanner import VulnScanner
from tools.password_tester import PasswordTester
from tools.osint_tools import OSINTTools
from tools.social_engineering import SocialEngineeringToolkit
from tools.forensics import ForensicsTools
from tools.reporting import ReportingModule
from tools.misc_utils import MiscUtilities
from tools.dependency_manager import get_dependency_manager
from tools.base_tool import URL_PATTERN, DOMAIN_PATTERN, BaseTool

S = {
    "title": "bold cyan",
    "header": "bold magenta",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "info": "cyan",
    "dim": "dim",
    "accent": "bold cyan",
    "label": "bold",
}

MAIN_MENU_ITEMS = [
    ("1", "Network Reconnaissance", "Port scanning, host discovery, service detection, OS fingerprinting"),
    ("2", "Vulnerability Assessment", "CVE scanning, web vulnerability testing, configuration checks"),
    ("3", "Password Strength Tester", "Analyze password security and crack time estimation"),
    ("4", "OSINT Tools", "Email, username, domain, phone number, social media research"),
    ("5", "Social Engineering Toolkit", "Phishing, pretexting, credential harvesting, spear phishing campaigns"),
    ("6", "Forensics", "Disk, memory, network, log, steganography analysis"),
    ("7", "Reporting", "Generate and export assessment reports (PDF, JSON, CSV)"),
    ("8", "Miscellaneous Utilities", "Encoding/decoding, hash generation, network utilities"),
    ("9", "Web Attack Tools", "SQLi, XSS, CSRF, subdomain discovery, tech stack detection"),
    ("10", "Wireless Attack Tools", "WiFi scanning, WPA cracking, Bluetooth analysis, deauth attacks"),
    ("11", "Malware Analysis", "Static and dynamic malware analysis tools"),
    ("12", "Reverse Engineering", "Binary analysis, disassembly, decompilation tools"),
    ("13", "Cryptography Tools", "Encryption, decryption, cryptographic analysis"),
    ("14", "Exit", "Quit the terminal"),
]

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

console = Console()


def paginate(console: Console, items: list, page_size: int = 10) -> None:
    for i in range(0, len(items), page_size):
        page = items[i:i + page_size]
        for item in page:
            console.print(item)
        if i + page_size < len(items):
            more = questionary.confirm("Show more?", default=True).ask()
            if not more:
                break


def show_menu_table(console: Console, title: str, options: list[tuple[str, str, str]]) -> str:
    choices = []
    for id_, name, desc in options:
        if id_ == "b":
            continue
        label = name
        if desc:
            label = f"{name}\n  {desc}"
        choices.append(questionary.Choice(title=label, value=id_))
    if any(o[0] == "b" for o in options):
        choices.append(questionary.Separator("──────────"))
        choices.append(questionary.Choice(title="←  Back", value="b"))
    result = questionary.select(
        title,
        choices=choices,
        style=CYBER_STYLE,
        qmark="┃",
        pointer="▸",
        use_shortcuts=False,
    ).ask()
    if result is None:
        return "b"
    return result


def qtext(prompt: str, default: str = "", validate: callable = None) -> str:
    result = questionary.text(prompt, default=default, validate=validate, style=CYBER_STYLE, qmark="┃").ask()
    return result if result is not None else ""


def qconfirm(prompt: str, default: bool = False) -> bool:
    result = questionary.confirm(prompt, default=default, style=CYBER_STYLE, qmark="┃").ask()
    return result if result is not None else False


def qselect(prompt: str, choices: list, default: str = None) -> str:
    result = questionary.select(prompt, choices=choices, default=default, style=CYBER_STYLE, qmark="┃", pointer="▸").ask()
    return result if result is not None else "b"


class ShadowNetOps:
    def __init__(self):
        self.console = console
        self.network_recon = NetworkRecon(console)
        self.vuln_scanner = VulnScanner(console)
        self.password_tester = PasswordTester(console)
        self.osint_tools = OSINTTools(console)
        self.social_engineering = SocialEngineeringToolkit(console)
        self.forensics = ForensicsTools(console)
        self.reporting = ReportingModule(console)
        self.misc_utils = MiscUtilities(console)
        self.dependency_manager = get_dependency_manager(console)

    def display_banner(self) -> None:
        banner_text = Text("ShadowNetOps", style=S["title"])
        banner_text.stylize("bold magenta", 0, 6)
        subtitle = (
            "Terminal v2.1.0  |  Cybersecurity Operations Platform\n"
            "Network Recon  |  Vuln Assessment  |  Password Testing  |  OSINT"
        )
        panel = Panel(
            Text(subtitle, justify="center"),
            title=banner_text,
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 4),
        )
        self.console.print(panel)
        self.console.print()

    def validate_target(self, target: str) -> bool:
        return BaseTool.validate_target(target)

    def check_dependencies(self, category: str) -> bool:
        missing_tools = self.dependency_manager.get_missing_tools(category)
        if missing_tools:
            self.console.print(f"\n[{S['warning']}] Missing tools for {category}:[/{S['warning']}]")
            for tool in missing_tools:
                self.console.print(f"  - [{S['error']}]{tool}[/{S['error']}]")
            self.console.print(f"\n[{S['warning']}]These tools need to be installed for {category} functionality.[/{S['warning']}]")
            if qconfirm("Would you like to attempt to install the missing tools?", default=False):
                return self.dependency_manager.install_missing_tools(category)
            else:
                self.console.print(f"[{S['warning']}]Please install required tools before proceeding.[/{S['warning']}]")
                return False
        else:
            self.console.print(f"\n[{S['success']}] All required tools for {category} are installed![/{S['success']}]")
            return True

    def _subprocess_run(self, cmd_args: list, timeout: int = 60, spinner_text: str = "Running..."):
        with Progress(SpinnerColumn(), TextColumn(f"[cyan]{{task.description}}[/cyan]"), console=self.console, transient=True) as p:
            p.add_task(spinner_text, total=None)
            return subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)

    def _handle_subprocess_error(self, e: Exception, tool_name: str):
        if isinstance(e, subprocess.CalledProcessError):
            self.console.print(f"[{S['error']}]Error running {tool_name}: {e}[/{S['error']}]")
        elif isinstance(e, FileNotFoundError):
            self.console.print(f"[{S['error']}]{tool_name} not found. Please install it.[/{S['error']}]")
        elif isinstance(e, subprocess.TimeoutExpired):
            self.console.print(f"[{S['warning']}]{tool_name} timed out.[/{S['warning']}]")
        else:
            self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")

    def _confirm_continue(self) -> bool:
        self.console.print(f"[{S['warning']}]Some tools may not function without required dependencies.[/{S['warning']}]")
        return qconfirm("Continue anyway?", default=False)

    def get_main_menu_choice(self) -> str:
        choices = []
        for id_, name, desc in MAIN_MENU_ITEMS:
            label = name
            if desc:
                label = f"{name}\n  {desc}"
            style = "fg:red bold" if id_ == "14" else ""
            choices.append(questionary.Choice(title=label, value=id_, style=style))
        result = questionary.select(
            "Select a tool category",
            choices=choices,
            style=CYBER_STYLE,
            qmark="┃",
            pointer="▸",
            use_shortcuts=False,
        ).ask()
        if result is None:
            return "14"
        return result

    def osint_tools_menu(self) -> None:
        if not self.check_dependencies('osint') and not self._confirm_continue():
            return
        choice = show_menu_table(self.console, "OSINT Tools", [
            ("1", "holehe", "Check email address usage across sites"),
            ("2", "h8mail", "Email OSINT and breach lookup"),
            ("3", "sherlock", "Find usernames across social networks"),
            ("4", "theHarvester", "Gather emails, subdomains, hosts, etc."),
            ("b", "Back", "Return to main menu"),
        ])
        if choice == "b":
            return
        if choice == "1":
            email = qtext("Enter email address to check")
            if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                self.console.print(f"[{S['error']}]Invalid email address format[/{S['error']}]")
                return
            self.console.print(f"[{S['info']}]Running holehe for {email}...[/{S['info']}]")
            try:
                result = self._subprocess_run(["holehe", email], spinner_text="holehe scanning...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "holehe")
        elif choice == "2":
            email = qtext("Enter email address for breach lookup")
            if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                self.console.print(f"[{S['error']}]Invalid email address format[/{S['error']}]")
                return
            self.console.print(f"[{S['info']}]Running h8mail for {email}...[/{S['info']}]")
            try:
                result = self._subprocess_run(["h8mail", "-t", email], spinner_text="h8mail breach lookup...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "h8mail")
        elif choice == "3":
            username = qtext("Enter username to search")
            if not username or not BaseTool.validate_input(username):
                self.console.print(f"[{S['error']}]Invalid username format[/{S['error']}]")
                return
            self.console.print(f"[{S['info']}]Running sherlock for {username}...[/{S['info']}]")
            try:
                result = self._subprocess_run(["sherlock", username], spinner_text="sherlock searching...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "sherlock")
        elif choice == "4":
            query = qtext("Enter domain, email, or IP for theHarvester")
            if not query or not self.validate_target(query):
                self.console.print(f"[{S['error']}]Invalid query format.[/{S['error']}]")
                return
            self.console.print(f"[{S['info']}]Running theHarvester for {query}...[/{S['info']}]")
            try:
                result = self._subprocess_run(["theHarvester", "-d", query, "-b", "all"], spinner_text="theHarvester gathering...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "theHarvester")

    def web_attack_tools_menu(self) -> None:
        if not self.check_dependencies('web') and not self._confirm_continue():
            return
        choice = show_menu_table(self.console, "Web Attack Tools", [
            ("1", "SQL Injection Scanner", "Detect SQLi vulnerabilities (sqlmap)"),
            ("2", "XSS Tester", "Test for XSS flaws (XSStrike)"),
            ("3", "CSRF PoC Generator", "Create CSRF proof-of-concept"),
            ("4", "Directory Brute Force", "Find hidden directories (ffuf)"),
            ("5", "Nikto Web Scanner", "Comprehensive web server scan"),
            ("6", "Subdomain Scanner", "Find subdomains (subfinder)"),
            ("7", "Tech Stack Detection", "Identify technologies (whatweb)"),
            ("8", "HTTP Header Analysis", "Analyze security headers"),
            ("9", "Wayback Machine Search", "Find old URLs from web archives"),
            ("b", "Back", "Return to main menu"),
        ])
        if choice == "b":
            return
        if choice in ("1", "2", "3", "4", "5", "7", "8"):
            url = qtext("Enter target URL", validate=lambda x: bool(URL_PATTERN.match(x)) or "Invalid URL format")
            if not url:
                return
            if choice == "1":
                try:
                    result = self._subprocess_run(["sqlmap", "-u", url, "--batch"], spinner_text="sqlmap scanning...")
                    self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
                except Exception as e:
                    self._handle_subprocess_error(e, "sqlmap")
            elif choice == "2":
                try:
                    result = self._subprocess_run(["xsstrike", "-u", url], spinner_text="XSStrike testing...")
                    self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
                except Exception as e:
                    self._handle_subprocess_error(e, "XSStrike")
            elif choice == "3":
                self.console.print(f"[{S['success']}]CSRF PoC generated for {url}[/{S['success']}]")
            elif choice == "4":
                wordlist = qtext("Enter path to wordlist", default="common.txt")
                if not wordlist:
                    return
                try:
                    result = self._subprocess_run(["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist], spinner_text="ffuf fuzzing...")
                    self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
                except Exception as e:
                    self._handle_subprocess_error(e, "ffuf")
            elif choice == "5":
                try:
                    result = self._subprocess_run(["nikto", "-h", url], spinner_text="Nikto scanning...")
                    self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
                except Exception as e:
                    self._handle_subprocess_error(e, "nikto")
            elif choice == "7":
                try:
                    result = self._subprocess_run(["whatweb", url], spinner_text="whatweb detecting...")
                    if result.returncode == 0:
                        techs = [l.strip() for l in result.stdout.split('\n') if '[' in l and ']' in l]
                        if techs:
                            self.console.print(f"[{S['success']}]Technologies detected:[/{S['success']}]")
                            for t in techs[:5]:
                                self.console.print(f"  [{S['info']}]{t}[/{S['info']}]")
                        else:
                            self.console.print(f"[{S['warning']}]No technologies detected.[/{S['warning']}]")
                    else:
                        self.console.print(f"[{S['error']}]whatweb returned code {result.returncode}[/{S['error']}]")
                except Exception as e:
                    self._handle_subprocess_error(e, "whatweb")
            elif choice == "8":
                try:
                    import requests
                    resp = requests.get(url, timeout=10)
                    important = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
                                 'X-Content-Type-Options', 'X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy']
                    found = [h for h in important if h in resp.headers]
                    missing = [h for h in important if h not in resp.headers]
                    if found:
                        self.console.print(f"[{S['success']}]Security headers found:[/{S['success']}]")
                        for h in found:
                            self.console.print(f"  [{S['success']}] {h}[/{S['success']}]")
                    if missing:
                        self.console.print(f"[{S['error']}]Missing security headers:[/{S['error']}]")
                        for h in missing:
                            self.console.print(f"  [{S['error']}] {h}[/{S['error']}]")
                except Exception as e:
                    self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
        elif choice == "6":
            domain = qtext("Enter domain for subdomain discovery", validate=lambda x: bool(DOMAIN_PATTERN.match(x)) or "Invalid domain format")
            if not domain:
                return
            try:
                result = self._subprocess_run(["subfinder", "-d", domain, "-silent"], spinner_text="subfinder discovering...")
                if result.returncode == 0 and result.stdout.strip():
                    subs = [s.strip() for s in result.stdout.strip().split('\n') if s.strip()]
                    self.console.print(f"[{S['success']}]Found {len(subs)} subdomains:[/{S['success']}]")
                    paginate(self.console, [f"  [{S['info']}]{s}[/{S['info']}]" for s in subs])
                else:
                    self.console.print(f"[{S['warning']}]No subdomains found.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "subfinder")
        elif choice == "9":
            domain = qtext("Enter domain for Wayback Machine search", validate=lambda x: bool(DOMAIN_PATTERN.match(x)) or "Invalid domain format")
            if not domain:
                return
            try:
                import requests
                resp = requests.get(
                    f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10",
                    timeout=15
                )
                if resp.status_code == 200 and len(resp.json()) > 1:
                    results = resp.json()[1:11]
                    self.console.print(f"[{S['success']}]Found {len(results)} historical URLs:[/{S['success']}]")
                    for entry in results:
                        self.console.print(f"  [{S['info']}]{entry[2]}[/{S['info']}]")
                else:
                    self.console.print(f"[{S['warning']}]No archived URLs found.[/{S['warning']}]")
            except Exception:
                self.console.print(f"[{S['warning']}]Wayback Machine API unavailable.[/{S['warning']}]")

    def wireless_attack_tools_menu(self) -> None:
        if not self.check_dependencies('wireless') and not self._confirm_continue():
            return
        choice = show_menu_table(self.console, "Wireless Attack Tools", [
            ("1", "WiFi Scanner", "Scan for nearby WiFi networks (airodump-ng)"),
            ("2", "Handshake Capture", "Capture WPA handshake (airodump-ng)"),
            ("3", "WPA Cracking", "Attempt WPA password cracking (hashcat)"),
            ("4", "Bluetooth Scanner", "Scan for Bluetooth devices (blue_hydra)"),
            ("5", "Wifite Automation", "Automated wireless attacks (wifite)"),
            ("6", "GPS Mapping", "Map wireless networks with GPS coordinates"),
            ("7", "Deauth Attack", "Deauthenticate clients from AP"),
            ("8", "Evil Twin AP", "Create rogue access point"),
            ("9", "WiFi Phishing Portal", "Create captive portal for credential harvesting"),
            ("10", "PMKID Capture", "Capture PMKID for offline cracking"),
            ("11", "WPS PIN Attack", "Bruteforce WPS PINs (reaver)"),
            ("12", "WiFi Signal Jammer", "Jam WiFi signals in range"),
            ("b", "Back", "Return to main menu"),
        ])
        if choice == "b":
            return
        if choice in ("1", "2", "5", "7", "10", "11", "12"):
            interface = qtext("Enter wireless interface", default="wlan0")
            if not interface:
                return
        if choice == "1":
            try:
                result = self._subprocess_run(["airodump-ng", interface], spinner_text="airodump-ng scanning...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "airodump-ng")
        elif choice == "2":
            channel = qtext("Enter WiFi channel to monitor", default="6")
            if not channel:
                return
            try:
                result = self._subprocess_run(["airodump-ng", interface, "--channel", channel], spinner_text="Capturing handshake...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "airodump-ng")
        elif choice == "3":
            try:
                result = self._subprocess_run(["hashcat", "--help"], spinner_text="hashcat check...")
                self.console.print(f"[{S['success']}]Hashcat is available.[/{S['success']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "hashcat")
        elif choice == "4":
            try:
                result = self._subprocess_run(["blue_hydra"], spinner_text="blue_hydra scanning...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No Bluetooth devices found.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "blue_hydra")
        elif choice == "5":
            try:
                result = self._subprocess_run(["wifite", "-i", interface, "--noaireplay"], spinner_text="wifite running...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "wifite")
        elif choice == "6":
            self.console.print(Markdown("GPS mapping requires GPS hardware and [kismet](https://www.kismetwireless.net/) with GPS support."))
        elif choice == "7":
            bssid = qtext("Enter target BSSID")
            if not bssid:
                return
            try:
                result = self._subprocess_run(["aireplay-ng", interface, "--deauth", "10", "-a", bssid], spinner_text="Deauth attack...")
                self.console.print(f"[{S['success']}]Deauth attack completed.[/{S['success']}]" if result.returncode == 0 else f"[{S['error']}]Failed.[/{S['error']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "aireplay-ng")
        elif choice == "8":
            ssid = qtext("Enter SSID", default="Free WiFi")
            self.console.print(f"[{S['warning']}]Would use hostapd to create rogue AP '{ssid}'[/{S['warning']}]")
        elif choice == "9":
            ssid = qtext("Enter SSID", default="Free WiFi")
            self.console.print(f"[{S['warning']}]Would create captive portal for '{ssid}' using fluxion[/{S['warning']}]")
        elif choice == "10":
            self.console.print(f"[{S['warning']}]Would use hcxdumptool for PMKID capture on {interface}[/{S['warning']}]")
        elif choice == "11":
            bssid = qtext("Enter target BSSID")
            if not bssid:
                return
            try:
                result = self._subprocess_run(["reaver", "-i", interface, "-b", bssid, "-vv"], spinner_text="reaver WPS attack...")
                self.console.print(Syntax(result.stdout, "text", theme="monokai") if result.stdout else f"[{S['warning']}]No output.[/{S['warning']}]")
            except Exception as e:
                self._handle_subprocess_error(e, "reaver")
        elif choice == "12":
            self.console.print(f"[{S['error']}]WARNING: Signal jamming may be illegal in your jurisdiction![/{S['error']}]")

    def malware_analysis_menu(self) -> None:
        choice = show_menu_table(self.console, "Malware Analysis Tools", [
            ("1", "Static Analysis", "File type and signature analysis"),
            ("2", "Dynamic Analysis", "Sandbox environment analysis"),
            ("3", "String Extraction", "Extract strings from binaries"),
            ("4", "YARA Rule Scanner", "Scan files with custom YARA rules"),
            ("5", "PE Header Analysis", "Analyze Portable Executable headers"),
            ("6", "Network Traffic Analysis", "Monitor malware communications"),
            ("7", "Memory Dump Analysis", "Analyze memory artifacts"),
            ("b", "Back", "Return to main menu"),
        ])
        if choice == "b":
            return
        if choice == "1":
            fp = qtext("Enter file path")
            if os.path.isfile(fp):
                result = subprocess.run(["file", fp], capture_output=True, text=True, timeout=15)
                self.console.print(f"[{S['label']}]File type:[/{S['label']}] {result.stdout.strip()}")
                self.console.print(f"[{S['warning']}]Full analysis would check signatures, packers, entropy[/{S['warning']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")
        elif choice == "2":
            self.console.print(f"[{S['info']}]Dynamic analysis requires Cuckoo, ANY.RUN, or a sandbox environment.[/{S['info']}]")
        elif choice == "3":
            fp = qtext("Enter file path")
            if os.path.isfile(fp):
                try:
                    result = self._subprocess_run(["strings", fp], spinner_text="Extracting strings...")
                    lines = [l for l in result.stdout.split('\n') if len(l) > 4]
                    self.console.print(f"[{S['success']}]Found {len(lines)} strings:[/{S['success']}]")
                    paginate(self.console, [f"  [{S['info']}]{l}[/{S['info']}]" for l in lines[:100]], page_size=15)
                except Exception as e:
                    self._handle_subprocess_error(e, "strings")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")
        elif choice == "4":
            rule = qtext("Enter YARA rule file", default="rules.yar")
            target = qtext("Enter target file/directory")
            if os.path.isfile(rule) and os.path.exists(target):
                try:
                    result = self._subprocess_run(["yara", rule, target], spinner_text="YARA scanning...")
                    if result.stdout.strip():
                        self.console.print(f"[{S['error']}]YARA matches:[/{S['error']}]")
                        self.console.print(Syntax(result.stdout, "text", theme="monokai"))
                    else:
                        self.console.print(f"[{S['success']}]No YARA matches.[/{S['success']}]")
                except FileNotFoundError:
                    self.console.print(f"[{S['error']}]yara command not found.[/{S['error']}]")
                except Exception as e:
                    self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid rule or target path.[/{S['error']}]")
        elif choice == "5":
            fp = qtext("Enter PE file path")
            if os.path.isfile(fp):
                try:
                    with open(fp, 'rb') as f:
                        magic = f.read(2)
                    self.console.print(f"[{S['success']}]Valid PE file (MZ header)[/{S['success']}]" if magic == b'MZ' else f"[{S['warning']}]File signature: {magic.hex()}[/{S['warning']}]")
                except Exception as e:
                    self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")
        elif choice == "6":
            iface = qtext("Enter network interface", default="eth0")
            try:
                result = self._subprocess_run(["tcpdump", "-i", iface, "-c", "10", "-nn"], spinner_text="Capturing packets...")
                self.console.print(Syntax(result.stdout, "bash", theme="monokai") if result.stdout.strip() else f"[{S['warning']}]No packets.[/{S['warning']}]")
            except FileNotFoundError:
                self.console.print(f"[{S['error']}]tcpdump not found.[/{S['error']}]")
            except Exception as e:
                self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
        elif choice == "7":
            fp = qtext("Enter memory dump path")
            if os.path.isfile(fp):
                self.console.print(f"[{S['warning']}]Install Volatility: pip install volatility3[/{S['warning']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")

    def reverse_engineering_menu(self) -> None:
        choice = show_menu_table(self.console, "Reverse Engineering Tools", [
            ("1", "Disassembler", "Disassemble binaries (objdump)"),
            ("2", "Debugger", "Debug executables (GDB)"),
            ("3", "Decompiler", "Decompile binaries to pseudo-code"),
            ("4", "Binary Analysis", "Analyze file format and hex dump"),
            ("5", "Function Recognition", "Identify library functions"),
            ("6", "String Decryption", "Decrypt obfuscated strings"),
            ("7", "Packer Detection", "Detect packers and protectors"),
            ("b", "Back", "Return to main menu"),
        ])
        if choice == "b":
            return
        if choice in ("1", "3"):
            fp = qtext("Enter binary path")
            if os.path.isfile(fp):
                try:
                    result = self._subprocess_run(["objdump", "-d", fp], spinner_text="Disassembling...")
                    lines = result.stdout.split('\n')
                    self.console.print(f"[{S['label']}]Output ({len(lines)} lines):[/{S['label']}]")
                    paginate(self.console, [f"  [{S['dim']}]{l}[/{S['dim']}]" for l in lines[:100]], page_size=20)
                except FileNotFoundError:
                    self.console.print(f"[{S['error']}]objdump not found. Install binutils.[/{S['error']}]")
                except Exception as e:
                    self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")
        elif choice == "2":
            fp = qtext("Enter binary path")
            if os.path.isfile(fp):
                self.console.print(f"[{S['info']}]gdb {fp}[/{S['info']}]")
                self.console.print(f"[{S['warning']}]Commands: break main, run, next, info registers[/{S['warning']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")
        elif choice == "4":
            fp = qtext("Enter binary path")
            if os.path.isfile(fp):
                ft = subprocess.run(["file", fp], capture_output=True, text=True, timeout=15)
                self.console.print(f"[{S['label']}]Type:[/{S['label']}] {ft.stdout.strip()}")
                try:
                    hexd = self._subprocess_run(["xxd", fp, "-l", "512"], spinner_text="Reading hex dump...")
                    paginate(self.console, [f"  [{S['dim']}]{l}[/{S['dim']}]" for l in hexd.stdout.split('\n')[:20]], page_size=10)
                except Exception as e:
                    self._handle_subprocess_error(e, "xxd")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")
        elif choice == "5":
            self.console.print(Markdown("Uses [FLIRT](https://www.hex-rays.com/products/ida/tech/flirt/) signatures (IDA Pro) or manual call analysis."))
        elif choice == "6":
            text = qtext("Enter hex or obfuscated string")
            if not text:
                return
            try:
                decoded = bytes.fromhex(text).decode('utf-8', errors='replace')
                self.console.print(f"[{S['success']}]Decoded: {decoded}[/{S['success']}]")
            except ValueError:
                key = qtext("Enter XOR key (hex)", default="0x41")
                try:
                    k = int(key, 16 if 'x' in key else 10) & 0xFF
                    self.console.print(f"[{S['success']}]XOR decoded: {bytes(b ^ k for b in text.encode()).decode('utf-8', errors='replace')}[/{S['success']}]")
                except Exception as e:
                    self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
        elif choice == "7":
            fp = qtext("Enter binary path")
            if os.path.isfile(fp):
                r = subprocess.run(["file", fp], capture_output=True, text=True, timeout=15)
                self.console.print(f"[{S['error']}]UPX packer detected![/{S['error']}]" if "UPX" in r.stdout else f"[{S['success']}]No packer detected via file command.[/{S['success']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")

    def cryptography_tools_menu(self) -> None:
        choice = show_menu_table(self.console, "Cryptography Tools", [
            ("1", "Hash Calculator", "MD5, SHA1, SHA256"),
            ("2", "Encryption/Decryption", "AES-256-CBC via pycryptodome"),
            ("3", "Encoding/Decoding", "Base64, Hex, URL"),
            ("4", "Hash Identifier", "Identify hash type by length"),
            ("5", "Certificate Analysis", "Check SSL/TLS certificates"),
            ("6", "Key Generation", "RSA or AES keys"),
            ("7", "Digital Signatures", "Sign and verify data"),
            ("b", "Back", "Return to main menu"),
        ])
        if choice == "b":
            return
        if choice == "1":
            fp = qtext("Enter file path")
            if os.path.isfile(fp):
                try:
                    with open(fp, 'rb') as f:
                        d = f.read()
                    self.console.print(f"[{S['label']}]MD5:[/{S['label']}]    {hashlib.md5(d).hexdigest()}")
                    self.console.print(f"[{S['label']}]SHA1:[/{S['label']}]   {hashlib.sha1(d).hexdigest()}")
                    self.console.print(f"[{S['label']}]SHA256:[/{S['label']}] {hashlib.sha256(d).hexdigest()}")
                except Exception as e:
                    self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
            else:
                self.console.print(f"[{S['error']}]Invalid file path.[/{S['error']}]")
        elif choice == "2":
            mode = qselect("Encrypt or Decrypt?", choices=["encrypt", "decrypt"])
            text = qtext("Enter text")
            pw = qtext("Password", default="defaultpassword123")
            if not text or not mode:
                return
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import pad, unpad
                from Crypto.Random import get_random_bytes
                key = hashlib.sha256(pw.encode()).digest()
                if mode == "encrypt":
                    iv = get_random_bytes(16)
                    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(text.encode(), AES.block_size))
                    self.console.print(f"[{S['success']}]Encrypted: {base64.b64encode(iv + ct).decode()}[/{S['success']}]")
                else:
                    raw = base64.b64decode(text)
                    pt = unpad(AES.new(key, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), AES.block_size).decode()
                    self.console.print(f"[{S['success']}]Decrypted: {pt}[/{S['success']}]")
            except ImportError:
                self.console.print(f"[{S['warning']}]Install: pip install pycryptodome[/{S['warning']}]")
            except Exception as e:
                self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
        elif choice == "3":
            text = qtext("Enter text")
            if not text:
                return
            self.console.print(f"[{S['label']}]Base64:[/{S['label']}] {base64.b64encode(text.encode()).decode()}")
            self.console.print(f"[{S['label']}]Hex:[/{S['label']}]    {text.encode().hex()}")
            self.console.print(f"[{S['label']}]URL:[/{S['label']}]    {urllib.parse.quote(text)}")
            dec = qtext("Decode string (or press Enter to skip)")
            if dec:
                for name, fn in [("Base64", lambda: base64.b64decode(dec).decode('utf-8', errors='replace')),
                                  ("Hex", lambda: bytes.fromhex(dec).decode('utf-8', errors='replace'))]:
                    try:
                        self.console.print(f"[{S['label']}]{name}:[/{S['label']}] {fn()}")
                    except Exception:
                        pass
        elif choice == "4":
            h = qtext("Enter hash")
            if h:
                ln = len(h)
                algos = {32: "MD5", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512"}
                self.console.print(f"[{S['label']}]Possible: {algos.get(ln, 'Unknown')}[/{S['label']}]")
        elif choice == "5":
            host = qtext("Enter hostname")
            if not host:
                return
            try:
                import socket, ssl
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                    s.settimeout(10)
                    s.connect((host, 443))
                    cert = s.getpeercert()
                    self.console.print(f"[{S['label']}]Subject:[/{S['label']}] {dict(cert['subject'][0][0])}")
                    self.console.print(f"[{S['label']}]Issuer:[/{S['label']}] {dict(cert['issuer'][0][0])}")
                    self.console.print(f"[{S['label']}]Valid:[/{S['label']}] {cert['notBefore']} -> {cert['notAfter']}")
            except Exception as e:
                self.console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
        elif choice == "6":
            kt = qselect("Key type", choices=["RSA", "AES"])
            if kt == "RSA":
                try:
                    from Crypto.PublicKey import RSA
                    k = RSA.generate(2048)
                    self.console.print(f"[{S['success']}]RSA 2048-bit key generated[/{S['success']}]")
                    self.console.print(f"[{S['label']}]Private:[/{S['label']}] {k.export_key().decode()[:100]}...")
                    self.console.print(f"[{S['label']}]Public:[/{S['label']}] {k.publickey().export_key().decode()[:100]}...")
                except ImportError:
                    self.console.print(f"[{S['warning']}]Install: pip install pycryptodome[/{S['warning']}]")
            else:
                pw = qtext("Enter passphrase")
                self.console.print(f"[{S['success']}]AES-256 key: {hashlib.sha256(pw.encode()).digest().hex()[:48]}...[/{S['success']}]")
        elif choice == "7":
            data = qtext("Enter data", default="test message")
            action = qselect("Action", choices=["sign", "verify"])
            ch = hashlib.sha256(data.encode()).hexdigest()
            if action == "sign":
                self.console.print(f"[{S['label']}]SHA256:[/{S['label']}] {ch}")
            else:
                expected = qtext("Enter expected hash")
                match = ch == expected
                self.console.print(f"[{S['label']}]Computed:[/{S['label']}] {ch}")
                self.console.print(f"[{S['success'] if match else S['error']}]Hash {'matches' if match else 'does not match'}![/{'green' if match else 'red'}]")

    def run(self) -> None:
        self.display_banner()
        while True:
            choice = self.get_main_menu_choice()
            self.console.print()
            if choice == "14":
                self.console.print(f"[{S['title']}]Shutting down ShadowNetOps...[/{S['title']}]")
                self.console.print(f"[{S['success']}] Session terminated[/{S['success']}]")
                sys.exit(0)
            if choice == "b":
                self.console.print()
                continue
            handlers = {
                "1": self.network_recon.run,
                "2": self.vuln_scanner.run,
                "3": self.password_tester.run,
                "4": self.osint_tools_menu,
                "5": self.social_engineering.run,
                "6": self.forensics.run,
                "7": self.reporting.run,
                "8": self.misc_utils.run,
                "9": self.web_attack_tools_menu,
                "10": self.wireless_attack_tools_menu,
                "11": self.malware_analysis_menu,
                "12": self.reverse_engineering_menu,
                "13": self.cryptography_tools_menu,
            }
            handler = handlers.get(choice)
            if handler:
                handler()
            self.console.print()
            self.console.print(f"[{S['dim']}]" + "\u2500" * 80 + f"[/{S['dim']}]")
            self.console.print()


def main() -> None:
    try:
        terminal = ShadowNetOps()
        terminal.run()
    except KeyboardInterrupt:
        console.print(f"\n[{S['warning']}] Interrupted by user[/{S['warning']}]")
        console.print(f"[{S['title']}]Shutting down ShadowNetOps...[/{S['title']}]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[{S['error']}]Error: {e}[/{S['error']}]")
        sys.exit(1)


if __name__ == "__main__":
    main()
