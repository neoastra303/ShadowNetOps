from rich.console import Console
from rich.prompt import Prompt
import time

class SocialEngineeringToolkit:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        self.console.print("[bold magenta]Social Engineering & Attack Toolkit[/bold magenta]")
        self.console.print("Select an attack type:")
        options = {
            "1": "Phishing Simulation",
            "2": "Pretexting Generator",
            "3": "Impersonation Scripts",
            "4": "Credential Harvesting",
            "5": "Spear Phishing",
            "6": "DDoS Attack (Demo)",
            "7": "Back"
        }
        for k, v in options.items():
            self.console.print(f"[cyan]{k}[/cyan]: {v}")
        choice = Prompt.ask("Choose an option", choices=list(options.keys()))
        if choice == "1":
            self.phishing_simulation()
        elif choice == "2":
            self.pretexting_generator()
        elif choice == "3":
            self.impersonation_scripts()
        elif choice == "4":
            self.credential_harvesting()
        elif choice == "5":
            self.spear_phishing()
        elif choice == "6":
            self.ddos_attack_demo()
        elif choice == "7":
            return

    def phishing_simulation(self):
        self.console.print("[bold yellow]Phishing Simulation[/bold yellow]")
        email = Prompt.ask("Enter target email address")
        subject = Prompt.ask("Enter email subject")
        body = Prompt.ask("Enter email body")
        self.console.print(f"[green]Simulated phishing email sent to {email} with subject '{subject}'.[/green]")

    def pretexting_generator(self):
        self.console.print("[bold yellow]Pretexting Generator[/bold yellow]")
        role = Prompt.ask("Enter role to impersonate (e.g., IT, HR)")
        scenario = Prompt.ask("Describe the scenario")
        self.console.print(f"[green]Generated pretext: Pretend to be {role} and say: '{scenario}'.[/green]")

    def impersonation_scripts(self):
        self.console.print("[bold yellow]Impersonation Scripts[/bold yellow]")
        name = Prompt.ask("Enter name to impersonate")
        context = Prompt.ask("Enter context (e.g., meeting, call)")
        self.console.print(f"[green]Impersonation script: 'Hello, I'm {name} calling about {context}.'[/green]")

    def credential_harvesting(self):
        self.console.print("[bold yellow]Credential Harvesting[/bold yellow]")
        target = Prompt.ask("Enter target website or service")
        self.console.print(f"[red]Simulated credential harvesting attempt on {target} (demo only).[/red]")

    def spear_phishing(self):
        self.console.print("[bold yellow]Spear Phishing[/bold yellow]")
        name = Prompt.ask("Enter target's name")
        company = Prompt.ask("Enter target's company")
        self.console.print(f"[green]Spear phishing email crafted for {name} at {company} (demo only).[/green]")

    def ddos_attack_demo(self):
        self.console.print("[bold yellow]DDoS Attack Tool (Demo)[/bold yellow]")
        target = Prompt.ask("Enter target IP or domain")
        self.console.print(f"[red]Launching simulated DDoS attack on {target}...[/red]")
        for i in range(5):
            self.console.print(f"[red]Packet {i+1} sent to {target}...[/red]")
            time.sleep(0.5)
        self.console.print(f"[green]DDoS simulation complete for {target}.[/green]")