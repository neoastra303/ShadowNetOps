from rich.console import Console
import time
from questionary import Style
import questionary

class SocialEngineeringToolkit:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        self.console.print("[bold magenta]Social Engineering & Attack Toolkit[/bold magenta]")
        choice = questionary.select(
            "Select an attack type",
            choices=["Phishing Simulation", "Pretexting Generator", "Impersonation Scripts", "Credential Harvesting", "Spear Phishing", "DDoS Attack (Demo)", "← Back"],
            style=Style([("qmark", "fg:ansicyan bold"), ("question", "bold"), ("pointer", "fg:ansicyan bold"), ("highlighted", "fg:ansicyan bold"), ("selected", "fg:ansigreen bold")])
        ).ask()
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
        elif choice == "← Back":
            return

    def phishing_simulation(self):
        self.console.print("[bold yellow]Phishing Simulation[/bold yellow]")
        email = questionary.text("Enter target email address").ask() or ""
        subject = questionary.text("Enter email subject").ask() or ""
        body = questionary.text("Enter email body").ask() or ""
        self.console.print(f"[green]Simulated phishing email sent to {email} with subject '{subject}'.[/green]")

    def pretexting_generator(self):
        self.console.print("[bold yellow]Pretexting Generator[/bold yellow]")
        role = questionary.text("Enter role to impersonate (e.g., IT, HR)").ask() or ""
        scenario = questionary.text("Describe the scenario").ask() or ""
        self.console.print(f"[green]Generated pretext: Pretend to be {role} and say: '{scenario}'.[/green]")

    def impersonation_scripts(self):
        self.console.print("[bold yellow]Impersonation Scripts[/bold yellow]")
        name = questionary.text("Enter name to impersonate").ask() or ""
        context = questionary.text("Enter context (e.g., meeting, call)").ask() or ""
        self.console.print(f"[green]Impersonation script: 'Hello, I'm {name} calling about {context}.'[/green]")

    def credential_harvesting(self):
        self.console.print("[bold yellow]Credential Harvesting[/bold yellow]")
        target = questionary.text("Enter target website or service").ask() or ""
        self.console.print(f"[red]Simulated credential harvesting attempt on {target} (demo only).[/red]")

    def spear_phishing(self):
        self.console.print("[bold yellow]Spear Phishing[/bold yellow]")
        name = questionary.text("Enter target's name").ask() or ""
        company = questionary.text("Enter target's company").ask() or ""
        self.console.print(f"[green]Spear phishing email crafted for {name} at {company} (demo only).[/green]")

    def ddos_attack_demo(self):
        self.console.print("[bold yellow]DDoS Attack Tool (Demo)[/bold yellow]")
        target = questionary.text("Enter target IP or domain").ask() or ""
        self.console.print(f"[red]Launching simulated DDoS attack on {target}...[/red]")
        for i in range(5):
            self.console.print(f"[red]Packet {i+1} sent to {target}...[/red]")
            time.sleep(0.5)
        self.console.print(f"[green]DDoS simulation complete for {target}.[/green]")