from rich.console import Console
from questionary import Style
import questionary

class SocialEngineeringToolkit:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        self.console.print("[bold magenta]Social Engineering Toolkit[/bold magenta]")
        choice = questionary.select(
            "Select an attack type",
            choices=["Phishing Simulation", "Pretexting Generator", "Impersonation Scripts", "Credential Harvesting", "Spear Phishing", "← Back"],
            style=Style([("qmark", "fg:ansicyan bold"), ("question", "bold"), ("pointer", "fg:ansicyan bold"), ("highlighted", "fg:ansicyan bold"), ("selected", "fg:ansigreen bold")])
        ).ask()
        if choice == "← Back":
            return
        actions = {
            "Phishing Simulation": self.phishing_simulation,
            "Pretexting Generator": self.pretexting_generator,
            "Impersonation Scripts": self.impersonation_scripts,
            "Credential Harvesting": self.credential_harvesting,
            "Spear Phishing": self.spear_phishing,
        }
        action = actions.get(choice)
        if action:
            action()

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

