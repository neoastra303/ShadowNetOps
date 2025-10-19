from rich.console import Console
from rich.prompt import Prompt


class ReportingModule:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        self.console.print("[bold magenta]Reporting Module[/bold magenta]")
        self.console.print("Select a report type:")
        options = {
            "1": "Generate Executive Summary",
            "2": "Export Findings (PDF)",
            "3": "Back",
        }
        for k, v in options.items():
            self.console.print(f"[cyan]{k}[/cyan]: {v}")
        choice = Prompt.ask("Choose an option", choices=list(options.keys()))
        if choice == "1":
            self.generate_executive_summary()
        elif choice == "2":
            self.export_findings_pdf()
        elif choice == "3":
            return

    def generate_executive_summary(self):
        self.console.print("[bold yellow]Executive Summary[/bold yellow]")
        summary = Prompt.ask("Enter summary text")
        self.console.print(f"[green]Executive Summary Generated:[/green] {summary}")

    def export_findings_pdf(self):
        self.console.print("[bold yellow]Export Findings (PDF)[/bold yellow]")
        self.console.print("[green]PDF export feature not implemented in demo.[/green]")
