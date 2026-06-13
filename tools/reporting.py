import json
import csv
import os
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box


class ReportingModule:
    def __init__(self, console: Console):
        self.console = console
        self.findings: list[dict] = []
        self.report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

    def run(self):
        choice = Prompt.ask(
            "[bold magenta]Reporting Module[/bold magenta]\n"
            "  [cyan]1[/cyan]: Generate Executive Summary\n"
            "  [cyan]2[/cyan]: Export Findings (JSON)\n"
            "  [cyan]3[/cyan]: Export Findings (CSV)\n"
            "  [cyan]4[/cyan]: Export Findings (HTML)\n"
            "  [cyan]5[/cyan]: View Current Findings\n"
            "  [cyan]6[/cyan]: Add Finding Manually\n"
            "  [cyan]b[/cyan]: Back\n"
            "Choose an option",
            choices=["1", "2", "3", "4", "5", "6", "b"],
            default="1"
        )
        if choice == "b":
            return
        handlers = {
            "1": self.generate_executive_summary,
            "2": lambda: self.export_findings("json"),
            "3": lambda: self.export_findings("csv"),
            "4": lambda: self.export_findings("html"),
            "5": self.view_findings,
            "6": self.add_finding,
        }
        handlers[choice]()

    def add_finding(self):
        title = Prompt.ask("Finding title")
        severity = Prompt.ask("Severity", choices=["critical", "high", "medium", "low", "info"], default="medium")
        desc = Prompt.ask("Description")
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": desc,
            "timestamp": datetime.now().isoformat(),
        })
        self.console.print("[bold green]Finding added.[/bold green]")

    def view_findings(self):
        if not self.findings:
            self.console.print("[yellow]No findings recorded.[/yellow]")
            return
        t = Table(title="Current Findings", show_header=True, header_style="bold magenta", border_style="cyan", box=box.ROUNDED)
        t.add_column("#", style="dim")
        t.add_column("Title", style="cyan")
        t.add_column("Severity", style="bold")
        t.add_column("Description")
        for i, f in enumerate(self.findings, 1):
            sev = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green", "info": "dim"}
            t.add_row(str(i), f["title"], f"[{sev.get(f['severity'], 'white')}]{f['severity']}[/]", f["description"])
        self.console.print(t)

    def generate_executive_summary(self):
        self.console.print("[bold]Executive Summary[/bold]")
        org = Prompt.ask("Organization name", default="N/A")
        assessor = Prompt.ask("Assessor name", default="N/A")
        summary_text = Prompt.ask("Executive summary text")

        report = {
            "report_type": "Executive Summary",
            "organization": org,
            "assessor": assessor,
            "summary": summary_text,
            "findings_count": len(self.findings),
            "generated_at": datetime.now().isoformat(),
        }
        os.makedirs(self.report_dir, exist_ok=True)
        path = os.path.join(self.report_dir, "executive_summary.json")
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        self.console.print(f"[bold green]Executive Summary saved to {path}[/bold green]")

    def export_findings(self, fmt: str):
        if not self.findings:
            self.console.print("[yellow]No findings to export.[/yellow]")
            return
        os.makedirs(self.report_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "json":
            path = os.path.join(self.report_dir, f"findings_{ts}.json")
            with open(path, "w") as f:
                json.dump(self.findings, f, indent=2)
        elif fmt == "csv":
            path = os.path.join(self.report_dir, f"findings_{ts}.csv")
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["title", "severity", "description", "timestamp"])
                w.writeheader()
                w.writerows(self.findings)
        elif fmt == "html":
            path = os.path.join(self.report_dir, f"findings_{ts}.html")
            rows = "".join(
                f"<tr><td>{f['title']}</td><td>{f['severity']}</td><td>{f['description']}</td></tr>"
                for f in self.findings
            )
            html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Findings Report</title>
<style>body {{ font-family: sans-serif; margin: 2em; }}
table {{ border-collapse: collapse; width: 100%; }}
th,td {{ border: 1px solid #ccc; padding: 0.5em; text-align: left; }}
th {{ background: #333; color: white; }}
tr:nth-child(even) {{ background: #f5f5f5; }}</style></head>
<body><h1>Findings Report</h1><p>Generated: {datetime.now().isoformat()}</p>
<p>Total findings: {len(self.findings)}</p>
<table><thead><tr><th>Title</th><th>Severity</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
            with open(path, "w") as f:
                f.write(html)
        self.console.print(f"[bold green]Findings exported to {path}[/bold green]")
