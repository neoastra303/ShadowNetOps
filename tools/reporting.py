import json
import csv
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box
from .base_tool import CYBER_STYLE


class ReportingModule:
    def __init__(self, console: Console):
        self.console = console
        self.findings: list[dict] = []
        self.report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

    def run(self):
        import questionary as q
        choice = q.select(
            "Reporting Options",
            choices=[
                q.Choice("Generate Executive Summary", value="1"),
                q.Choice("Export Findings (JSON)", value="2"),
                q.Choice("Export Findings (CSV)", value="3"),
                q.Choice("Export Findings (HTML)", value="4"),
                q.Choice("View Current Findings", value="5"),
                q.Choice("Add Finding Manually", value="6"),
                q.Separator(),
                q.Choice("← Back", value="7"),
            ],
            style=CYBER_STYLE,
            qmark="┃",
            pointer="▸",
        ).ask()
        if not choice or choice == "7":
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
        import questionary as q
        title = q.text("Finding title", style=CYBER_STYLE, qmark="┃").ask() or "Untitled"
        severity = q.select("Severity", choices=["critical", "high", "medium", "low", "info"], default="medium", style=CYBER_STYLE, qmark="┃", pointer="▸").ask() or "medium"
        desc = q.text("Description", style=CYBER_STYLE, qmark="┃").ask() or ""
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
        import questionary as q
        org = q.text("Organization name", default="N/A", style=CYBER_STYLE, qmark="┃").ask() or "N/A"
        assessor = q.text("Assessor name", default="N/A", style=CYBER_STYLE, qmark="┃").ask() or "N/A"
        summary_text = q.text("Executive summary text", style=CYBER_STYLE, qmark="┃").ask() or ""

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
