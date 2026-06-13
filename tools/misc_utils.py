from rich.console import Console
import hashlib
import base64
import secrets
from questionary import Style
import questionary


class MiscUtilities:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        self.console.print("[bold magenta]Miscellaneous Utilities[/bold magenta]")
        choice = questionary.select(
            "Select a utility",
            choices=["Hash Calculator", "Base64 Encoder/Decoder", "Random Password Generator", "← Back"],
            style=Style([("qmark", "fg:ansicyan bold"), ("question", "bold"), ("pointer", "fg:ansicyan bold"), ("highlighted", "fg:ansicyan bold"), ("selected", "fg:ansigreen bold")])
        ).ask()
        if choice == "← Back":
            return
        if choice == "1":
            self.hash_calculator()
        elif choice == "2":
            self.base64_encoder_decoder()
        elif choice == "3":
            self.random_password_generator()
        elif choice == "4":
            return

    def hash_calculator(self):
        self.console.print("[bold yellow]Hash Calculator[/bold yellow]")
        data = questionary.text("Enter text to hash").ask() or ""
        md5 = hashlib.md5(data.encode()).hexdigest()
        sha256 = hashlib.sha256(data.encode()).hexdigest()
        self.console.print(f"MD5: [green]{md5}[/green]")
        self.console.print(f"SHA256: [green]{sha256}[/green]")

    def base64_encoder_decoder(self):
        self.console.print("[bold yellow]Base64 Encoder/Decoder[/bold yellow]")
        action = questionary.select("Choose action", choices=["encode", "decode"]).ask()
        data = questionary.text("Enter text").ask() or ""
        if action == "encode":
            encoded = base64.b64encode(data.encode()).decode()
            self.console.print(f"Encoded: [green]{encoded}[/green]")
        else:
            try:
                decoded = base64.b64decode(data.encode()).decode()
                self.console.print(f"Decoded: [green]{decoded}[/green]")
            except Exception as e:
                self.console.print(f"[red]Error decoding: {e}[/red]")

    def random_password_generator(self):
        self.console.print("[bold yellow]Random Password Generator[/bold yellow]")
        length = int(questionary.text("Enter password length", default="12").ask() or "12")
        password = "".join(
            secrets.choice(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
            )
            for _ in range(length)
        )
        self.console.print(f"Generated password: [green]{password}[/green]")
