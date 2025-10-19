from rich.console import Console
from rich.prompt import Prompt
import hashlib
import base64
import secrets


class MiscUtilities:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        self.console.print("[bold magenta]Miscellaneous Utilities[/bold magenta]")
        self.console.print("Select a utility:")
        options = {
            "1": "Hash Calculator",
            "2": "Base64 Encoder/Decoder",
            "3": "Random Password Generator",
            "4": "Back",
        }
        for k, v in options.items():
            self.console.print(f"[cyan]{k}[/cyan]: {v}")
        choice = Prompt.ask("Choose an option", choices=list(options.keys()))
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
        data = Prompt.ask("Enter text to hash")
        md5 = hashlib.md5(data.encode()).hexdigest()
        sha256 = hashlib.sha256(data.encode()).hexdigest()
        self.console.print(f"MD5: [green]{md5}[/green]")
        self.console.print(f"SHA256: [green]{sha256}[/green]")

    def base64_encoder_decoder(self):
        self.console.print("[bold yellow]Base64 Encoder/Decoder[/bold yellow]")
        action = Prompt.ask("Choose action", choices=["encode", "decode"])
        data = Prompt.ask("Enter text")
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
        length = int(Prompt.ask("Enter password length", default="12"))
        password = "".join(
            secrets.choice(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
            )
            for _ in range(length)
        )
        self.console.print(f"Generated password: [green]{password}[/green]")
