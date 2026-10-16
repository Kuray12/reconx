"""Console output helpers - reproduces the colored [*] [+] [!] style."""

from __future__ import annotations

from rich.console import Console

console = Console()

# Tags mirror the original UI so muscle memory still works.
INFO = "[*]"
OK = "[+]"
WARN = "[!]"
FAIL = "[-]"
DONE = "[>]"


def info(msg: str) -> None:
    console.print(f"[bold yellow]{INFO}[/] {msg}")


def ok(msg: str) -> None:
    console.print(f"[bold green]{OK}[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[bold magenta]{WARN}[/] {msg}")


def fail(msg: str) -> None:
    console.print(f"[bold red]{FAIL}[/] {msg}")


def step(msg: str) -> None:
    console.print(f"[bold cyan]{DONE}[/] {msg}")


def plain(msg: str = "") -> None:
    console.print(msg)


def rule(title: str = "") -> None:
    from rich.rule import Rule

    console.print(Rule(title, style="cyan"))


def banner() -> None:
    from reconx import __version__, BANNER

    console.print(f"[bold cyan]{BANNER}[/]")
    console.print(f"        [dim]v{__version__}  |  authorized security testing only[/]\n")
