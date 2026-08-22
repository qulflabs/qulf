import typer
from rich.console import Console

from qulf.cli.commands import init

app = typer.Typer(
    name="qulf",
    help="Qulf CLI - The framework-agnostic auth ecosystem.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

app.add_typer(init.app, name="init", help="Scaffold Qulf models and configuration.")


@app.callback()
def main() -> None:
    """Qulf Developer Tools."""
    pass


if __name__ == "__main__":
    app()
