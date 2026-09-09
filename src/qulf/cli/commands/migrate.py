import importlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import tomlkit
import typer
from rich.console import Console

app = typer.Typer(help="Orchestrate database migrations for Qulf.")
console = Console()


def _get_config_app_path() -> str:
    """Finds and parses the Qulf config to get the app import path."""
    pyproject_path = Path.cwd() / "pyproject.toml"
    standalone_path = Path.cwd() / ".qulf.toml"

    if pyproject_path.exists():
        with open(pyproject_path, encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
            if "tool" in doc and "qulf" in doc["tool"]:
                return str(doc["tool"]["qulf"]["app"])

    if standalone_path.exists():
        with open(standalone_path, encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
            if "qulf" in doc:
                return str(doc["qulf"]["app"])

    console.print(
        "[bold red]Error:[/] Qulf config not found. Run [cyan]qulf init[/] first."
    )
    raise typer.Exit(1)


def _load_qulf_instance(app_path: str) -> Any:
    """Dynamically imports the user's Qulf instance."""
    sys.path.insert(0, str(Path.cwd()))
    try:
        module_path, obj_name = app_path.split(":")
        module = importlib.import_module(module_path)
        return getattr(module, obj_name)
    except Exception as e:
        console.print(
            f"[bold red]Error loading Qulf instance from '{app_path}':[/] {e}"
        )
        raise typer.Exit(1)


def _run_command(cmd: list[str]) -> None:
    """Safely executes a subprocess command."""
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/] Could not execute '{cmd[0]}'. "
            "Is it installed and in your PATH?"
        )
        raise typer.Exit(1)
    except subprocess.CalledProcessError as e:
        console.print(
            f"[bold red]Error:[/] Command '{' '.join(cmd)}' "
            f"failed with exit code {e.returncode}."
        )
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def migrate_models(
    message: str = typer.Option(
        "qulf_auto_migration",
        "--message",
        "-m",
        help="Message for the migration revision (Alembic only).",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        "-a",
        help="Immediately apply the migrations after generating them.",
    ),
) -> None:
    """Generate and optionally apply database migrations based on your active ORM."""
    app_path = _get_config_app_path()
    auth = _load_qulf_instance(app_path)
    orm_name = getattr(auth.db, "name", "unknown")

    if orm_name in ["mongo", "memory"]:
        console.print(
            f"[green]Your active adapter ({orm_name}) "
            "is schemaless and does not require migrations![/]"
        )
        raise typer.Exit(0)

    console.print(f"[bold cyan]Orchestrating migrations for {orm_name}...[/]")

    if orm_name == "django":
        if not Path("manage.py").exists():
            console.print(
                "[bold red]Error:[/] 'manage.py' not found. "
                "Run this from the root of your Django project."
            )
            raise typer.Exit(1)

        console.print("[cyan]Running makemigrations...[/]")
        _run_command([sys.executable, "manage.py", "makemigrations"])

        if apply:
            console.print("\n[cyan]Running migrate...[/]")
            _run_command([sys.executable, "manage.py", "migrate"])

    elif orm_name in ["sqlalchemy", "sqlmodel"]:
        if not Path("alembic.ini").exists():
            console.print(
                "[bold red]Error:[/] 'alembic.ini' not found. "
                "Please initialize Alembic in your project root."
            )
            raise typer.Exit(1)

        console.print(
            f"[cyan]Running alembic revision --autogenerate -m '{message}'...[/]"
        )
        _run_command(["alembic", "revision", "--autogenerate", "-m", message])

        if apply:
            console.print("\n[cyan]Running alembic upgrade head...[/]")
            _run_command(["alembic", "upgrade", "head"])

    else:
        console.print(
            f"[bold red]Error:[/] Unknown ORM '{orm_name}'. "
            "Cannot orchestrate migrations."
        )
        raise typer.Exit(1)

    console.print(
        f"\n[bold green]Migration workflow completed successfully for {orm_name}![/]"
    )
