from datetime import datetime
from enum import Enum
from pathlib import Path

import tomlkit
import typer
from rich.console import Console

from qulf.cli.templates.scaffold import DJANGO_TEMPLATE, SQLALCHEMY_TEMPLATE

ascii_art = """
  █████   █▒   ██  ██▓      █████▒
▒██▓  ██▒ ██  ▓██▒▓██▒    ▓██   ▒ 
▒██▒  ██░▓██  ▒██░▒██░    ▒████ ░ 
░██   █ ░▓▓█  ░██░▒██░    ░▓█▒  ░ 
░▒███▒█▄ ▒▒█████▓ ░██████▒░▒█░    
░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░ ▒ ░    
 ░ ▒░  ░ ░░▒░ ░ ░ ░ ░ ▒  ░ ░      
   ░   ░  ░░░ ░ ░   ░ ░    ░ ░    
    ░       ░         ░  ░        
"""

app = typer.Typer(help="Initialize Qulf configuration and models in your project.")
console = Console()


class SupportedORM(str, Enum):
    django = "django"
    sqlalchemy = "sqlalchemy"
    sqlmodel = "sqlmodel"
    mongo = "mongo"


class ConfigLocation(str, Enum):
    pyproject = "pyproject.toml"
    standalone = ".qulf.toml"


def _update_or_create_toml(
    config_path: Path, app_path: str, models_path: str | None
) -> None:
    """Safely appends or updates the Qulf configuration block in the TOML file."""

    # Read existing content
    content = ""
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            content = f.read()

    doc = tomlkit.parse(content)
    is_pyproject = config_path.name == "pyproject.toml"

    has_qulf_block = False
    if is_pyproject:
        if "tool" in doc and "qulf" in doc["tool"]:
            has_qulf_block = True
    else:
        if "qulf" in doc:
            has_qulf_block = True

    if has_qulf_block:
        target_table = doc["tool"]["qulf"] if is_pyproject else doc["qulf"]
        target_table["app"] = app_path
        if models_path:
            target_table["models"] = models_path

        with open(config_path, "w", encoding="utf-8") as f:
            f.write(tomlkit.dumps(doc))
        return

    # append it as a raw string to bypass tomlkit proxies.
    block_header = "\n[tool.qulf]\n" if is_pyproject else "\n[qulf]\n"
    models_line = f'models = "{models_path}"\n' if models_path else ""

    new_block = f'{block_header}app = "{app_path}"\n{models_line}'

    with open(config_path, "a", encoding="utf-8") as f:
        f.write(new_block)


@app.callback(invoke_without_command=True)
def init_project(
    orm: SupportedORM = typer.Option(
        ..., prompt="Which ORM are you using?", help="The database ORM to scaffold."
    ),
    eject: bool = typer.Option(
        True,
        "--eject/--no-eject",
        prompt="Do you want to explicitly generate the "
        "database models in your project directory? (Recommended)",
        help="Copy the base models into your project.",
    ),
) -> None:
    """
    Interactively initialize Qulf and generate database models.
    """
    console.print(ascii_art)
    console.print("[bold cyan]Welcome to Qulf Setup![/]")

    # Config Discovery
    pyproject_path = Path.cwd() / "pyproject.toml"
    standalone_path = Path.cwd() / ".qulf.toml"

    has_config = False
    if pyproject_path.exists():
        with open(pyproject_path, encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
            if "tool" in doc and "qulf" in doc["tool"]:
                has_config = True

    if standalone_path.exists():
        with open(standalone_path, encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
            if "qulf" in doc:
                has_config = True

    app_path = "src.main:auth"
    target_models_path: str | None = None

    if eject and orm != SupportedORM.mongo:
        default_path = "models.py" if orm == SupportedORM.django else "src/db/models.py"
        target_models_path = typer.prompt(
            "Where should we save the models file?",
            default=default_path,
        )

    if not has_config:
        console.print("\n[yellow]No Qulf configuration found.[/]")
        app_path = typer.prompt(
            "What is the Python import path to your Qulf instance?",
            default="src.main:auth",
        )

        config_choice = typer.prompt(
            "Where would you like to save this configuration?",
            type=ConfigLocation,
            default=ConfigLocation.pyproject.value
            if pyproject_path.exists()
            else ConfigLocation.standalone.value,
        )

        target_config = (
            pyproject_path
            if config_choice == ConfigLocation.pyproject
            else standalone_path
        )
        _update_or_create_toml(target_config, app_path, target_models_path)
        console.print(f"[green]✔ Saved configuration to {target_config.name}[/]")

    if eject and orm != SupportedORM.mongo and target_models_path:
        target_path = Path.cwd() / target_models_path

        target_path.parent.mkdir(parents=True, exist_ok=True)

        if target_path.exists():
            console.print(
                f"[bold red]Error:[/] {target_path} already exists. "
                "Aborting to prevent overwriting."
            )
            raise typer.Exit(code=1)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        plugin_columns_str = (
            "    # (Run `qulf sync` later to inject plugin columns automatically)"
        )

        if orm == SupportedORM.django:
            content = DJANGO_TEMPLATE.format(
                timestamp=timestamp, plugin_columns=plugin_columns_str
            )
        elif orm == SupportedORM.sqlalchemy:
            content = SQLALCHEMY_TEMPLATE.format(
                timestamp=timestamp, plugin_columns=plugin_columns_str
            )
        else:
            console.print(
                f"[bold yellow]Scaffolding for {orm.value} is not yet implemented.[/]"
            )
            raise typer.Exit(code=0)

        with open(target_path, "w") as f:
            f.write(content)

        console.print(f"[green]✔ Generated models at[/] [bold]{target_path}[/]")

    console.print("\n[bold green]Qulf Initialization Complete![/]")
    console.print(f"1. Ensure your framework imports Qulf from [cyan]{app_path}[/]")
    if target_models_path:
        console.print(
            "2. Ensure your DatabaseAdapter uses the models in "
            f"[cyan]{target_models_path}[/]"
        )
    console.print(
        "3. Run [bold cyan]qulf sync[/] "
        "whenever you add new plugins to update your schema!"
    )
