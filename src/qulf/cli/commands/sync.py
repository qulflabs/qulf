import importlib
import sys
from pathlib import Path
from typing import Any

import libcst as cst
import tomlkit
import typer
from rich.console import Console
from rich.panel import Panel

from qulf.cli import ast_utils

app = typer.Typer(help="Sync active plugins to your local models.")
console = Console()


def _get_config() -> tuple[str, str | None]:
    pyproject_path = Path.cwd() / "pyproject.toml"
    standalone_path = Path.cwd() / ".qulf.toml"

    if pyproject_path.exists():
        with open(pyproject_path, encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
            if "tool" in doc and "qulf" in doc["tool"]:
                return str(doc["tool"]["qulf"]["app"]), doc["tool"]["qulf"].get(
                    "models"
                )

    if standalone_path.exists():
        with open(standalone_path, encoding="utf-8") as f:
            doc = tomlkit.parse(f.read())
            if "qulf" in doc:
                return str(doc["qulf"]["app"]), doc["qulf"].get("models")

    console.print(
        "[bold red]Error:[/] Qulf config not found. Run [cyan]qulf init[/] first."
    )
    raise typer.Exit(1)


def _load_qulf_instance(app_path: str) -> Any:
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


@app.callback(invoke_without_command=True)
def sync_models(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed warnings about skipped fields."
    ),
) -> None:
    """
    Read active plugins and inject their required columns into your models.py file.
    """

    app_path, models_path = _get_config()

    if not models_path:
        console.print(
            "[green]You are using in-memory default models![/] "
            "No file syncing required."
        )
        raise typer.Exit(0)

    target_file = Path.cwd() / models_path
    if not target_file.exists():
        console.print(f"[bold red]Error:[/] Models file '{models_path}' not found.")
        raise typer.Exit(1)

    auth = _load_qulf_instance(app_path)
    orm_name = getattr(auth.db, "name", "unknown")

    cst_injections: dict[
        str, dict[str, tuple[cst.BaseExpression, cst.BaseExpression | None, str]]
    ] = {}

    for plugin in auth.plugins.values():
        cols = plugin.get_custom_columns()
        for table_name, columns in cols.items():
            class_name = table_name.capitalize()
            if class_name not in cst_injections:
                cst_injections[class_name] = {}
            for col_name, col_type in columns.items():
                node_tuple = ast_utils.create_fallback_cst_nodes(orm_name, col_type)
                cst_injections[class_name][col_name] = (*node_tuple, plugin.name)

        specific_method = getattr(plugin, f"get_{orm_name}_columns", None)
        if specific_method:
            import inspect
            import textwrap

            raw_source = inspect.getsource(specific_method)
            source = textwrap.dedent(raw_source)
            nodes = ast_utils.extract_nodes_from_source(source)

            for table_name, columns in nodes.items():
                class_name = table_name.capitalize()
                if class_name not in cst_injections:
                    cst_injections[class_name] = {}
                for col_name, node_tuple in columns.items():
                    cst_injections[class_name][col_name] = (*node_tuple, plugin.name)

    if not cst_injections:
        console.print("[yellow]No active plugins require custom database columns.[/]")
        raise typer.Exit(0)

    content = target_file.read_text(encoding="utf-8")
    tree = cst.parse_module(content)

    injector = ast_utils.ModelInjector(cst_injections)
    modified_tree = tree.visit(injector)

    target_file.write_text(modified_tree.code, encoding="utf-8")

    console.print(
        Panel.fit(
            f"[bold green]Sync Complete for {orm_name}![/]\n\n"
            f"[cyan]Injected:[/] {len(injector.injected_fields)} fields\n"
            f"[yellow]Skipped (Already defined):[/] {len(injector.skipped_fields)} "
            "fields"
        )
    )

    if verbose and injector.skipped_fields:
        for class_name, col_name in injector.skipped_fields:
            console.print(f"  - [yellow]Skipped[/]: {class_name}.{col_name}")
