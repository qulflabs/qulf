# Resolver architecture
import importlib.util
import inspect
import sys
from pathlib import Path
from types import ModuleType

from qulf.exceptions import ModelResolutionError


def load_models_module(models_path: Path) -> ModuleType:
    module_name = models_path.stem
    project_root = str(models_path.parent.resolve())

    # User models frequently import local files relative to project root.
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    spec = importlib.util.spec_from_file_location(module_name, models_path)
    if spec is None or spec.loader is None:
        raise ModelResolutionError(
            f"Could not load module specification from {models_path}"
        )

    module = importlib.util.module_from_spec(spec)
    # Required before exec_module for circular or dataclass resolution.
    sys.modules[module_name] = module

    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise ModelResolutionError(
            f"Failed to execute models module at {models_path}: {e}"
        ) from e

    return module


def resolve_table_to_class_map(models_path: Path, orm_name: str) -> dict[str, str]:
    module = load_models_module(models_path)
    table_to_class: dict[str, str] = {}

    for name, cls in inspect.getmembers(module, inspect.isclass):
        # Limit to classes declared directly in the target module.
        if cls.__module__ != module.__name__:
            continue

        # Register exact class name as a fallback target.
        table_to_class[name] = name

        table_name: str | None = None
        if orm_name in ("sqlalchemy", "sqlmodel"):
            table = getattr(cls, "__table__", None)
            if table is not None and hasattr(table, "name"):
                table_name = str(table.name)
        elif orm_name == "django":
            meta = getattr(cls, "_meta", None)
            if meta is not None:
                table_name = getattr(meta, "db_table", None)

        if table_name:
            table_to_class[table_name] = name

    return table_to_class
