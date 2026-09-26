import sys
from pathlib import Path

import pytest

from qulf.cli.resolver import load_models_module, resolve_table_to_class_map
from qulf.exceptions import ModelResolutionError


def test_resolver_project_root_not_in_path(tmp_path: Path) -> None:
    models_file = tmp_path / "models.py"
    models_file.write_text("class ValidModel:\n    pass\n")

    project_root = str(tmp_path.resolve())
    if project_root in sys.path:
        sys.path.remove(project_root)

    module = load_models_module(models_file)
    assert module.__name__ == "models"
    assert project_root in sys.path


def test_resolver_invalid_spec(tmp_path: Path) -> None:
    # A directory cannot be loaded as a module specification
    with pytest.raises(
        ModelResolutionError, match="Could not load module specification"
    ):
        load_models_module(tmp_path)


def test_resolver_execution_error(tmp_path: Path) -> None:
    models_file = tmp_path / "models.py"
    models_file.write_text("1 / 0\n")
    with pytest.raises(ModelResolutionError, match="Failed to execute models module"):
        load_models_module(models_file)


def test_resolver_skips_foreign_classes(tmp_path: Path) -> None:
    models_file = tmp_path / "models.py"
    models_file.write_text(
        "from datetime import datetime\nclass LocalModel:\n    pass\n"
    )

    mapping = resolve_table_to_class_map(models_file, "django")
    assert "LocalModel" in mapping
    assert "datetime" not in mapping


def test_resolver_sqlalchemy_table(tmp_path: Path) -> None:
    models_file = tmp_path / "models.py"
    models_file.write_text(
        "class User:\n    class __table__:\n        name = 'users'\n"
    )
    mapping = resolve_table_to_class_map(models_file, "sqlalchemy")
    assert mapping["users"] == "User"
    assert mapping["User"] == "User"
