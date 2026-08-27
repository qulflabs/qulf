import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qulf.cli.commands.sync import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolate_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure all CLI tests happen in a temporary directory."""
    monkeypatch.chdir(tmp_path)


class DummyDB:
    name = "django"


class DummyPlugin:
    name = "dummy"

    def get_custom_columns(self) -> dict:
        return {"user": {"injected_col": str}}


class DummyAuth:
    db = DummyDB()
    plugins = {"dummy": DummyPlugin()}


# Expose the dummy auth globally so the CLI can dynamically import it via sys.modules

sys.modules["dummy_app"] = type("dummy_module", (), {"auth": DummyAuth()})


class TestQulfSyncCommand:
    def test_sync_no_config_aborts(self) -> None:
        result = runner.invoke(app)
        assert result.exit_code == 1
        assert "Qulf config not found" in result.stdout

    def test_sync_no_models_path_skips(self) -> None:
        Path("pyproject.toml").write_text("[tool.qulf]\napp = 'dummy_app:auth'\n")
        result = runner.invoke(app)
        assert result.exit_code == 0
        assert "No file syncing required" in result.stdout

    def test_sync_models_path_not_found(self) -> None:
        Path(".qulf.toml").write_text(
            "[qulf]\napp = 'dummy_app:auth'\nmodels = 'missing.py'\n"
        )
        result = runner.invoke(app)
        assert result.exit_code == 1
        assert "Models file 'missing.py' not found" in result.stdout

    def test_sync_invalid_import_path(self) -> None:
        Path(".qulf.toml").write_text(
            "[qulf]\napp = 'bad_path:missing'\nmodels = 'models.py'\n"
        )
        Path("models.py").write_text("class User:\n    pass\n")
        result = runner.invoke(app)
        assert result.exit_code == 1
        assert "Error loading Qulf instance" in result.stdout

    def test_sync_no_columns_required(self) -> None:
        Path(".qulf.toml").write_text(
            "[qulf]\napp = 'dummy_app:empty_auth'\nmodels = 'models.py'\n"
        )
        Path("models.py").write_text("class User:\n    pass\n")

        class EmptyAuth:
            db = DummyDB()
            plugins = {}

        sys.modules["dummy_app"].empty_auth = EmptyAuth()

        result = runner.invoke(app)
        assert result.exit_code == 0
        assert "No active plugins require custom database columns" in result.stdout

    def test_sync_success_and_skip_verbose(self) -> None:
        Path(".qulf.toml").write_text(
            "[qulf]\napp = 'dummy_app:auth'\nmodels = 'models.py'\n"
        )

        # We manually write a file that already has `injected_col` (Assign)
        # and `ann_col` (AnnAssign) to force the AST utility to skip them.
        Path("models.py").write_text(
            "class User:\n"
            "    id = 1\n"
            "    injected_col = 'already exists'\n"
            "    ann_col: str = 'already exists'\n"
        )

        class SkipPlugin:
            name = "dummy"

            def get_custom_columns(self) -> dict:
                return {"user": {"injected_col": str, "ann_col": str}}

        sys.modules["dummy_app"].auth.plugins = {"dummy": SkipPlugin()}

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "Sync Complete" in result.stdout
        assert "Skipped (Already defined): 2 fields" in result.stdout
        assert "User.injected_col" in result.stdout
        assert "User.ann_col" in result.stdout

    def test_sync_success_injection(self) -> None:
        Path(".qulf.toml").write_text(
            "[qulf]\napp = 'dummy_app:auth'\nmodels = 'models.py'\n"
        )
        Path("models.py").write_text("class User:\n    id = 1\n")

        # FIX: Reset the global test state back to the original DummyPlugin!
        sys.modules["dummy_app"].auth.plugins = {"dummy": DummyPlugin()}

        result = runner.invoke(app)

        assert result.exit_code == 0
        assert "Injected: 1 fields" in result.stdout

        content = Path("models.py").read_text()
        assert "injected_col =" in content
        assert "# Injected by dummy:" in content


class SpecificPlugin:
    name = "specific"

    def get_custom_columns(self) -> dict:
        return {"user": {"generic_col": str}}

    def get_django_columns(self) -> dict:
        return {"user": {"dj_specific": str}}


class SpecificAuth:
    db = DummyDB()
    plugins = {"specific": SpecificPlugin()}


def test_sync_with_specific_orm_method() -> None:
    """Hits lines 90-98 by triggering the specific_method ORM override block."""
    Path(".qulf.toml").write_text(
        "[qulf]\napp = 'dummy_app:auth'\nmodels = 'models.py'\n"
    )
    Path("models.py").write_text("class User:\n    id = 1\n")

    # Override the dummy auth in sys.modules to use our specific plugin
    sys.modules["dummy_app"].auth = SpecificAuth()

    result = runner.invoke(app)
    assert result.exit_code == 0

    content = Path("models.py").read_text()
    assert "dj_specific =" in content
