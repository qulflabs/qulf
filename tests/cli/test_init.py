from pathlib import Path

import pytest
from typer.testing import CliRunner

from qulf.cli.commands.init import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolate_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure all CLI file generations happen in a temporary directory."""
    monkeypatch.chdir(tmp_path)


class TestQulfInitCommand:
    def test_init_no_eject_exits_early(self) -> None:
        """Test the fast-path where the user declines
        to eject models but sets up config."""
        result = runner.invoke(
            app, ["--no-eject"], input="django\nsrc.main:auth\npyproject.toml\n"
        )

        assert result.exit_code == 0
        assert "Saved configuration to pyproject.toml" in result.stdout

        assert not Path("models.py").exists()
        assert Path("pyproject.toml").exists()

    def test_init_django_eject_and_create_pyproject(self) -> None:
        """Test full Django scaffolding + generating pyproject.toml."""
        result = runner.invoke(
            app, ["--eject"], input="django\nmodels.py\nsrc.main:auth\npyproject.toml\n"
        )
        assert result.exit_code == 0
        assert "Generated models at" in result.stdout

        assert Path("models.py").exists()
        assert Path("pyproject.toml").exists()

    def test_init_sqlalchemy_eject_and_create_standalone_config(self) -> None:
        """Test SQLAlchemy scaffolding + generating .qulf.toml."""
        result = runner.invoke(
            app,
            ["--eject"],
            input="sqlalchemy\nsrc/db/models.py\ncore:auth\n.qulf.toml\n",
        )
        assert result.exit_code == 0

        assert Path("src/db/models.py").exists()
        assert Path(".qulf.toml").exists()

    def test_init_mongo_skips_eject_and_prompts_config(self) -> None:
        """Test Mongo ORM which is schemaless and
        should automatically skip model ejection."""
        result = runner.invoke(
            app, ["--eject"], input="mongo\nsrc:auth\npyproject.toml\n"
        )
        assert result.exit_code == 0

        assert not Path("models.py").exists()
        assert Path("pyproject.toml").exists()

    def test_init_sqlmodel_hits_unimplemented_fallback(self) -> None:
        """Test SQLModel which currently hits the 'not yet implemented' block."""
        result = runner.invoke(
            app, ["--eject"], input="sqlmodel\nmodels.py\nsrc:auth\npyproject.toml\n"
        )
        assert result.exit_code == 0
        assert "Scaffolding for sqlmodel is not yet implemented" in result.stdout

        assert Path("pyproject.toml").exists()
        assert not Path("models.py").exists()

    def test_init_aborts_if_model_file_exists(self) -> None:
        """Test that the CLI refuses to overwrite an existing models.py file."""
        Path("models.py").write_text("existing code")

        result = runner.invoke(
            app, ["--eject"], input="django\nmodels.py\nsrc:auth\npyproject.toml\n"
        )
        assert result.exit_code == 1
        assert "already exists. Aborting to prevent overwriting." in result.stdout

    def test_init_skips_config_prompts_if_config_exists(self) -> None:
        """Test that the CLI recognizes an existing
        [tool.qulf] block and doesn't ask for it again."""
        Path("pyproject.toml").write_text("[tool.qulf]\napp = 'my:auth'\n")

        result = runner.invoke(app, ["--eject"], input="django\nmodels.py\n")
        assert result.exit_code == 0

        config_content = Path("pyproject.toml").read_text()
        assert 'app = "src.main:auth"' not in config_content

    def test_init_appends_to_existing_pyproject(self) -> None:
        """Test appending [tool.qulf] to a pyproject.toml
        that has other tools but not qulf."""
        Path("pyproject.toml").write_text("[tool.pytest.ini_options]\naddopts = '-v'\n")

        result = runner.invoke(
            app, ["--eject"], input="django\nmodels.py\nsrc:auth\npyproject.toml\n"
        )
        assert result.exit_code == 0

        config_content = Path("pyproject.toml").read_text()
        assert "[tool.pytest.ini_options]" in config_content
        assert "[tool.qulf]" in config_content

    def test_init_appends_to_existing_standalone_config(self) -> None:
        """Test appending to an existing .qulf.toml file (Coverage: line 52)."""
        Path(".qulf.toml").write_text("[other]\nkey = 'value'\n")

        result = runner.invoke(
            app, ["--eject"], input="django\nmodels.py\nsrc:auth\n.qulf.toml\n"
        )
        assert result.exit_code == 0

        config_content = Path(".qulf.toml").read_text()
        assert "[other]" in config_content
        assert "[qulf]" in config_content

    def test_init_skips_config_prompts_if_standalone_config_has_block(self) -> None:
        """Test that it skips asking config questions if
        .qulf.toml has [qulf] block (Coverage: line 106)."""
        Path(".qulf.toml").write_text("[qulf]\napp = 'my:auth'\n")

        result = runner.invoke(app, ["--eject"], input="django\nmodels.py\n")
        assert result.exit_code == 0
        assert "Qulf Initialization Complete!" in result.stdout

    def test_init_updates_existing_qulf_block(self) -> None:
        """Test updating an existing [tool.qulf]
        block without overwriting the whole file."""
        Path("pyproject.toml").write_text("[tool.qulf]\napp = 'old:auth'\n")

        # manually call _update_or_create_toml to hit the update block
        from qulf.cli.commands.init import _update_or_create_toml

        _update_or_create_toml(Path("pyproject.toml"), "new:auth", "new_models.py")

        config_content = Path("pyproject.toml").read_text()
        assert 'app = "new:auth"' in config_content
        assert 'models = "new_models.py"' in config_content

    def test_init_updates_existing_standalone_config(self) -> None:
        """Test updating an existing [qulf] block inside
        .qulf.toml (Coverage: _update_or_create_toml else branch)."""
        Path(".qulf.toml").write_text("[qulf]\napp = 'old:auth'\n")

        # manually call _update_or_create_toml to hit the specific logic branch
        from qulf.cli.commands.init import _update_or_create_toml

        _update_or_create_toml(Path(".qulf.toml"), "new:auth", "new_models.py")

        config_content = Path(".qulf.toml").read_text()
        assert 'app = "new:auth"' in config_content
        assert 'models = "new_models.py"' in config_content
