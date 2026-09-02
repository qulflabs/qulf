from typer.testing import CliRunner

from qulf.cli.main import app

runner = CliRunner()


def test_cli_main_entrypoint_help() -> None:
    """Test that the main CLI entrypoint works and shows the registered commands."""
    result = runner.invoke(app, ["--help"])
    print(f"result.stdout: {result.stdout}")

    assert result.exit_code == 0
    assert "init" in result.stdout
    assert "Scaffold Qulf models and configuration" in result.stdout
