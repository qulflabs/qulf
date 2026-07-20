import importlib
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

import qulf
from qulf import Qulf


def test_package_version():
    assert isinstance(qulf.__version__, str)
    assert qulf.__version__


def test_public_api():
    assert Qulf is not None


def test_can_create_qulf():
    from unittest.mock import MagicMock

    auth = Qulf(db=MagicMock())
    assert auth is not None


def test_package_version_not_found() -> None:
    """Ensure __version__ falls back to 'unknown' if PackageNotFoundError is raised."""
    # Patch the upstream module so that when qulf re-imports it, it grabs the mock
    with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
        importlib.reload(qulf)
        assert qulf.__version__ == "unknown"

    # Reload again to restore the real __version__ for any downstream tests
    importlib.reload(qulf)
