import importlib
from importlib.metadata import PackageNotFoundError
from unittest.mock import MagicMock, patch

import qulf
from qulf import Qulf


class TestQulfInitialization:
    def test_public_api(self) -> None:
        assert Qulf is not None

    def test_can_create_qulf(self) -> None:
        auth = Qulf(db=MagicMock())
        assert auth is not None


class TestPackageMetadata:
    def test_package_version(self) -> None:
        assert isinstance(qulf.__version__, str)
        assert qulf.__version__

    def test_package_version_not_found(self) -> None:
        with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
            importlib.reload(qulf)
            assert qulf.__version__ == "unknown"

        importlib.reload(qulf)
