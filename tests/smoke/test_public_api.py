import qulf
from qulf import Qulf


def test_package_version():
    assert isinstance(qulf.__version__, str)
    assert qulf.__version__


def test_public_api():
    assert Qulf is not None


def test_can_create_qulf():
    auth = Qulf(db=None)
    assert auth is not None