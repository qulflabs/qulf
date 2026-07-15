from importlib.metadata import PackageNotFoundError, version

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.routing import QulfRequest, QulfResponse, QulfRoute

try:
    __version__ = version("qulf")
except PackageNotFoundError:
    __version__ = "unknown"

from .core import Qulf

__all__ = [
    "Qulf",
    "QulfConfig",
    "QulfRequest",
    "QulfResponse",
    "QulfRoute",
    "__version__",
]
