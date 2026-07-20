from importlib.metadata import PackageNotFoundError, version

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.routing import HttpMethod, QulfRequest, QulfResponse, QulfRoute

try:
    __version__ = version("qulf")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = [
    "HttpMethod",
    "Qulf",
    "QulfConfig",
    "QulfRequest",
    "QulfResponse",
    "QulfRoute",
    "__version__",
]
