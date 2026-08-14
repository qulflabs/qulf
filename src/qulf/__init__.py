from importlib.metadata import PackageNotFoundError, version

from qulf.adapters.base import DatabaseAdapter
from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    InvalidCredentialsError,
    InvalidTokenError,
    PasskeyVerificationError,
    QulfException,
    RateLimitExceededError,
    Requires2FAError,
    SessionExpiredError,
    UserAccountDeactivatedError,
    UserAlreadyExistsError,
    UserEmailNotVerifiedError,
    UserNotFoundError,
    UserPasswordLoginDisabledError,
)
from qulf.plugins.base import QulfPlugin
from qulf.routing import CookieOptions, HttpMethod, QulfRequest, QulfResponse, QulfRoute
from qulf.types import (
    Account,
    AccountCreate,
    Permission,
    Role,
    Session,
    User,
    UserCreate,
    UserUpdate,
    UserWithPassword,
)

try:
    __version__ = version("qulf")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = [
    "Account",
    "AccountCreate",
    "AuthenticationError",
    "AuthorizationError",
    "ConfigurationError",
    "CookieOptions",
    "DatabaseAdapter",
    "HttpMethod",
    "InvalidCredentialsError",
    "InvalidTokenError",
    "PasskeyVerificationError",
    "Permission",
    "Qulf",
    "QulfConfig",
    "QulfException",
    "QulfPlugin",
    "QulfRequest",
    "QulfResponse",
    "QulfRoute",
    "RateLimitExceededError",
    "Requires2FAError",
    "Role",
    "Session",
    "SessionExpiredError",
    "User",
    "UserAccountDeactivatedError",
    "UserAlreadyExistsError",
    "UserCreate",
    "UserEmailNotVerifiedError",
    "UserNotFoundError",
    "UserPasswordLoginDisabledError",
    "UserUpdate",
    "UserWithPassword",
    "__version__",
]
