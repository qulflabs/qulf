import importlib
from importlib.metadata import PackageNotFoundError
from unittest.mock import MagicMock, patch

import qulf
from qulf import (
    Account,
    AccountCreate,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    CookieOptions,
    DatabaseAdapter,
    HttpMethod,
    InvalidCredentialsError,
    InvalidTokenError,
    PasskeyCredential,
    PasskeyCredentialCreate,
    PasskeyVerificationError,
    Permission,
    Qulf,
    QulfConfig,
    QulfException,
    QulfPlugin,
    QulfRequest,
    QulfResponse,
    QulfRoute,
    RateLimitExceededError,
    Requires2FAError,
    Role,
    Session,
    SessionExpiredError,
    User,
    UserAccountDeactivatedError,
    UserAlreadyExistsError,
    UserCreate,
    UserEmailNotVerifiedError,
    UserNotFoundError,
    UserPasswordLoginDisabledError,
    UserUpdate,
    UserWithPassword,
)
from qulf.adapters import DatabaseAdapter as AdapterDatabaseAdapter
from qulf.plugins import (
    MagicLinkPlugin,
    OAuthPlugin,
    PasskeyPlugin,
    RateLimitPlugin,
    SessionManagementPlugin,
    TOTPPlugin,
)
from qulf.plugins import (
    QulfPlugin as PluginQulfPlugin,
)


class TestQulfInitialization:
    def test_public_api(self) -> None:
        assert Qulf is not None
        assert QulfConfig is not None
        assert DatabaseAdapter is not None
        assert QulfPlugin is not None
        assert User is not None
        assert Session is not None
        assert UserCreate is not None
        assert UserUpdate is not None
        assert UserWithPassword is not None
        assert Account is not None
        assert AccountCreate is not None
        assert Role is not None
        assert Permission is not None
        assert CookieOptions is not None
        assert HttpMethod is not None
        assert QulfRequest is not None
        assert QulfResponse is not None
        assert QulfRoute is not None
        assert QulfException is not None
        assert AuthenticationError is not None
        assert AuthorizationError is not None
        assert ConfigurationError is not None
        assert InvalidCredentialsError is not None
        assert InvalidTokenError is not None
        assert PasskeyCredential is not None
        assert PasskeyCredentialCreate is not None
        assert PasskeyVerificationError is not None
        assert RateLimitExceededError is not None
        assert Requires2FAError is not None
        assert SessionExpiredError is not None
        assert UserAccountDeactivatedError is not None
        assert UserAlreadyExistsError is not None
        assert UserEmailNotVerifiedError is not None
        assert UserNotFoundError is not None
        assert UserPasswordLoginDisabledError is not None

    def test_plugins_public_api(self) -> None:
        assert PluginQulfPlugin is not None
        assert MagicLinkPlugin is not None
        assert OAuthPlugin is not None
        assert PasskeyPlugin is not None
        assert RateLimitPlugin is not None
        assert SessionManagementPlugin is not None
        assert TOTPPlugin is not None

    def test_adapters_public_api(self) -> None:
        assert AdapterDatabaseAdapter is not None
        assert AdapterDatabaseAdapter is DatabaseAdapter

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


class TestExceptionHierarchy:
    """Regression tests for QL-37.

    QulfException must inherit from Exception, not BaseException, so that
    standard ``except Exception:`` blocks and web-framework middleware can
    catch Qulf errors without requiring special-cased handlers.
    """

    def test_qulf_exception_is_exception_subclass(self) -> None:
        assert issubclass(QulfException, Exception)

    def test_qulf_exception_is_not_bare_base_exception(self) -> None:
        # Guard against accidentally re-rooting to BaseException.
        assert QulfException.__bases__ != (BaseException,)

    def test_all_subclasses_catchable_as_exception(self) -> None:
        subclasses = [
            AuthenticationError,
            AuthorizationError,
            ConfigurationError,
            InvalidCredentialsError,
            InvalidTokenError,
            PasskeyVerificationError,
            RateLimitExceededError,
            Requires2FAError,
            SessionExpiredError,
            UserAccountDeactivatedError,
            UserAlreadyExistsError,
            UserEmailNotVerifiedError,
            UserNotFoundError,
            UserPasswordLoginDisabledError,
        ]
        for cls in subclasses:
            assert issubclass(cls, Exception), (
                f"{cls.__name__} must be catchable as `except Exception:`"
            )
