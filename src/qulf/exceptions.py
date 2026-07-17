class QulfException(BaseException):
    """
    Base exception for all Qulf errors.

    Inheriting from BaseException ensures that Qulf-specific domain errors
    can be cleanly isolated and handled separately by adapter layers.
    """

    pass


class ConfigurationError(QulfException):
    """
    Raised when a plugin or Qulf core is misconfigured.

    Helps developers fail fast during startup rather than encountering
    runtime bugs in production.
    """

    pass


class UserAlreadyExistsError(QulfException):
    """
    Raised when trying to sign up with an email that is already registered.

    Prevents unauthorized account hijacking via registration forms.
    """

    pass


class AuthenticationError(QulfException):
    """
    Base class for login and session failures.

    Allows catch-all logic for any generic credential or session validation failures.
    """

    pass


class UserNotFoundError(AuthenticationError):
    """
    Raised during sign-in if the email doesn't exist.

    Maintained as a discrete exception internally, although framework adapters may merge
    this with InvalidCredentialsError to prevent user enumeration.
    """

    pass


class InvalidCredentialsError(AuthenticationError):
    """
    Raised during sign-in if the password does not match.
    """

    pass


class InvalidTokenError(AuthenticationError):
    """
    Raised when a magic link, session, or OAuth token is malformed.
    """

    pass


class SessionExpiredError(AuthenticationError):
    """
    Raised when attempting to use an expired session or magic link.
    """

    pass


class Requires2FAError(QulfException):
    """
    Raised when a user tries to login but has 2fa enabled.
    """

    pass


class RateLimitExceededError(QulfException):
    def __init__(self, message: str, retry_after: int):
        super().__init__(message)
        self.retry_after = retry_after
