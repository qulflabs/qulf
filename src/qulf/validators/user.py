from __future__ import annotations

from collections.abc import Callable
from typing import Generic, Self, TypeVar

from qulf.exceptions import (
    UserAccountDeactivatedError,
    UserEmailNotVerifiedError,
    UserNotFoundError,
    UserPasswordLoginDisabledError,
)
from qulf.types import User, UserWithPassword

T = TypeVar("T", UserWithPassword, User)


class UserValidator(Generic[T]):
    """A chainable validator for user objects.

    Provides a fluent interface to validate various states of a User 
    (or UserWithPassword) object. If any validation step fails, it raises 
    the corresponding exception. It supports a custom hidden message to 
    obfuscate exact failure reasons.

    Example:
    ```python
    user = UserValidator(user, hidden_message="Invalid credentials") \\
        .exists() \\
        .active() \\
        .verified() \\
        .user
    ```

    Args:
        `user` (T | None): The user object to validate. If None, validation 
            methods will raise a UserNotFoundError.
        `hidden_message` (str | None, optional): A generic error message to 
            override specific default error messages. Defaults to None.
    """

    _user: T | None
    _hidden_message: str | None

    def __init__(
        self,
        user: T | None,
        *,
        hidden_message: str | None = None,
    ) -> None:
        self._user = user
        self._hidden_message = hidden_message

    @property
    def user(self) -> T:
        return self._require_user()

    def _require_user(self) -> T:
        if self._user is None:
            raise UserNotFoundError(self._hidden_message or "User not found.")

        return self._user

    def exists(self) -> Self:
        self._require_user()
        return self

    def active(self) -> Self:
        user = self._require_user()

        if user.deleted_at is not None:
            raise UserAccountDeactivatedError(
                self._hidden_message or "User account has been deactivated."
            )

        return self

    def verified(self) -> Self:
        user = self._require_user()

        if user.email_verified_at is None:
            raise UserEmailNotVerifiedError(
                self._hidden_message or "Email address has not been verified."
            )

        return self

    def password_login_enabled(self) -> Self:
        user = self._require_user()

        hashed_pw = getattr(user, "hashed_password", None)
        if not hashed_pw:
            raise UserPasswordLoginDisabledError(
                self._hidden_message
                or "Password authentication is disabled for this account."
            )
        return self

    def ensure(
        self,
        predicate: bool | Callable[[T], bool],
        error: type[Exception],
        message: str | Callable[[T], str],
    ) -> Self:
        user = self._require_user()

        passed = predicate(user) if callable(predicate) else predicate

        if not passed:
            raise error(message(user) if callable(message) else message)

        return self
