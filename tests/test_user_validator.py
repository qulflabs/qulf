from datetime import datetime, timezone

import pytest

from qulf.exceptions import (
    UserAccountDeactivatedError,
    UserEmailNotVerifiedError,
    UserNotFoundError,
    UserPasswordLoginDisabledError,
)
from qulf.types import UserWithPassword
from qulf.validators import UserValidator


@pytest.fixture
def valid_user() -> UserWithPassword:
    return UserWithPassword(
        id="1",
        email="test@test.com",
        name="Test",
        username="test",
        created_at=datetime.now(timezone.utc),
        email_verified_at=datetime.now(timezone.utc),
        hashed_password="secure_hash",
        deleted_at=None,
    )


def test_validator_successful_chain(valid_user: UserWithPassword) -> None:
    user = (
        UserValidator(valid_user)
        .exists()
        .active()
        .verified()
        .password_login_enabled()
        .user
    )
    assert user == valid_user


def test_validator_missing_user() -> None:
    with pytest.raises(UserNotFoundError):
        UserValidator(None).exists()


def test_validator_deactivated_user(valid_user: UserWithPassword) -> None:
    valid_user.deleted_at = datetime.now(timezone.utc)
    with pytest.raises(UserAccountDeactivatedError):
        UserValidator(valid_user).active()


def test_validator_unverified_user(valid_user: UserWithPassword) -> None:
    valid_user.email_verified_at = None
    with pytest.raises(UserEmailNotVerifiedError):
        UserValidator(valid_user).verified()


def test_validator_password_login_disabled(valid_user: UserWithPassword) -> None:
    valid_user.hashed_password = ""
    with pytest.raises(UserPasswordLoginDisabledError):
        UserValidator(valid_user).password_login_enabled()


def test_validator_hidden_message(valid_user: UserWithPassword) -> None:
    valid_user.deleted_at = datetime.now(timezone.utc)
    with pytest.raises(UserAccountDeactivatedError, match="Generic Error"):
        UserValidator(valid_user, hidden_message="Generic Error").active()


def test_validator_ensure_predicate(valid_user: UserWithPassword) -> None:
    class CustomError(Exception):
        pass

    with pytest.raises(CustomError):
        UserValidator(valid_user).ensure(False, CustomError, "string message")

    validator = UserValidator(valid_user).ensure(True, CustomError, "string message")
    assert validator.user is not None
