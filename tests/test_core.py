from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from qulf.core import Qulf
from qulf.crypto import verify_password
from qulf.exceptions import (
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from qulf.types import UserCreate


@pytest.mark.asyncio
async def test_signup_and_signin(memory_db):
    auth = Qulf(db=memory_db)

    user_data = UserCreate(
        name="Test",
        email="test@test.com",
        username="tester123",
        password="securepassword1",
        password_confirmation="securepassword1",
    )
    new_user = await auth.sign_up(user_data)
    assert new_user.email == "test@test.com"

    session = await auth.sign_in("test@test.com", "securepassword1")
    assert session.token is not None


@pytest.mark.asyncio
async def test_signup_duplicate_email(memory_db):
    auth = Qulf(db=memory_db)
    user_data = UserCreate(
        name="Test",
        email="test@test.com",
        username="tester",
        password="password",
        password_confirmation="password",
    )
    await auth.sign_up(user_data)
    with pytest.raises(
        UserAlreadyExistsError, match="Email already associated with an account."
    ):
        await auth.sign_up(user_data)


@pytest.mark.asyncio
async def test_signin_failures(memory_db):
    auth = Qulf(db=memory_db)
    await auth.sign_up(
        UserCreate(
            name="Test",
            email="test@test.com",
            username="tester",
            password="correct_password",
            password_confirmation="correct_password",
        )
    )
    with pytest.raises(UserNotFoundError, match="User not found"):
        await auth.sign_in("wrong@test.com", "correct_password")
    with pytest.raises(InvalidCredentialsError, match="Password incorrect"):
        await auth.sign_in("test@test.com", "wrong_password")


def test_password_mismatch():
    with pytest.raises(ValidationError):
        UserCreate(
            name="T",
            email="t@t.com",
            username="t",
            password="p1",
            password_confirmation="p2",
        )


@pytest.mark.asyncio
async def test_session_validation_and_signout(memory_db):
    auth = Qulf(db=memory_db)
    await auth.sign_up(
        UserCreate(
            name="T",
            email="t@t.com",
            username="t",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("t@t.com", "p")

    valid_session, user = await auth.validate_session(session.token)

    assert valid_session is not None
    assert valid_session.token == session.token

    await auth.sign_out(session.token)
    assert await auth.validate_session(session.token) == (None, None)


@pytest.mark.asyncio
async def test_expired_session(memory_db):
    auth = Qulf(db=memory_db)
    await auth.sign_up(
        UserCreate(
            name="T",
            email="t@t.com",
            username="t",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("t@t.com", "p")

    memory_db.sessions[session.token].expires_at = datetime.now(
        timezone.utc
    ) - timedelta(days=1)
    assert await auth.validate_session(session.token) == (None, None)


def test_crypto_invalid_hash():
    assert verify_password("password", "this_is_not_a_real_argon2_hash") is False


@pytest.mark.asyncio
async def test_validate_session_user_deleted(memory_db):
    auth = Qulf(db=memory_db)
    await auth.sign_up(
        UserCreate(
            name="T",
            email="t@t.com",
            username="t",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("t@t.com", "p")

    memory_db.users.clear()

    assert await auth.validate_session(session.token) == (None, None)


def test_base_plugin_routing():
    from qulf.plugins.base import QulfPlugin

    plugin = QulfPlugin()
    plugin.name = "dummy"
    assert plugin.get_fastapi_router(None) is None
