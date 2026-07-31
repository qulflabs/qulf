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

    validated = await auth.validate_session(session.token)

    assert validated is not None

    valid_session, user = validated

    assert valid_session is not None
    assert valid_session.token == session.token

    await auth.sign_out(session.token)
    assert await auth.validate_session(session.token) is None


@pytest.mark.asyncio
async def test_expired_session(auth, memory_db):
    from qulf.types import UserCreate

    # 1. Sign up and sign in a test user
    await auth.sign_up(
        UserCreate(
            name="Expired Guy",
            email="expired@test.com",
            username="exp_user",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("expired@test.com", "p")

    auth.db.sessions[session.token].expires_at = datetime.now(timezone.utc) - timedelta(
        days=30
    )

    assert await auth.validate_session(session.token) is None


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

    assert await auth.validate_session(session.token) is None


def test_base_plugin_routing():
    from qulf.plugins.base import QulfPlugin

    base_plugin = QulfPlugin()
    assert base_plugin.get_routes() == []


@pytest.mark.asyncio
async def test_jwt_session_strategy(memory_db):
    from qulf.config import QulfConfig, SessionConfig

    # 1. Initialize Qulf in JWT Mode
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
        sessions=SessionConfig(strategy="jwt"),
    )
    auth = Qulf(db=memory_db, config=config)

    # 2. Sign up and Sign in
    await auth.sign_up(
        UserCreate(
            name="JWT User",
            email="jwt@test.com",
            username="jwtuser",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("jwt@test.com", "p")

    # the token is a JWT
    assert len(session.token.split(".")) == 3

    # Validate Session Statelessly
    memory_db.sessions.clear()  # Simulate an empty database or cache miss

    result = await auth.validate_session(session.token)
    assert result is not None
    valid_session, user = result

    # reconstructed the user from the JWT payload
    assert user.email == "jwt@test.com"
    assert user.name == "JWT User"

    # expired JWTs are caught
    from datetime import datetime, timedelta, timezone

    import jwt

    expired_payload = {
        "sub": user.id,
        "email": user.email,
        "name": user.name,
        "username": user.username,
        "created_at": user.created_at.timestamp(),
        "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
    }
    expired_token = jwt.encode(expired_payload, config.secret_key, algorithm="HS256")

    assert await auth.validate_session(expired_token) is None

    @pytest.mark.asyncio
    async def test_get_session_from_cookies(memory_db):
        auth = Qulf(db=memory_db)
        await auth.sign_up(
            UserCreate(
                name="Cookie User",
                email="cookie@test.com",
                username="cookie_monster",
                password="p",
                password_confirmation="p",
            )
        )
        session = await auth.sign_in("cookie@test.com", "p")

        # Test Valid Cookie
        cookies = {auth.config.cookies.name: session.token}
        result = await auth.get_session_from_cookies(cookies)
        assert result is not None
        assert result[1].email == "cookie@test.com"

        # Test Missing Cookie
        assert await auth.get_session_from_cookies({}) is None

        # Test Invalid Cookie
        assert (
            await auth.get_session_from_cookies({auth.config.cookies.name: "fake"})
            is None
        )


def test_get_plugin_registry(memory_db):
    """Test the generic get_plugin method for type safety and resolution."""
    from qulf.plugins.base import QulfPlugin

    class DummyPluginA(QulfPlugin):
        name = "dummy_a"

    class DummyPluginB(QulfPlugin):
        name = "dummy_b"

    class UnregisteredPlugin(QulfPlugin):
        name = "unregistered"

    plugin_a = DummyPluginA()
    plugin_b = DummyPluginB()

    auth = Qulf(db=memory_db, plugins=[plugin_a, plugin_b])

    # O(N) Fallback scan by class type
    res1 = auth.get_plugin(DummyPluginA)
    assert res1 is plugin_a

    # O(1) Exact lookup by name
    res2 = auth.get_plugin(DummyPluginB, name="dummy_b")
    assert res2 is plugin_b

    # Type Mismatch Safety
    # (Asking for Plugin B, but the name "dummy_a" points to Plugin A)
    res3 = auth.get_plugin(DummyPluginB, name="dummy_a")
    assert res3 is None

    # Plugin not registered
    res4 = auth.get_plugin(UnregisteredPlugin)
    assert res4 is None

    # Name not found
    res5 = auth.get_plugin(DummyPluginA, name="does_not_exist")
    assert res5 is None


@pytest.mark.asyncio
async def test_core_require_rbac():
    from datetime import datetime, timezone
    from unittest.mock import AsyncMock

    from qulf.config import QulfConfig
    from qulf.core import Qulf
    from qulf.exceptions import AuthorizationError
    from qulf.types import Permission, Role, User

    # 1. Setup Mock DB and Core Engine
    mock_db = AsyncMock()
    config = QulfConfig(secret_key="long_secret_key_for_testing_purposes")
    auth = Qulf(db=mock_db, config=config)

    dummy_user = User(
        id="123",
        email="test@example.com",
        name="Test",
        username="test",
        created_at=datetime.now(timezone.utc),
    )

    # require_role
    mock_role = Role(id="123", name="admin", created_at=datetime.now(timezone.utc))

    # 1. Success Path
    mock_db.get_user_roles.return_value = [mock_role]
    dummy_user.roles = None  # Reset internal cache
    await auth.require_role(dummy_user, "admin")  # Should not raise

    # 2. Failure Path (Raises AuthorizationError)
    mock_db.get_user_roles.return_value = []
    dummy_user.roles = None
    with pytest.raises(AuthorizationError, match="User lacks required role: 'admin'"):
        await auth.require_role(dummy_user, "admin")

    # require_permission
    mock_perm = Permission(
        id="123", name="write:docs", created_at=datetime.now(timezone.utc)
    )

    # Success Path
    mock_db.get_user_permissions.return_value = [mock_perm]
    dummy_user.permissions = None  # Reset internal cache
    await auth.require_permission(dummy_user, "write:docs")  # Should not raise

    # Failure Path (Raises AuthorizationError)
    mock_db.get_user_permissions.return_value = []
    dummy_user.permissions = None
    with pytest.raises(
        AuthorizationError, match="User lacks required permission: 'write:docs'"
    ):
        await auth.require_permission(dummy_user, "write:docs")
