from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from pydantic import ValidationError

from qulf.adapters.base import DatabaseAdapter
from qulf.config import QulfConfig, SessionConfig
from qulf.core import Qulf
from qulf.crypto import verify_password
from qulf.exceptions import (
    AuthorizationError,
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from qulf.plugins.base import QulfPlugin
from qulf.types import Permission, Role, User, UserCreate

# ==========================================
# REUSABLE TEST VARIABLES
# ==========================================
VALID_USER_PAYLOAD = {
    "name": "Test User",
    "email": "test@test.com",
    "username": "tester",
    "password": "securepassword1",
    "password_confirmation": "securepassword1",
}


# ==========================================
# TEST SUITES
# ==========================================


@pytest.mark.asyncio
class TestCoreAuthFlows:
    async def test_signup_and_signin(self, memory_db) -> None:
        auth = Qulf(db=memory_db)
        user_data = UserCreate(**VALID_USER_PAYLOAD)

        new_user = await auth.sign_up(user_data)
        assert new_user.email == "test@test.com"

        session = await auth.sign_in("test@test.com", "securepassword1")
        assert session.token is not None

    async def test_signup_duplicate_email(self, memory_db) -> None:
        auth = Qulf(db=memory_db)
        user_data = UserCreate(**VALID_USER_PAYLOAD)

        await auth.sign_up(user_data)

        with pytest.raises(
            UserAlreadyExistsError, match="Email already associated with an account."
        ):
            await auth.sign_up(user_data)

    async def test_signin_failures(self, memory_db) -> None:
        auth = Qulf(db=memory_db)
        await auth.sign_up(UserCreate(**VALID_USER_PAYLOAD))

        with pytest.raises(UserNotFoundError, match="User not found"):
            await auth.sign_in("wrong@test.com", "securepassword1")

        with pytest.raises(InvalidCredentialsError, match="Password incorrect"):
            await auth.sign_in("test@test.com", "wrong_password")

    async def test_password_mismatch(self) -> None:
        with pytest.raises(ValidationError):
            UserCreate(
                name="T",
                email="t@t.com",
                username="t",
                password="p1",
                password_confirmation="p2",
            )


@pytest.mark.asyncio
class TestCoreSessionManagement:
    async def test_session_validation_and_signout(self, memory_db) -> None:
        auth = Qulf(db=memory_db)
        await auth.sign_up(UserCreate(**VALID_USER_PAYLOAD))
        session = await auth.sign_in("test@test.com", "securepassword1")

        validated = await auth.validate_session(session.token)
        assert validated is not None

        valid_session, user = validated
        assert valid_session is not None
        assert valid_session.token == session.token

        await auth.sign_out(session.token)
        assert await auth.validate_session(session.token) is None

    async def test_expired_session(self, memory_db) -> None:
        auth = Qulf(db=memory_db)
        await auth.sign_up(UserCreate(**VALID_USER_PAYLOAD))
        session = await auth.sign_in("test@test.com", "securepassword1")

        memory_db.sessions[session.token].expires_at = datetime.now(
            timezone.utc
        ) - timedelta(days=30)
        assert await auth.validate_session(session.token) is None

    async def test_validate_session_user_deleted(self, memory_db) -> None:
        auth = Qulf(db=memory_db)
        await auth.sign_up(UserCreate(**VALID_USER_PAYLOAD))
        session = await auth.sign_in("test@test.com", "securepassword1")

        memory_db.users.clear()
        assert await auth.validate_session(session.token) is None

    async def test_jwt_session_strategy(self, memory_db) -> None:
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
            sessions=SessionConfig(strategy="jwt"),
        )
        auth = Qulf(db=memory_db, config=config)

        await auth.sign_up(UserCreate(**VALID_USER_PAYLOAD))
        session = await auth.sign_in("test@test.com", "securepassword1")

        assert len(session.token.split(".")) == 3

        memory_db.sessions.clear()

        result = await auth.validate_session(session.token)
        assert result is not None

        valid_session, user = result
        assert user.email == "test@test.com"
        assert user.name == "Test User"

        expired_payload = {
            "sub": user.id,
            "email": user.email,
            "name": user.name,
            "username": user.username,
            "created_at": user.created_at.timestamp(),
            "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
        }
        expired_token = jwt.encode(
            expired_payload, config.secret_key, algorithm="HS256"
        )
        assert await auth.validate_session(expired_token) is None

    async def test_get_session_from_cookies(self, memory_db) -> None:
        auth = Qulf(db=memory_db)
        await auth.sign_up(UserCreate(**VALID_USER_PAYLOAD))
        session = await auth.sign_in("test@test.com", "securepassword1")

        cookies = {auth.config.cookies.name: session.token}
        result = await auth.get_session_from_cookies(cookies)
        assert result is not None
        assert result[1].email == "test@test.com"

        assert await auth.get_session_from_cookies({}) is None
        assert (
            await auth.get_session_from_cookies({auth.config.cookies.name: "fake"})
            is None
        )


@pytest.mark.asyncio
class TestCoreRBAC:
    @pytest.fixture
    def rbac_auth(self) -> tuple[Qulf, MagicMock, User]:
        mock_db = MagicMock(spec=DatabaseAdapter)
        mock_db.get_user_roles = AsyncMock()
        mock_db.get_user_permissions = AsyncMock()

        config = QulfConfig(secret_key="long_secret_key_for_testing_purposes")
        auth = Qulf(db=mock_db, config=config)

        dummy_user = User(
            id="123",
            email="test@example.com",
            name="Test",
            username="test",
            created_at=datetime.now(timezone.utc),
        )
        return auth, mock_db, dummy_user

    async def test_require_role(self, rbac_auth: tuple[Qulf, MagicMock, User]) -> None:
        auth, mock_db, dummy_user = rbac_auth
        mock_role = Role(id="123", name="admin", created_at=datetime.now(timezone.utc))

        mock_db.get_user_roles.return_value = [mock_role]
        dummy_user.roles = None
        await auth.require_role(dummy_user, "admin")

        mock_db.get_user_roles.return_value = []
        dummy_user.roles = None
        with pytest.raises(
            AuthorizationError, match="User lacks required role: 'admin'"
        ):
            await auth.require_role(dummy_user, "admin")

    async def test_has_role_boolean(
        self, rbac_auth: tuple[Qulf, MagicMock, User]
    ) -> None:
        auth, mock_db, dummy_user = rbac_auth
        mock_role = Role(id="123", name="editor", created_at=datetime.now(timezone.utc))

        mock_db.get_user_roles.return_value = [mock_role]
        assert await auth.has_role(dummy_user, "editor") is True
        assert await auth.has_role(dummy_user, "admin") is False

    async def test_require_permission(
        self, rbac_auth: tuple[Qulf, MagicMock, User]
    ) -> None:
        auth, mock_db, dummy_user = rbac_auth
        mock_perm = Permission(
            id="123", name="write:docs", created_at=datetime.now(timezone.utc)
        )

        mock_db.get_user_permissions.return_value = [mock_perm]
        dummy_user.permissions = None
        await auth.require_permission(dummy_user, "write:docs")

        mock_db.get_user_permissions.return_value = []
        dummy_user.permissions = None
        with pytest.raises(
            AuthorizationError, match="User lacks required permission: 'write:docs'"
        ):
            await auth.require_permission(dummy_user, "write:docs")

    async def test_has_permission_boolean(
        self, rbac_auth: tuple[Qulf, MagicMock, User]
    ) -> None:
        auth, mock_db, dummy_user = rbac_auth
        mock_perm = Permission(
            id="123", name="delete:users", created_at=datetime.now(timezone.utc)
        )

        mock_db.get_user_permissions.return_value = [mock_perm]
        assert await auth.has_permission(dummy_user, "delete:users") is True
        assert await auth.has_permission(dummy_user, "write:docs") is False


class TestCorePlugins:
    def test_base_plugin_defaults(self) -> None:
        plugin = QulfPlugin()
        assert plugin.get_routes() == []
        assert plugin.get_custom_columns() == {}

    def test_get_plugin_registry(self, memory_db) -> None:
        class DummyPluginA(QulfPlugin):
            name = "dummy_a"

        class DummyPluginB(QulfPlugin):
            name = "dummy_b"

        class UnregisteredPlugin(QulfPlugin):
            name = "unregistered"

        plugin_a = DummyPluginA()
        plugin_b = DummyPluginB()

        auth = Qulf(db=memory_db, plugins=[plugin_a, plugin_b])

        assert auth.get_plugin(DummyPluginA) is plugin_a
        assert auth.get_plugin(DummyPluginB, name="dummy_b") is plugin_b
        assert auth.get_plugin(DummyPluginB, name="dummy_a") is None
        assert auth.get_plugin(UnregisteredPlugin) is None
        assert auth.get_plugin(DummyPluginA, name="does_not_exist") is None


class TestCoreCrypto:
    def test_crypto_invalid_hash(self) -> None:
        assert verify_password("password", "this_is_not_a_real_argon2_hash") is False
