from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import jwt
import pytest

from qulf.config import EmailHooks
from qulf.core import Qulf, QulfConfig
from qulf.exceptions import QulfException
from qulf.types import UserCreate


@pytest.fixture
async def auth(memory_db) -> Qulf:
    async def dummy_send_reset(email: str, token: str) -> None:
        pass

    config = QulfConfig(
        secret_key="asfdsfsdfs89d76f9780fasodhfs0fsdg8fg9fysd0fys0d6f",
        email_hooks=EmailHooks(send_password_reset=dummy_send_reset),
    )

    auth_instance = Qulf(db=memory_db, config=config)

    await auth_instance.sign_up(
        UserCreate(
            name="Test",
            email="test@test.com",
            username="test_u",
            password="password123",
            password_confirmation="password123",
        )
    )
    return auth_instance


@pytest.mark.asyncio
class TestCoreAccountManagement:
    async def test_password_reset_flow(self, auth: Qulf) -> None:
        token = await auth.generate_password_reset_token("test@test.com")
        assert isinstance(token, str)

        user = await auth.reset_password(token, "new_secure_password")
        assert user.email == "test@test.com"
        assert user.email_verified_at is not None

        session = await auth.sign_in(
            "test@test.com", "new_secure_password", "127.0.0.1", "test-agent"
        )
        assert session is not None

    async def test_invalid_reset_tokens(self, auth: Qulf) -> None:
        expired_payload = {
            "sub": "some-id",
            "action": "reset_password",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=15),
        }
        expired_token = jwt.encode(
            expired_payload, auth.config.secret_key, algorithm="HS256"
        )

        with pytest.raises(QulfException, match="Token expired"):
            await auth.reset_password(expired_token, "new_pass")

        wrong_action_payload = {
            "sub": "some-id",
            "action": "wrong_action",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        }
        wrong_token = jwt.encode(
            wrong_action_payload, auth.config.secret_key, algorithm="HS256"
        )
        with pytest.raises(QulfException, match="Invalid action"):
            await auth.reset_password(wrong_token, "new_pass")

    async def test_verify_email_flow(self, auth: Qulf) -> None:
        token = await auth.generate_email_verification_token("test@test.com")
        assert isinstance(token, str)

        user = await auth.verify_email(token)
        assert user is not None
        assert user.email_verified_at is not None

    async def test_change_password(self, auth: Qulf) -> None:
        user = await auth.db.get_user_by_email("test@test.com")
        assert user is not None

        with pytest.raises(QulfException, match="Invalid current password"):
            await auth.change_password(str(user.id), "wrongpassword", "newpass")

        updated_user = await auth.change_password(
            str(user.id), "password123", "newpass"
        )
        assert updated_user is not None

        session = await auth.sign_in("test@test.com", "newpass", None, None)
        assert session is not None

    async def test_delete_account(self, auth: Qulf) -> None:
        user = await auth.db.get_user_by_email("test@test.com")
        assert user is not None

        await auth.delete_account(str(user.id))

        deleted_user = await auth.db.get_user_by_id(str(user.id))
        assert deleted_user is not None
        assert deleted_user.deleted_at is not None

        with pytest.raises(QulfException):
            await auth.sign_in("test@test.com", "password123", None, None)

    async def test_core_edge_cases(self, auth: Qulf) -> None:
        auth.config.account_deletion.enabled = False
        with pytest.raises(QulfException, match="Account deletion is disabled"):
            await auth.delete_account("some-id")
        auth.config.account_deletion.enabled = True

        with pytest.raises(
            QulfException, match="User not found or account deactivated"
        ):
            await auth.delete_account("fake-id")

        with pytest.raises(
            QulfException, match="User not found or account deactivated"
        ):
            await auth.change_password("fake-id", "old", "new")

        wrong_action_payload = {
            "sub": "some-id",
            "action": "wrong_action",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        }
        wrong_token = jwt.encode(
            wrong_action_payload, auth.config.secret_key, algorithm="HS256"
        )
        with pytest.raises(QulfException, match="Invalid action"):
            await auth.verify_email(wrong_token)

    async def test_core_deactivated_user_flows(self, auth: Qulf) -> None:
        user = await auth.db.get_user_by_email("test@test.com")
        assert user is not None

        reset_token = jwt.encode(
            {
                "sub": str(user.id),
                "action": "reset_password",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            },
            auth.config.secret_key,
            algorithm="HS256",
        )
        verify_token = jwt.encode(
            {
                "sub": str(user.id),
                "action": "verify_email",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            },
            auth.config.secret_key,
            algorithm="HS256",
        )

        await auth.delete_account(str(user.id))

        with pytest.raises(QulfException, match="Account deactivated"):
            await auth.generate_password_reset_token("test@test.com")

        with pytest.raises(
            QulfException, match="User not found or account deactivated"
        ):
            await auth.reset_password(reset_token, "new")

        with pytest.raises(
            QulfException, match="User not found or account deactivated"
        ):
            await auth.generate_email_verification_token("test@test.com")

        with pytest.raises(
            QulfException, match="User not found or account deactivated"
        ):
            await auth.verify_email(verify_token)

        with pytest.raises(
            QulfException, match="User not found or account deactivated"
        ):
            await auth.change_password(str(user.id), "password123", "new")

    async def test_generate_password_reset_nonexistent_user(self, auth: Qulf) -> None:
        with pytest.raises(
            QulfException, match="If the email exists, a reset link will be sent."
        ):
            await auth.generate_password_reset_token("nobody@example.com")

    async def test_reset_password_malformed_and_expired(self, auth: Qulf) -> None:
        with pytest.raises(QulfException, match="Invalid token"):
            await auth.reset_password("this.is.not.a.valid.jwt", "new_pass")

        expired_payload = {
            "sub": "some-id",
            "action": "reset_password",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=15),
        }
        expired_token = jwt.encode(
            expired_payload, auth.config.secret_key, algorithm="HS256"
        )

        with pytest.raises(QulfException, match="Token expired"):
            await auth.reset_password(expired_token, "new_pass")

    async def test_verify_email_invalid_and_expired_tokens(self, auth: Qulf) -> None:
        with pytest.raises(QulfException, match="Invalid token"):
            await auth.verify_email("this.is.not.a.valid.jwt")

        expired_payload = {
            "sub": "some-id",
            "action": "verify_email",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=15),
        }
        expired_token = jwt.encode(
            expired_payload, auth.config.secret_key, algorithm="HS256"
        )

        with pytest.raises(QulfException, match="Token expired"):
            await auth.verify_email(expired_token)

    async def test_email_verification_hook_called(self, memory_db) -> None:

        mock_send_verification = AsyncMock()
        config = QulfConfig(
            email_hooks=EmailHooks(send_verification=mock_send_verification),
        )
        auth = Qulf(db=memory_db, config=config)

        await auth.sign_up(
            UserCreate(
                name="Hook Test",
                email="hook@test.com",
                username="hookuser",
                password="password123",
                password_confirmation="password123",
            )
        )

        await auth.generate_email_verification_token("hook@test.com")
        mock_send_verification.assert_called_once()
