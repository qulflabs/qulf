from datetime import datetime, timedelta, timezone

import jwt
import pytest

from qulf.config import EmailHooks
from qulf.core import Qulf, QulfConfig
from qulf.exceptions import QulfException


@pytest.fixture
async def auth(memory_db):
    async def dummy_send_reset(email: str, token: str):
        pass

    config = QulfConfig(
        secret_key="asfdsfsdfs89d76f9780fasodhfs0fsdg8fg9fysd0fys0d6f",
        email_hooks=EmailHooks(send_password_reset=dummy_send_reset),
    )

    auth_instance = Qulf(db=memory_db, config=config)
    # Seed a user
    from qulf.types import UserCreate

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
async def test_password_reset_flow(auth: Qulf):
    # 1. Generate token
    token = await auth.generate_password_reset_token("test@test.com")
    assert isinstance(token, str)

    # 2. Reset Password
    user = await auth.reset_password(token, "new_secure_password")
    assert user.email == "test@test.com"

    # 3. Verify auto-verify email worked
    assert user.email_verified_at is not None

    # 4. Try logging in with the new password
    session = await auth.sign_in(
        "test@test.com", "new_secure_password", "127.0.0.1", "test-agent"
    )
    assert session is not None


@pytest.mark.asyncio
async def test_invalid_reset_tokens(auth: Qulf):
    # Test expired token
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

    # Test invalid action
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


@pytest.mark.asyncio
async def test_verify_email_flow(auth: Qulf):
    token = await auth.generate_email_verification_token("test@test.com")
    assert isinstance(token, str)

    user = await auth.verify_email(token)
    assert user is not None
    assert user.email_verified_at is not None


@pytest.mark.asyncio
async def test_change_password(auth: Qulf):
    user = await auth.db.get_user_by_email("test@test.com")
    assert user is not None
    # Wrong old password
    with pytest.raises(QulfException, match="Invalid current password"):
        await auth.change_password(str(user.id), "wrongpassword", "newpass")

    # Correct old password
    updated_user = await auth.change_password(str(user.id), "password123", "newpass")
    assert updated_user is not None

    # Verify login works with new password
    session = await auth.sign_in("test@test.com", "newpass", None, None)
    assert session is not None


@pytest.mark.asyncio
async def test_delete_account(auth: Qulf):
    user = await auth.db.get_user_by_email("test@test.com")
    assert user is not None
    # Delete the account
    await auth.delete_account(str(user.id))

    # Verify soft delete
    deleted_user = await auth.db.get_user_by_id(str(user.id))
    assert deleted_user is not None
    assert deleted_user.deleted_at is not None

    # Ensure they can no longer sign in
    with pytest.raises(QulfException):
        await auth.sign_in("test@test.com", "password123", None, None)


@pytest.mark.asyncio
async def test_core_edge_cases(auth: Qulf):
    # 1. Delete account when disabled
    auth.config.account_deletion.enabled = False
    with pytest.raises(QulfException, match="Account deletion is disabled"):
        await auth.delete_account("some-id")
    auth.config.account_deletion.enabled = True

    # 2. Delete account for non-existent user
    with pytest.raises(QulfException, match="User not found or account deactivated"):
        await auth.delete_account("fake-id")

    # 3. Change password for non-existent user
    with pytest.raises(QulfException, match="User not found or account deactivated"):
        await auth.change_password("fake-id", "old", "new")

    # 4. Verify email with wrong action
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


@pytest.mark.asyncio
async def test_core_deactivated_user_flows(auth: Qulf):
    user = await auth.db.get_user_by_email("test@test.com")
    assert user is not None

    # Generate tokens before we delete them
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

    # Soft delete the user
    await auth.delete_account(str(user.id))

    with pytest.raises(QulfException, match="Account deactivated"):
        await auth.generate_password_reset_token("test@test.com")

    with pytest.raises(QulfException, match="User not found or account deactivated"):
        await auth.reset_password(reset_token, "new")

    with pytest.raises(QulfException, match="User not found or account deactivated"):
        await auth.generate_email_verification_token("test@test.com")

    with pytest.raises(QulfException, match="User not found or account deactivated"):
        await auth.verify_email(verify_token)

    with pytest.raises(QulfException, match="User not found or account deactivated"):
        await auth.change_password(str(user.id), "password123", "new")
