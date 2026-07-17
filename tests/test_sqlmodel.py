from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.sqlmodel import SQLModelAdapter
from qulf.types import AccountCreate, UserCreate


@pytest.mark.asyncio
async def test_sqlmodel_adapter_flow(sqlmodel_adapter: SQLModelAdapter):
    adapter = sqlmodel_adapter

    user_data = UserCreate(
        name="DB User",
        email="db@test.com",
        username="dbu",
        password="p",
        password_confirmation="p",
    )

    user = await adapter.create_user(user_data, "fake_hashed_password")

    assert user.email == "db@test.com"

    fetched_by_email = await adapter.get_user_by_email("db@test.com")
    assert fetched_by_email is not None
    assert fetched_by_email.hashed_password == "fake_hashed_password"

    fetched_by_id = await adapter.get_user_by_id(user.id)
    assert fetched_by_id is not None

    assert await adapter.get_user_by_email("nobody@test.com") is None
    assert await adapter.get_user_by_id(999) is None

    expires = datetime.now(timezone.utc) + timedelta(days=1)
    session = await adapter.create_session(user.id, "tok123", expires)
    assert session.token == "tok123"

    fetched_sess = await adapter.get_session("tok123")
    assert fetched_sess is not None
    assert await adapter.get_session("bad_token") is None

    await adapter.delete_session("tok123")
    assert await adapter.get_session("tok123") is None


@pytest.mark.asyncio
async def test_sqlmodel_session_validation_naive(sqlmodel_adapter: SQLModelAdapter):
    from qulf.config import QulfConfig
    from qulf.core import Qulf

    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
    )
    auth = Qulf(db=sqlmodel_adapter, config=config)
    user_data = UserCreate(
        name="DB User 2",
        email="db2@test.com",
        username="dbu2",
        password="p",
        password_confirmation="p",
    )
    await auth.sign_up(user_data)
    session = await auth.sign_in("db2@test.com", "p")

    result = await auth.validate_session(session.token)
    assert result is not None
    session, user = result
    assert user and session is not None
    assert user.email == "db2@test.com"


@pytest.mark.asyncio
async def test_sqlmodel_update_user(sqlmodel_adapter: SQLModelAdapter):
    adapter = sqlmodel_adapter

    user = await adapter.create_user(
        UserCreate(
            name="Update Me",
            email="update@test.com",
            username="updater",
            password="p",
            password_confirmation="p",
        ),
        "hash",
    )

    updated = await adapter.update_user(user.id, {"name": "Updated Name"})
    assert updated.name == "Updated Name"

    # Non-existent user should raise
    with pytest.raises(ValueError, match="User not found"):
        await adapter.update_user(99999, {"name": "X"})


@pytest.mark.asyncio
async def test_sqlmodel_session_management(sqlmodel_adapter: SQLModelAdapter):
    adapter = sqlmodel_adapter

    user = await adapter.create_user(
        UserCreate(
            name="Session User",
            email="sessions@test.com",
            username="sessuser",
            password="p",
            password_confirmation="p",
        ),
        "hash",
    )

    expires = datetime.now(timezone.utc) + timedelta(days=1)

    # Create multiple sessions
    s1 = await adapter.create_session(user.id, "sess-tok-1", expires)
    s2 = await adapter.create_session(user.id, "sess-tok-2", expires)
    await adapter.create_session(user.id, "sess-tok-3", expires)

    # get_user_sessions returns all 3
    all_sessions = await adapter.get_user_sessions(user.id)
    assert len(all_sessions) == 3

    # delete_user_session removes the targeted token only
    deleted = await adapter.delete_user_session(user.id, s1.token)
    assert deleted is True
    remaining = await adapter.get_user_sessions(user.id)
    assert len(remaining) == 2

    # delete_user_session returns False for non-existent token
    assert await adapter.delete_user_session(user.id, "ghost-token") is False

    # delete_all_user_sessions with except_token keeps one
    deleted_tokens = await adapter.delete_all_user_sessions(
        user.id, except_token=s2.token
    )
    assert len(deleted_tokens) == 1
    still_alive = await adapter.get_user_sessions(user.id)
    assert len(still_alive) == 1
    assert still_alive[0].token == s2.token

    # delete_all_user_sessions without except_token removes everything
    await adapter.delete_all_user_sessions(user.id)
    assert await adapter.get_user_sessions(user.id) == []


@pytest.mark.asyncio
async def test_sqlmodel_account_management(sqlmodel_adapter: SQLModelAdapter):
    adapter = sqlmodel_adapter

    user = await adapter.create_user(
        UserCreate(
            name="OAuth User",
            email="oauth@test.com",
            username="oauthuser",
            password="p",
            password_confirmation="p",
        ),
        "hash",
    )

    account_data = AccountCreate(
        user_id=user.id,
        provider_id="github",
        account_id="gh-12345",
        access_token="access_abc",
        refresh_token=None,
        expires_at=None,
        scope="read:user",
        id_token=None,
    )

    account = await adapter.create_account(account_data)
    assert account.provider_id == "github"
    assert account.account_id == "gh-12345"

    fetched = await adapter.get_account_by_provider("github", "gh-12345")
    assert fetched is not None
    assert fetched.scope == "read:user"

    # Returns None for unknown provider/account
    assert await adapter.get_account_by_provider("github", "unknown") is None
    assert await adapter.get_account_by_provider("unknown-provider", "gh-12345") is None


@pytest.mark.asyncio
async def test_sqlmodel_inject_custom_columns(sqlmodel_adapter: SQLModelAdapter):
    adapter = sqlmodel_adapter

    # inject_custom_columns with a known table should not raise
    adapter.inject_custom_columns({"user": {"two_factor_secret": str}})

    # inject_custom_columns with an unknown table should silently skip
    adapter.inject_custom_columns({"nonexistent_table": {"some_col": str}})
