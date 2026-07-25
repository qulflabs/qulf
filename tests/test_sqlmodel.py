from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.sqlmodel import SQLModelAdapter
from qulf.config import DeletionStrategy
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


@pytest.mark.asyncio
async def test_sqlmodel_hard_deletes_and_misses(sqlmodel_adapter: SQLModelAdapter):
    await sqlmodel_adapter.delete_user("fake-id", DeletionStrategy.HARD)
    assert (
        await sqlmodel_adapter.get_user_by_email_with_password("nobody@nowhere.com")
        is None
    )
    assert await sqlmodel_adapter.get_user_by_id_with_password("fake-id") is None

    user = await sqlmodel_adapter.create_user(
        UserCreate(
            name="a",
            email="soft@test.com",
            username="softu",
            password="p",
            password_confirmation="p",
        ),
        "hashed",
    )

    u1 = await sqlmodel_adapter.get_user_by_id_with_password(str(user.id))
    assert u1 is not None and u1.hashed_password == "hashed"

    u2 = await sqlmodel_adapter.get_user_by_email_with_password("soft@test.com")
    assert u2 is not None and u2.hashed_password == "hashed"

    # Soft delete
    await sqlmodel_adapter.delete_user(str(user.id), DeletionStrategy.SOFT)
    deleted_user = await sqlmodel_adapter.get_user_by_id(str(user.id))
    assert deleted_user is not None
    assert deleted_user.deleted_at is not None

    # Hard delete
    await sqlmodel_adapter.delete_user(str(user.id), DeletionStrategy.HARD)
    hard_deleted = await sqlmodel_adapter.get_user_by_id(str(user.id))
    assert hard_deleted is None


@pytest.mark.asyncio
async def test_sqlmodel_accounts(sqlmodel_adapter: SQLModelAdapter):
    user = await sqlmodel_adapter.create_user(
        UserCreate(
            name="a",
            email="acc@test.com",
            username="accu",
            password="p",
            password_confirmation="p",
        ),
        "hashed",
    )

    acc_data = AccountCreate(
        user_id=str(user.id),
        account_id="acc123",
        provider_id="github",
        access_token="token",
        refresh_token="refresh",
        expires_at=datetime.now(timezone.utc),
        scope="read",
        id_token="id_token",
    )
    acc = await sqlmodel_adapter.create_account(acc_data)
    assert acc is not None

    fetched = await sqlmodel_adapter.get_account_by_provider("github", "acc123")
    assert fetched is not None
    assert fetched.account_id == "acc123"

    miss = await sqlmodel_adapter.get_account_by_provider("google", "acc123")
    assert miss is None


@pytest.mark.asyncio
async def test_sqlmodel_get_and_delete_user(sqlmodel_adapter: SQLModelAdapter):
    from qulf.types import UserCreate

    # 1. Create a dummy user
    user = await sqlmodel_adapter.create_user(
        UserCreate(
            name="a",
            email="del@test.com",
            username="delu",
            password="p",
            password_confirmation="p",
        ),
        "hash",
    )

    # 2. Hit get_user_by_id_with_password (Exists)
    fetched = await sqlmodel_adapter.get_user_by_id_with_password(str(user.id))
    assert fetched is not None
    assert fetched.hashed_password == "hash"
