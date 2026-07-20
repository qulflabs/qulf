# tests/test_sqlalchemy.py
from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.sqlalchemy import SQLAlchemyAdapter
from qulf.types import AccountCreate, UserCreate


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_flow(sqlite_adapter: SQLAlchemyAdapter):
    adapter = sqlite_adapter

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
async def test_sqlalchemy_session_validation_naive(sqlite_adapter: SQLAlchemyAdapter):
    from qulf.config import QulfConfig
    from qulf.core import Qulf
    from qulf.types import UserCreate

    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
    )
    auth = Qulf(db=sqlite_adapter, config=config)
    user_data = UserCreate(
        name="DB User 2",
        email="db2@test.com",
        username="dbu2",
        password="p",
        password_confirmation="p",
    )
    await auth.sign_up(user_data)
    session = await auth.sign_in("db2@test.com", "p")
    assert session is not None
    session_user = await auth.validate_session(session.token)
    assert session_user is not None
    session, user = session_user
    assert user and session is not None
    assert user.email == "db2@test.com"


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_inject_columns(sqlite_adapter: SQLAlchemyAdapter):
    # Test injecting into a valid table
    # an unknown table, and a column that already exists
    custom_columns = {
        "user": {
            "custom_string": str,
            "custom_int": int,
            "custom_bool": bool,
            "email": str,  # Already exists, should be skipped
        },
        "unknown_table": {"fake_col": str},
    }

    sqlite_adapter.inject_custom_columns(custom_columns)

    # Verify the custom columns were added to the user model
    assert hasattr(sqlite_adapter.user_model, "custom_string")
    assert hasattr(sqlite_adapter.user_model, "custom_int")
    assert hasattr(sqlite_adapter.user_model, "custom_bool")


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_update_user(sqlite_adapter: SQLAlchemyAdapter):
    user_data = UserCreate(
        name="Update User",
        email="update@test.com",
        username="update_u",
        password="p",
        password_confirmation="p",
    )
    user = await sqlite_adapter.create_user(user_data, "hashed")

    # Success Update
    updated = await sqlite_adapter.update_user(user.id, {"name": "Changed Name"})
    assert updated.name == "Changed Name"

    # Failure Update (User Not Found)
    with pytest.raises(ValueError, match="User not found"):
        await sqlite_adapter.update_user(9999, {"name": "Changed"})


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_sessions_extended(sqlite_adapter: SQLAlchemyAdapter):
    user_data = UserCreate(
        name="Session User",
        email="sess@test.com",
        username="sess_u",
        password="p",
        password_confirmation="p",
    )
    user = await sqlite_adapter.create_user(user_data, "hashed")

    expires = datetime.now(timezone.utc)

    # Create 3 sessions for the same user
    await sqlite_adapter.create_session(user.id, "tok1", expires)
    await sqlite_adapter.create_session(user.id, "tok2", expires)
    await sqlite_adapter.create_session(user.id, "tok3", expires)

    sessions = await sqlite_adapter.get_user_sessions(user.id)
    assert len(sessions) == 3

    # Delete specific user session
    deleted = await sqlite_adapter.delete_user_session(user.id, "tok1")
    assert deleted is True

    # Delete invalid user session
    deleted_bad = await sqlite_adapter.delete_user_session(user.id, "bad_tok")
    assert deleted_bad is False

    # Delete all except tok2
    deleted_tokens = await sqlite_adapter.delete_all_user_sessions(
        user.id, except_token="tok2"
    )
    assert len(deleted_tokens) == 1
    assert deleted_tokens[0] == "tok3"  # tok1 was already deleted, tok2 is excepted

    # Verify only tok2 remains
    sessions_left = await sqlite_adapter.get_user_sessions(user.id)
    assert len(sessions_left) == 1
    assert sessions_left[0].token == "tok2"

    # Delete all remaining without exception
    final_deleted = await sqlite_adapter.delete_all_user_sessions(user.id)
    assert len(final_deleted) == 1
    assert final_deleted[0] == "tok2"


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_accounts(sqlite_adapter: SQLAlchemyAdapter):
    user_data = UserCreate(
        name="Account User",
        email="acc@test.com",
        username="acc_u",
        password="p",
        password_confirmation="p",
    )
    user = await sqlite_adapter.create_user(user_data, "hashed")

    account_data = AccountCreate(
        user_id=user.id,
        account_id="gh_123",
        provider_id="github",
        access_token="access_tok",
        refresh_token="refresh_tok",
        expires_at=datetime.now(timezone.utc),
        scope="read:user",
        id_token="id_tok",
    )

    # Create Account
    created_account = await sqlite_adapter.create_account(account_data)
    assert created_account.provider_id == "github"
    assert created_account.account_id == "gh_123"

    # Fetch valid account
    fetched = await sqlite_adapter.get_account_by_provider("github", "gh_123")
    assert fetched is not None
    assert fetched.user_id == user.id

    # Fetch invalid account
    not_fetched = await sqlite_adapter.get_account_by_provider("github", "wrong_id")
    assert not_fetched is None
