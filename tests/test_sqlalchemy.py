# tests/test_sqlalchemy.py
from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.sqlalchemy import SQLAlchemyAdapter
from qulf.types import UserCreate


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

    session, user = await auth.validate_session(session.token)
    assert user and session is not None
    assert user.email == "db2@test.com"
