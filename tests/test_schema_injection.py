import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from qulf.adapters.sqlalchemy import QulfBase, SQLAlchemyAdapter
from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.plugins.base import QulfPlugin
from qulf.types import UserCreate


class BannedUserPlugin(QulfPlugin):
    name = "banned_user_plugin"

    def get_custom_columns(self) -> dict[str, dict[str, type]]:
        return {"user": {"is_banned": bool, "ban_reason": str}}


@pytest.mark.asyncio
async def test_sqlalchemy_schema_injection():
    # 1. Setup raw database adapter (DO NOT create tables yet)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    adapter = SQLAlchemyAdapter(session_maker)

    plugin = BannedUserPlugin()
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
    )

    # 2. Initialize Qulf (This dynamically injects the columns into the SQLAlchemy Models!)
    auth = Qulf(db=adapter, config=config, plugins=[plugin])

    # 3. NOW create the tables! SQLAlchemy will see the injected columns and tell SQLite to create them.
    async with engine.begin() as conn:
        await conn.run_sync(QulfBase.metadata.create_all)

    # 4. Create a user
    user_data = UserCreate(
        name="Bad Guy",
        email="bad@guy.com",
        username="badguy",
        password="p",
        password_confirmation="p",
    )
    user = await auth.sign_up(user_data)

    # 5. Update the custom column directly via SQLAlchemy to prove it exists
    async with session_maker() as session:
        result = await session.execute(
            select(adapter.user_model).where(adapter.user_model.email == "bad@guy.com")
        )
        db_user = result.scalar_one()

        assert hasattr(db_user, "is_banned")
        assert hasattr(db_user, "ban_reason")

        db_user.is_banned = True
        db_user.ban_reason = "Spamming"
        await session.commit()

    # 6. Fetch the user through Qulf to ensure Pydantic allows the extra fields
    fetched_user = await auth.db.get_user_by_email("bad@guy.com")
    assert fetched_user is not None
    assert fetched_user.email == "bad@guy.com"
