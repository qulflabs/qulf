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


class TestSQLAlchemySchemaInjection:
    @pytest.fixture
    async def engine_and_session_maker(self):
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        session_maker = async_sessionmaker(engine, expire_on_commit=False)

        yield engine, session_maker

        await engine.dispose()

    @pytest.fixture
    async def injected_auth(self, engine_and_session_maker):
        engine, session_maker = engine_and_session_maker
        adapter = SQLAlchemyAdapter(session_maker)
        plugin = BannedUserPlugin()
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
        )

        auth = Qulf(db=adapter, config=config, plugins=[plugin])

        # Tables must be created after Qulf
        # initialization so the plugin columns are injected.
        async with engine.begin() as conn:
            await conn.run_sync(QulfBase.metadata.create_all)

        return auth

    @pytest.mark.asyncio
    async def test_sqlalchemy_schema_injection(
        self, engine_and_session_maker, injected_auth
    ):
        _, session_maker = engine_and_session_maker

        user_data = UserCreate(
            name="Bad Guy",
            email="bad@guy.com",
            username="badguy",
            password="p",
            password_confirmation="p",
        )
        await injected_auth.sign_up(user_data)

        adapter = injected_auth.db

        async with session_maker() as session:
            result = await session.execute(
                select(adapter.user_model).where(
                    adapter.user_model.email == "bad@guy.com"
                )
            )
            db_user = result.scalar_one()

            assert hasattr(db_user, "is_banned")
            assert hasattr(db_user, "ban_reason")

            db_user.is_banned = True
            db_user.ban_reason = "Spamming"
            await session.commit()

        fetched_user = await adapter.get_user_by_email("bad@guy.com")
        assert fetched_user is not None
        assert fetched_user.email == "bad@guy.com"
