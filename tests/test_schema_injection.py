from datetime import datetime
from typing import Any

import pytest
from django.db import models
from sqlalchemy import Boolean, DateTime, Integer, String, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import mapped_column

from qulf.adapters.django import DjangoORMAdapter
from qulf.adapters.sqlalchemy import QulfBase, SQLAlchemyAdapter
from qulf.adapters.sqlmodel import SQLModelAdapter
from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.plugins.base import QulfPlugin
from qulf.types import UserCreate


# TEST PLUGINS
class GenericBannedUserPlugin(QulfPlugin):
    """Tests the generic Python-type fallback logic."""

    name = "generic_plugin"

    def get_custom_columns(self) -> dict[str, dict[str, type]]:
        return {
            "user": {
                "strike_count": int,
                "is_banned": bool,
                "ban_reason": str,
                "ban_expires_at": datetime,
            }
        }


class SpecificBannedUserPlugin(QulfPlugin):
    """Tests the native ORM escape hatch precedence logic."""

    name = "specific_plugin"

    def get_custom_columns(self) -> dict[str, dict[str, type]]:
        return {"user": {"should_be_ignored": bool}}

    def get_sqlalchemy_columns(self) -> dict[str, dict[str, Any]]:
        return {
            "user": {
                "sa_strike_count": mapped_column(Integer, default=0),
                "sa_is_banned": mapped_column(Boolean, default=False),
                "sa_ban_reason": mapped_column(String, nullable=True),
                "sa_ban_expires_at": mapped_column(DateTime, nullable=True),
            }
        }

    def get_sqlmodel_columns(self) -> dict[str, dict[str, Any]]:
        from sqlmodel import Field

        return {
            "user": {
                "sm_strike_count": Field(default=0),
                "sm_is_banned": Field(default=False),
                "sm_ban_reason": Field(default=None, nullable=True),
                "sm_ban_expires_at": Field(default=None, nullable=True),
            }
        }

    def get_django_columns(self) -> dict[str, dict[str, Any]]:
        from django.db import models

        return {
            "user": {
                "dj_strike_count": models.IntegerField(default=0),
                "dj_is_banned": models.BooleanField(default=False),
                "dj_ban_reason": models.TextField(null=True, blank=True),
                "dj_ban_expires_at": models.DateTimeField(null=True, blank=True),
            }
        }


# TEST CONFIGURATION
@pytest.fixture
def base_config() -> QulfConfig:
    return QulfConfig(secret_key="super_secret_test_key_that_is_at_least_32_bytes_long")


# SQLALCHEMY TESTS
class TestSQLAlchemySchemaInjection:
    @pytest.fixture
    async def sa_engine_and_session(self) -> Any:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        session_maker = async_sessionmaker(engine, expire_on_commit=False)
        yield engine, session_maker
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_sa_generic_and_specific_injection(
        self, sa_engine_and_session: Any, base_config: QulfConfig
    ) -> None:
        engine, session_maker = sa_engine_and_session
        adapter = SQLAlchemyAdapter(session_maker)

        # Load BOTH plugins to test both paths
        auth = Qulf(
            db=adapter,
            config=base_config,
            plugins=[GenericBannedUserPlugin(), SpecificBannedUserPlugin()],
        )

        async with engine.begin() as conn:
            await conn.run_sync(QulfBase.metadata.create_all)

        await auth.sign_up(
            UserCreate(
                name="Bad Guy",
                email="bad@guy.com",
                username="badguy",
                password="p",
                password_confirmation="p",
            )
        )

        async with session_maker() as session:
            result = await session.execute(
                select(adapter.user_model).where(
                    adapter.user_model.email == "bad@guy.com"
                )
            )
            db_user = result.scalar_one()

            # Generic fallback fields
            assert hasattr(db_user, "strike_count")
            assert hasattr(db_user, "is_banned")
            assert hasattr(db_user, "ban_reason")
            assert hasattr(db_user, "ban_expires_at")

            # Specific override fields
            assert hasattr(db_user, "sa_is_banned")
            assert hasattr(db_user, "sa_ban_reason")
            assert hasattr(db_user, "sa_ban_expires_at")
            assert hasattr(db_user, "sa_strike_count")

            # Proof the generic fallback was ignored for the specific plugin
            assert not hasattr(db_user, "should_be_ignored")

    @pytest.mark.asyncio
    async def test_sa_unknown_table_is_ignored(
        self, sa_engine_and_session: Any, base_config: QulfConfig
    ) -> None:
        engine, session_maker = sa_engine_and_session
        adapter = SQLAlchemyAdapter(session_maker)

        adapter.inject_custom_columns({"unknown_table": {"ghost_col": str}})

        assert not hasattr(adapter.user_model, "ghost_col")


@pytest.mark.django_db(transaction=True)
class TestDjangoSchemaInjection:
    @pytest.mark.asyncio
    async def test_django_generic_and_specific_injection(
        self, django_adapter: DjangoORMAdapter, base_config: QulfConfig
    ) -> None:
        Qulf(
            db=django_adapter,
            config=base_config,
            plugins=[GenericBannedUserPlugin(), SpecificBannedUserPlugin()],
        )

        # Generic plugin columns should be converted from Python types.
        assert hasattr(django_adapter.user_model, "is_banned")
        assert hasattr(django_adapter.user_model, "ban_reason")
        assert hasattr(django_adapter.user_model, "ban_expires_at")

        # Specific Django fields should be used directly through the native
        # Django ORM escape hatch.
        assert hasattr(django_adapter.user_model, "dj_strike_count")
        assert hasattr(django_adapter.user_model, "dj_is_banned")
        assert hasattr(django_adapter.user_model, "dj_ban_reason")
        assert hasattr(django_adapter.user_model, "dj_ban_expires_at")

        # Generic custom columns from another plugin should not leak through
        # the generic Django path when the plugin provides native
        # Django fields.
        assert not hasattr(django_adapter.user_model, "should_be_ignored")

    @pytest.mark.asyncio
    async def test_django_custom_column_type_factories(
        self, django_adapter: DjangoORMAdapter, base_config: QulfConfig
    ) -> None:
        adapter = django_adapter

        custom_columns = {
            "user": {
                "test_string": str,
                "test_integer": int,
                "test_boolean": bool,
                "test_datetime": datetime,
                "test_json": list,
            }
        }
        adapter.inject_custom_columns(custom_columns)

        string_field = adapter.user_model._meta.get_field("test_string")
        integer_field = adapter.user_model._meta.get_field("test_integer")
        boolean_field = adapter.user_model._meta.get_field("test_boolean")
        datetime_field = adapter.user_model._meta.get_field("test_datetime")
        json_field = adapter.user_model._meta.get_field("test_json")

        assert isinstance(string_field, models.CharField)
        assert isinstance(integer_field, models.IntegerField)
        assert isinstance(boolean_field, models.BooleanField)
        assert isinstance(datetime_field, models.DateTimeField)
        assert isinstance(json_field, models.JSONField)

    @pytest.mark.asyncio
    async def test_django_native_field_is_used_directly(
        self, django_adapter: DjangoORMAdapter, base_config: QulfConfig
    ) -> None:
        native_field = models.TextField(null=True, blank=True)

        django_adapter.inject_custom_columns(
            {
                "user": {
                    "test_native_field": native_field,
                }
            }
        )

        field = django_adapter.user_model._meta.get_field("test_native_field")

        assert field is native_field
        assert isinstance(field, models.TextField)

    @pytest.mark.asyncio
    async def test_django_existing_column_is_not_overwritten(
        self, django_adapter: DjangoORMAdapter, base_config: QulfConfig
    ) -> None:
        existing_field = django_adapter.user_model._meta.get_field("email")

        django_adapter.inject_custom_columns(
            {
                "user": {
                    "email": models.IntegerField(),
                }
            }
        )

        field = django_adapter.user_model._meta.get_field("email")

        assert field is existing_field
        assert isinstance(field, models.EmailField)

    @pytest.mark.asyncio
    async def test_django_unknown_table_is_ignored(
        self, django_adapter: DjangoORMAdapter, base_config: QulfConfig
    ) -> None:
        django_adapter.inject_custom_columns(
            {
                "unknown_table": {
                    "should_not_exist": str,
                }
            }
        )

        assert not hasattr(django_adapter.user_model, "should_not_exist")
        assert not hasattr(django_adapter.session_model, "should_not_exist")
        assert not hasattr(django_adapter.account_model, "should_not_exist")


# SQLMODEL TESTS
class TestSQLModelSchemaInjection:
    @pytest.fixture
    async def sm_engine_and_session(self) -> Any:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        session_maker = async_sessionmaker(engine, expire_on_commit=False)
        yield engine, session_maker
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_sm_generic_and_specific_injection(
        self, sm_engine_and_session: Any, base_config: QulfConfig
    ) -> None:
        engine, session_maker = sm_engine_and_session
        adapter = SQLModelAdapter(session_maker)

        auth = Qulf(
            db=adapter,
            config=base_config,
            plugins=[GenericBannedUserPlugin(), SpecificBannedUserPlugin()],
        )

        from sqlmodel import SQLModel

        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        await auth.sign_up(
            UserCreate(
                name="Bad Guy",
                email="bad@guy.com",
                username="badguy",
                password="p",
                password_confirmation="p",
            )
        )

        async with session_maker() as session:
            result = await session.execute(
                select(adapter.user_model).where(
                    adapter.user_model.email == "bad@guy.com"
                )
            )
            db_user = result.scalar_one()

            # Generic fallback fields
            assert hasattr(db_user, "is_banned")
            assert hasattr(db_user, "ban_reason")
            assert hasattr(db_user, "ban_expires_at")

            # Specific override fields
            assert hasattr(db_user, "sm_is_banned")
            assert hasattr(db_user, "sm_ban_reason")
            assert hasattr(db_user, "sm_ban_expires_at")
            assert hasattr(db_user, "sm_strike_count")

            # Proof the generic fallback was ignored
            assert not hasattr(db_user, "should_be_ignored")

    @pytest.mark.asyncio
    async def test_sm_unknown_table_is_ignored(
        self, sm_engine_and_session: Any, base_config: QulfConfig
    ) -> None:
        """Hits the `if not model: continue`
        branch in SQLModel inject_custom_columns."""
        engine, session_maker = sm_engine_and_session
        adapter = SQLModelAdapter(session_maker)

        # Inject into a table that doesn't exist
        adapter.inject_custom_columns({"unknown_table": {"ghost_col": str}})

        # Ensure it didn't accidentally inject it into the user model
        assert not hasattr(adapter.user_model, "ghost_col")
