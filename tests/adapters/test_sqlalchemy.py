from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.sqlalchemy import SQLAlchemyAdapter
from qulf.config import DeletionStrategy, QulfConfig
from qulf.core import Qulf
from qulf.types import AccountCreate, UserCreate


@pytest.fixture
async def sqla_seeded_user(sqlalchemy_adapter: SQLAlchemyAdapter):
    return await sqlalchemy_adapter.create_user(
        UserCreate(
            name="Seeded User",
            email="seeded@test.com",
            username="seededuser",
            password="p",
            password_confirmation="p",
        ),
        "fake_hashed_password",
    )


@pytest.fixture
async def sqla_seeded_rbac(sqlalchemy_adapter: SQLAlchemyAdapter):
    await sqlalchemy_adapter.create_permission("read:users", "Read users")
    await sqlalchemy_adapter.create_permission("write:users", "Write users")
    await sqlalchemy_adapter.create_role("admin", "Admin role")
    await sqlalchemy_adapter.create_role("user", "User role")
    await sqlalchemy_adapter.grant_permission_to_role("admin", "read:users")
    await sqlalchemy_adapter.grant_permission_to_role("admin", "write:users")
    await sqlalchemy_adapter.grant_permission_to_role("user", "read:users")


class TestSQLAlchemyUserManagement:
    @pytest.mark.asyncio
    async def test_user_creation_and_fetches(
        self, sqlalchemy_adapter: SQLAlchemyAdapter, sqla_seeded_user
    ):
        assert sqla_seeded_user.email == "seeded@test.com"

        fetched_by_email = await sqlalchemy_adapter.get_user_by_email_with_password(
            "seeded@test.com"
        )
        assert fetched_by_email is not None
        assert fetched_by_email.hashed_password == "fake_hashed_password"

        fetched_by_id = await sqlalchemy_adapter.get_user_by_id(sqla_seeded_user.id)
        assert fetched_by_id is not None

        assert await sqlalchemy_adapter.get_user_by_email("nobody@test.com") is None
        assert await sqlalchemy_adapter.get_user_by_id(999) is None

    @pytest.mark.asyncio
    async def test_update_user(
        self, sqlalchemy_adapter: SQLAlchemyAdapter, sqla_seeded_user
    ):
        updated = await sqlalchemy_adapter.update_user(
            sqla_seeded_user.id, {"name": "Changed Name"}
        )
        assert updated.name == "Changed Name"

        with pytest.raises(ValueError, match="User not found"):
            await sqlalchemy_adapter.update_user(9999, {"name": "Changed"})


class TestSQLAlchemyUserDeletion:
    @pytest.mark.asyncio
    async def test_hard_deletes_and_misses(self, sqlalchemy_adapter: SQLAlchemyAdapter):
        await sqlalchemy_adapter.delete_user("fake-id", DeletionStrategy.HARD)

        assert (
            await sqlalchemy_adapter.get_user_by_email_with_password(
                "nobody@nowhere.com"
            )
            is None
        )
        assert await sqlalchemy_adapter.get_user_by_id_with_password("fake-id") is None

    @pytest.mark.asyncio
    async def test_soft_deletes_and_gets(
        self, sqlalchemy_adapter: SQLAlchemyAdapter, sqla_seeded_user
    ):
        user_id = str(sqla_seeded_user.id)

        u1 = await sqlalchemy_adapter.get_user_by_id_with_password(user_id)
        assert u1 is not None and u1.hashed_password == "fake_hashed_password"

        u2 = await sqlalchemy_adapter.get_user_by_email_with_password(
            sqla_seeded_user.email
        )
        assert u2 is not None and u2.hashed_password == "fake_hashed_password"

        await sqlalchemy_adapter.delete_user(user_id, DeletionStrategy.SOFT)

        deleted_user = await sqlalchemy_adapter.get_user_by_id(user_id)
        assert deleted_user is not None
        assert deleted_user.deleted_at is not None


class TestSQLAlchemySessionManagement:
    @pytest.mark.asyncio
    async def test_single_session_lifecycle(
        self, sqlalchemy_adapter: SQLAlchemyAdapter, sqla_seeded_user
    ):
        expires = datetime.now(timezone.utc) + timedelta(days=1)
        session = await sqlalchemy_adapter.create_session(
            sqla_seeded_user.id, "tok123", expires
        )
        assert session.token == "tok123"

        fetched_sess = await sqlalchemy_adapter.get_session("tok123")
        assert fetched_sess is not None
        assert await sqlalchemy_adapter.get_session("bad_token") is None

        await sqlalchemy_adapter.delete_session("tok123")
        assert await sqlalchemy_adapter.get_session("tok123") is None

    @pytest.mark.asyncio
    async def test_extended_session_management(
        self, sqlalchemy_adapter: SQLAlchemyAdapter, sqla_seeded_user
    ):
        expires = datetime.now(timezone.utc)

        await sqlalchemy_adapter.create_session(sqla_seeded_user.id, "tok1", expires)
        await sqlalchemy_adapter.create_session(sqla_seeded_user.id, "tok2", expires)
        await sqlalchemy_adapter.create_session(sqla_seeded_user.id, "tok3", expires)

        sessions = await sqlalchemy_adapter.get_user_sessions(sqla_seeded_user.id)
        assert len(sessions) == 3

        deleted = await sqlalchemy_adapter.delete_user_session(
            sqla_seeded_user.id, "tok1"
        )
        assert deleted is True

        deleted_bad = await sqlalchemy_adapter.delete_user_session(
            sqla_seeded_user.id, "bad_tok"
        )
        assert deleted_bad is False

        deleted_tokens = await sqlalchemy_adapter.delete_all_user_sessions(
            sqla_seeded_user.id, except_token="tok2"
        )
        assert len(deleted_tokens) == 1
        assert deleted_tokens[0] == "tok3"

        sessions_left = await sqlalchemy_adapter.get_user_sessions(sqla_seeded_user.id)
        assert len(sessions_left) == 1
        assert sessions_left[0].token == "tok2"

        final_deleted = await sqlalchemy_adapter.delete_all_user_sessions(
            sqla_seeded_user.id
        )
        assert len(final_deleted) == 1
        assert final_deleted[0] == "tok2"


class TestSQLAlchemyAccountManagement:
    @pytest.mark.asyncio
    async def test_create_and_fetch_account(
        self, sqlalchemy_adapter: SQLAlchemyAdapter, sqla_seeded_user
    ):
        account_data = AccountCreate(
            user_id=sqla_seeded_user.id,
            account_id="gh_123",
            provider_id="github",
            access_token="access_tok",
            refresh_token="refresh_tok",
            expires_at=datetime.now(timezone.utc),
            scope="read:user",
            id_token="id_tok",
        )

        created_account = await sqlalchemy_adapter.create_account(account_data)
        assert created_account.provider_id == "github"
        assert created_account.account_id == "gh_123"

        fetched = await sqlalchemy_adapter.get_account_by_provider("github", "gh_123")
        assert fetched is not None
        assert fetched.user_id == sqla_seeded_user.id

        not_fetched = await sqlalchemy_adapter.get_account_by_provider(
            "github", "wrong_id"
        )
        assert not_fetched is None


class TestSQLAlchemySchemaInjection:
    @pytest.mark.asyncio
    async def test_inject_custom_columns(self, sqlalchemy_adapter: SQLAlchemyAdapter):
        custom_columns = {
            "user": {
                "custom_string": str,
                "custom_int": int,
                "custom_bool": bool,
                "email": str,
            },
            "unknown_table": {"fake_col": str},
        }

        sqlalchemy_adapter.inject_custom_columns(custom_columns)

        assert hasattr(sqlalchemy_adapter.user_model, "custom_string")
        assert hasattr(sqlalchemy_adapter.user_model, "custom_int")
        assert hasattr(sqlalchemy_adapter.user_model, "custom_bool")


class TestSQLAlchemyIntegration:
    @pytest.mark.asyncio
    async def test_session_validation_naive(
        self, sqlalchemy_adapter: SQLAlchemyAdapter
    ):
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
        )
        auth = Qulf(db=sqlalchemy_adapter, config=config)

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

        session_obj, user_obj = session_user
        assert user_obj and session_obj is not None
        assert user_obj.email == "db2@test.com"


class TestSQLAlchemyRBAC:
    @pytest.mark.asyncio
    async def test_permissions_crud(self, sqlalchemy_adapter: SQLAlchemyAdapter):
        await sqlalchemy_adapter.create_permission("read:users", "Read users")

        fetched_perm = await sqlalchemy_adapter.get_permission_by_name("read:users")
        assert fetched_perm is not None
        assert fetched_perm.name == "read:users"
        assert await sqlalchemy_adapter.get_permission_by_name("non_existent") is None

    @pytest.mark.asyncio
    async def test_roles_crud(self, sqlalchemy_adapter: SQLAlchemyAdapter):
        await sqlalchemy_adapter.create_role("admin", "Admin role")

        fetched_role = await sqlalchemy_adapter.get_role_by_name("admin")
        assert fetched_role is not None
        assert fetched_role.name == "admin"
        assert await sqlalchemy_adapter.get_role_by_name("non_existent") is None

    @pytest.mark.asyncio
    async def test_grant_permissions_to_roles(
        self, sqlalchemy_adapter: SQLAlchemyAdapter, sqla_seeded_rbac
    ):
        # Assign duplicate permission to trigger
        # the IntegrityError pass block for coverage
        await sqlalchemy_adapter.grant_permission_to_role("admin", "read:users")

        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await sqlalchemy_adapter.grant_permission_to_role("fake_role", "read:users")

        with pytest.raises(ValueError, match="Permission 'fake_perm' does not exist."):
            await sqlalchemy_adapter.grant_permission_to_role("admin", "fake_perm")

    @pytest.mark.asyncio
    async def test_user_role_assignment_and_removal(
        self,
        sqlalchemy_adapter: SQLAlchemyAdapter,
        sqla_seeded_user,
        sqla_seeded_rbac,
    ):
        assert await sqlalchemy_adapter.get_user_roles(sqla_seeded_user.id) == []
        assert await sqlalchemy_adapter.get_user_permissions(sqla_seeded_user.id) == []

        await sqlalchemy_adapter.assign_role_to_user(sqla_seeded_user.id, "admin")
        await sqlalchemy_adapter.assign_role_to_user(sqla_seeded_user.id, "user")

        # Assign duplicate role to trigger the IntegrityError pass block for coverage
        await sqlalchemy_adapter.assign_role_to_user(sqla_seeded_user.id, "admin")

        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await sqlalchemy_adapter.assign_role_to_user(
                sqla_seeded_user.id, "fake_role"
            )

        roles = await sqlalchemy_adapter.get_user_roles(sqla_seeded_user.id)
        role_names = [r.name for r in roles]
        assert "admin" in role_names
        assert "user" in role_names

        permissions = await sqlalchemy_adapter.get_user_permissions(sqla_seeded_user.id)
        perm_names = [p.name for p in permissions]
        assert "read:users" in perm_names
        assert "write:users" in perm_names

        await sqlalchemy_adapter.remove_role_from_user(sqla_seeded_user.id, "admin")

        updated_roles = await sqlalchemy_adapter.get_user_roles(sqla_seeded_user.id)
        updated_role_names = [r.name for r in updated_roles]
        assert "admin" not in updated_role_names
        assert "user" in updated_role_names

        updated_permissions = await sqlalchemy_adapter.get_user_permissions(
            sqla_seeded_user.id
        )
        updated_perm_names = [p.name for p in updated_permissions]
        assert "write:users" not in updated_perm_names
        assert "read:users" in updated_perm_names
