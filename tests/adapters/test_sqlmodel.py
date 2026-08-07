from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.sqlmodel import SQLModelAdapter
from qulf.config import DeletionStrategy, QulfConfig
from qulf.core import Qulf
from qulf.types import AccountCreate, UserCreate


@pytest.fixture
async def sqlmodel_seeded_user(sqlmodel_adapter: SQLModelAdapter):
    return await sqlmodel_adapter.create_user(
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
async def sqlmodel_seeded_rbac(sqlmodel_adapter: SQLModelAdapter):
    await sqlmodel_adapter.create_permission("read:users", "Read users")
    await sqlmodel_adapter.create_permission("write:users", "Write users")
    await sqlmodel_adapter.create_role("admin", "Admin role")
    await sqlmodel_adapter.create_role("user", "User role")
    await sqlmodel_adapter.grant_permission_to_role("admin", "read:users")
    await sqlmodel_adapter.grant_permission_to_role("admin", "write:users")
    await sqlmodel_adapter.grant_permission_to_role("user", "read:users")


class TestSQLModelUserManagement:
    @pytest.mark.asyncio
    async def test_user_creation_and_fetches(
        self, sqlmodel_adapter: SQLModelAdapter, sqlmodel_seeded_user
    ):
        assert sqlmodel_seeded_user.email == "seeded@test.com"

        fetched_by_email = await sqlmodel_adapter.get_user_by_email("seeded@test.com")
        assert fetched_by_email is not None
        assert fetched_by_email.hashed_password == "fake_hashed_password"

        fetched_by_email_pw = await sqlmodel_adapter.get_user_by_id_with_password(
            str(sqlmodel_seeded_user.id)
        )
        assert fetched_by_email_pw is not None
        assert fetched_by_email_pw.hashed_password == "fake_hashed_password"

        fetched_by_id = await sqlmodel_adapter.get_user_by_id(sqlmodel_seeded_user.id)
        assert fetched_by_id is not None

        assert await sqlmodel_adapter.get_user_by_email("nobody@test.com") is None
        assert await sqlmodel_adapter.get_user_by_id(999) is None

    @pytest.mark.asyncio
    async def test_update_user(
        self, sqlmodel_adapter: SQLModelAdapter, sqlmodel_seeded_user
    ):
        updated = await sqlmodel_adapter.update_user(
            sqlmodel_seeded_user.id, {"name": "Updated Name"}
        )
        assert updated.name == "Updated Name"

        with pytest.raises(ValueError, match="User not found"):
            await sqlmodel_adapter.update_user(99999, {"name": "X"})


class TestSQLModelUserDeletion:
    @pytest.mark.asyncio
    async def test_hard_deletes_and_misses(self, sqlmodel_adapter: SQLModelAdapter):
        await sqlmodel_adapter.delete_user("fake-id", DeletionStrategy.HARD)

        assert (
            await sqlmodel_adapter.get_user_by_email_with_password("nobody@nowhere.com")
            is None
        )
        assert await sqlmodel_adapter.get_user_by_id_with_password("fake-id") is None

    @pytest.mark.asyncio
    async def test_soft_deletes_and_gets(
        self, sqlmodel_adapter: SQLModelAdapter, sqlmodel_seeded_user
    ):
        user_id = str(sqlmodel_seeded_user.id)

        await sqlmodel_adapter.delete_user(user_id, DeletionStrategy.SOFT)

        deleted_user = await sqlmodel_adapter.get_user_by_id(user_id)
        assert deleted_user is not None
        assert deleted_user.deleted_at is not None

        await sqlmodel_adapter.delete_user(user_id, DeletionStrategy.HARD)
        hard_deleted = await sqlmodel_adapter.get_user_by_id(user_id)
        assert hard_deleted is None


class TestSQLModelSessionManagement:
    @pytest.mark.asyncio
    async def test_single_session_lifecycle(
        self, sqlmodel_adapter: SQLModelAdapter, sqlmodel_seeded_user
    ):
        expires = datetime.now(timezone.utc) + timedelta(days=1)
        session = await sqlmodel_adapter.create_session(
            sqlmodel_seeded_user.id, "tok123", expires
        )
        assert session.token == "tok123"

        fetched_sess = await sqlmodel_adapter.get_session("tok123")
        assert fetched_sess is not None
        assert await sqlmodel_adapter.get_session("bad_token") is None

        await sqlmodel_adapter.delete_session("tok123")
        assert await sqlmodel_adapter.get_session("tok123") is None

    @pytest.mark.asyncio
    async def test_extended_session_management(
        self, sqlmodel_adapter: SQLModelAdapter, sqlmodel_seeded_user
    ):
        expires = datetime.now(timezone.utc) + timedelta(days=1)

        s1 = await sqlmodel_adapter.create_session(
            sqlmodel_seeded_user.id, "sess-tok-1", expires
        )
        s2 = await sqlmodel_adapter.create_session(
            sqlmodel_seeded_user.id, "sess-tok-2", expires
        )
        await sqlmodel_adapter.create_session(
            sqlmodel_seeded_user.id, "sess-tok-3", expires
        )

        all_sessions = await sqlmodel_adapter.get_user_sessions(sqlmodel_seeded_user.id)
        assert len(all_sessions) == 3

        deleted = await sqlmodel_adapter.delete_user_session(
            sqlmodel_seeded_user.id, s1.token
        )
        assert deleted is True

        remaining = await sqlmodel_adapter.get_user_sessions(sqlmodel_seeded_user.id)
        assert len(remaining) == 2

        assert (
            await sqlmodel_adapter.delete_user_session(
                sqlmodel_seeded_user.id, "ghost-token"
            )
            is False
        )

        deleted_tokens = await sqlmodel_adapter.delete_all_user_sessions(
            sqlmodel_seeded_user.id, except_token=s2.token
        )
        assert len(deleted_tokens) == 1

        still_alive = await sqlmodel_adapter.get_user_sessions(sqlmodel_seeded_user.id)
        assert len(still_alive) == 1
        assert still_alive[0].token == s2.token

        await sqlmodel_adapter.delete_all_user_sessions(sqlmodel_seeded_user.id)
        assert await sqlmodel_adapter.get_user_sessions(sqlmodel_seeded_user.id) == []


class TestSQLModelAccountManagement:
    @pytest.mark.asyncio
    async def test_create_and_fetch_account(
        self, sqlmodel_adapter: SQLModelAdapter, sqlmodel_seeded_user
    ):
        account_data = AccountCreate(
            user_id=sqlmodel_seeded_user.id,
            provider_id="github",
            account_id="gh-12345",
            access_token="access_abc",
            refresh_token=None,
            expires_at=datetime.now(timezone.utc),
            scope="read:user",
            id_token=None,
        )

        account = await sqlmodel_adapter.create_account(account_data)
        assert account.provider_id == "github"
        assert account.account_id == "gh-12345"

        fetched = await sqlmodel_adapter.get_account_by_provider("github", "gh-12345")
        assert fetched is not None
        assert fetched.scope == "read:user"

        assert (
            await sqlmodel_adapter.get_account_by_provider("github", "unknown") is None
        )
        assert (
            await sqlmodel_adapter.get_account_by_provider("unknown", "gh-12345")
            is None
        )


class TestSQLModelSchemaInjection:
    @pytest.mark.asyncio
    async def test_inject_custom_columns(self, sqlmodel_adapter: SQLModelAdapter):
        sqlmodel_adapter.inject_custom_columns({"user": {"two_factor_secret": str}})
        sqlmodel_adapter.inject_custom_columns({"nonexistent_table": {"some_col": str}})


class TestSQLModelIntegration:
    @pytest.mark.asyncio
    async def test_session_validation_naive(self, sqlmodel_adapter: SQLModelAdapter):
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

        session_obj, user_obj = result
        assert user_obj and session_obj is not None
        assert user_obj.email == "db2@test.com"


class TestSQLModelRBAC:
    @pytest.mark.asyncio
    async def test_permissions_crud(self, sqlmodel_adapter: SQLModelAdapter):
        await sqlmodel_adapter.create_permission("read:users", "Read users")

        fetched_perm = await sqlmodel_adapter.get_permission_by_name("read:users")
        assert fetched_perm is not None
        assert fetched_perm.name == "read:users"
        assert await sqlmodel_adapter.get_permission_by_name("non_existent") is None

    @pytest.mark.asyncio
    async def test_roles_crud(self, sqlmodel_adapter: SQLModelAdapter):
        await sqlmodel_adapter.create_role("admin", "Admin role")

        fetched_role = await sqlmodel_adapter.get_role_by_name("admin")
        assert fetched_role is not None
        assert fetched_role.name == "admin"
        assert await sqlmodel_adapter.get_role_by_name("non_existent") is None

    @pytest.mark.asyncio
    async def test_grant_permissions_to_roles(
        self, sqlmodel_adapter: SQLModelAdapter, sqlmodel_seeded_rbac
    ):
        await sqlmodel_adapter.grant_permission_to_role("admin", "read:users")

        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await sqlmodel_adapter.grant_permission_to_role("fake_role", "read:users")

        with pytest.raises(ValueError, match="Permission 'fake_perm' does not exist."):
            await sqlmodel_adapter.grant_permission_to_role("admin", "fake_perm")

    @pytest.mark.asyncio
    async def test_user_role_assignment_and_removal(
        self,
        sqlmodel_adapter: SQLModelAdapter,
        sqlmodel_seeded_user,
        sqlmodel_seeded_rbac,
    ):
        assert await sqlmodel_adapter.get_user_roles(sqlmodel_seeded_user.id) == []
        assert (
            await sqlmodel_adapter.get_user_permissions(sqlmodel_seeded_user.id) == []
        )

        await sqlmodel_adapter.assign_role_to_user(sqlmodel_seeded_user.id, "admin")
        await sqlmodel_adapter.assign_role_to_user(sqlmodel_seeded_user.id, "user")

        await sqlmodel_adapter.assign_role_to_user(sqlmodel_seeded_user.id, "admin")

        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await sqlmodel_adapter.assign_role_to_user(
                sqlmodel_seeded_user.id, "fake_role"
            )

        roles = await sqlmodel_adapter.get_user_roles(sqlmodel_seeded_user.id)
        role_names = [r.name for r in roles]
        assert "admin" in role_names
        assert "user" in role_names

        permissions = await sqlmodel_adapter.get_user_permissions(
            sqlmodel_seeded_user.id
        )
        perm_names = [p.name for p in permissions]
        assert "read:users" in perm_names
        assert "write:users" in perm_names

        await sqlmodel_adapter.remove_role_from_user(sqlmodel_seeded_user.id, "admin")

        await sqlmodel_adapter.remove_role_from_user(
            sqlmodel_seeded_user.id, "non_existent_role"
        )

        updated_roles = await sqlmodel_adapter.get_user_roles(sqlmodel_seeded_user.id)
        updated_role_names = [r.name for r in updated_roles]
        assert "admin" not in updated_role_names
        assert "user" in updated_role_names

        updated_permissions = await sqlmodel_adapter.get_user_permissions(
            sqlmodel_seeded_user.id
        )
        updated_perm_names = [p.name for p in updated_permissions]
        assert "write:users" not in updated_perm_names
        assert "read:users" in updated_perm_names
