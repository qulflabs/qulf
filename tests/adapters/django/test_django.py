from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import pytest
from django.db import DatabaseError

from qulf.adapters.django import DjangoORMAdapter
from qulf.config import DeletionStrategy, QulfConfig
from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.types import AccountCreate, UserCreate


@pytest.fixture(scope="session", autouse=True)
def setup_django_tables(django_db_setup: Any, django_db_blocker: Any) -> None:
    """Foolproof way to build tables for standalone library models."""
    with django_db_blocker.unblock():
        from django.db import connection

        from qulf.adapters.django import (
            DefaultAccount,
            DefaultPermission,
            DefaultRole,
            DefaultRolePermission,
            DefaultSession,
            DefaultUser,
            DefaultUserRole,
        )

        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(DefaultUser)
            schema_editor.create_model(DefaultSession)
            schema_editor.create_model(DefaultAccount)
            schema_editor.create_model(DefaultRole)
            schema_editor.create_model(DefaultPermission)
            schema_editor.create_model(DefaultUserRole)
            schema_editor.create_model(DefaultRolePermission)


@pytest.fixture(autouse=True)
async def clear_django_db() -> None:
    """Manually flush the database between tests to prevent async transaction leaks."""
    from qulf.adapters.django import (
        DefaultAccount,
        DefaultPermission,
        DefaultRole,
        DefaultSession,
        DefaultUser,
    )

    await DefaultSession.objects.all().adelete()
    await DefaultAccount.objects.all().adelete()
    await DefaultUser.objects.all().adelete()
    await DefaultRole.objects.all().adelete()
    await DefaultPermission.objects.all().adelete()


@pytest.fixture
async def django_seeded_user(django_adapter: DjangoORMAdapter) -> Any:
    return await django_adapter.create_user(
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
async def django_seeded_rbac(django_adapter: DjangoORMAdapter) -> None:
    await django_adapter.create_permission("read:users", "Read users")
    await django_adapter.create_permission("write:users", "Write users")
    await django_adapter.create_role("admin", "Admin role")
    await django_adapter.create_role("user", "User role")
    await django_adapter.grant_permission_to_role("admin", "read:users")
    await django_adapter.grant_permission_to_role("admin", "write:users")
    await django_adapter.grant_permission_to_role("user", "read:users")


class TestDjangoUserManagement:
    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_user_creation_and_fetches(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        assert django_seeded_user.email == "seeded@test.com"

        fetched_by_email = await django_adapter.get_user_by_email_with_password(
            "seeded@test.com"
        )
        assert fetched_by_email is not None
        assert fetched_by_email.hashed_password == "fake_hashed_password"

        fetched_by_id = await django_adapter.get_user_by_id(django_seeded_user.id)
        assert fetched_by_id is not None

        assert await django_adapter.get_user_by_email("seeded@test.com") is not None
        assert await django_adapter.get_user_by_email("nobody@test.com") is None
        assert await django_adapter.get_user_by_id(999) is None

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_duplicate_user(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        from qulf.exceptions import QulfException

        with pytest.raises(QulfException, match="User already exists"):
            await django_adapter.create_user(
                UserCreate(
                    name="Seeded User",
                    email="seeded@test.com",
                    username="seededuser",
                    password="p",
                    password_confirmation="p",
                ),
                "fake_hashed_password",
            )

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_update_user(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        updated = await django_adapter.update_user(
            django_seeded_user.id, {"name": "Changed Name"}
        )
        assert updated.name == "Changed Name"

        with pytest.raises(ValueError, match="User not found"):
            await django_adapter.update_user(9999, {"name": "Changed"})

        assert await django_adapter.get_user_by_id_with_password(9999) is None

        with patch.object(
            django_adapter.user_model.objects,
            "acreate",
            side_effect=DatabaseError("DB died"),
        ):
            with pytest.raises(DatabaseError):
                await django_adapter.create_user(
                    UserCreate(
                        name="Bad",
                        email="bad@test.com",
                        username="bad",
                        password="p",
                        password_confirmation="p",
                    ),
                    "hash",
                )

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_user_misses_for_coverage(
        self, django_adapter: DjangoORMAdapter
    ) -> None:
        assert (
            await django_adapter.get_user_by_email_with_password("ghost@test.com")
            is None
        )
        assert await django_adapter.get_user_by_id_with_password(999999) is None

        with patch.object(
            django_adapter.user_model.objects,
            "acreate",
            side_effect=QulfException("Generic Qulf DB Error"),
        ):
            with pytest.raises(QulfException, match="Generic Qulf DB Error"):
                await django_adapter.create_user(
                    UserCreate(
                        name="B",
                        email="b@b.com",
                        username="b",
                        password="p",
                        password_confirmation="p",
                    ),
                    "hash",
                )


class TestDjangoUserDeletion:
    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_hard_deletes_and_misses(
        self, django_adapter: DjangoORMAdapter
    ) -> None:
        res = await django_adapter.delete_user("1204972398423", DeletionStrategy.HARD)
        assert res is False
        assert (
            await django_adapter.get_user_by_email_with_password("nobody@nowhere.com")
            is None
        )
        assert (
            await django_adapter.get_user_by_id_with_password("1204972398423") is None
        )

        user = await django_adapter.create_user(
            UserCreate(
                name="Hard Delete",
                email="harddelete@test.com",
                username="harddelete",
                password="p",
                password_confirmation="p",
            ),
            "hash",
        )
        res = await django_adapter.delete_user(user.id, DeletionStrategy.HARD)
        assert res is True
        assert await django_adapter.get_user_by_id(user.id) is None

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_soft_deletes_and_gets(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        user_id = str(django_seeded_user.id)

        u1 = await django_adapter.get_user_by_id_with_password(user_id)
        assert u1 is not None and u1.hashed_password == "fake_hashed_password"

        u2 = await django_adapter.get_user_by_email_with_password(
            django_seeded_user.email
        )
        assert u2 is not None and u2.hashed_password == "fake_hashed_password"

        res = await django_adapter.delete_user(user_id, DeletionStrategy.SOFT)
        assert res is True

        deleted_user = await django_adapter.get_user_by_id(user_id)
        assert deleted_user is not None
        assert deleted_user.deleted_at is not None


class TestDjangoSessionManagement:
    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_single_session_lifecycle(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        expires = datetime.now(timezone.utc) + timedelta(days=1)
        session = await django_adapter.create_session(
            django_seeded_user.id, "tok123", expires
        )
        assert session.token == "tok123"

        fetched_sess = await django_adapter.get_session("tok123")
        assert fetched_sess is not None
        assert await django_adapter.get_session("bad_token") is None

        res = await django_adapter.delete_session("tok123")
        assert res is True
        assert await django_adapter.get_session("tok123") is None

        res_bad = await django_adapter.delete_session("bad_token")
        assert res_bad is False

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_delete_all_user_sessions_empty(
        self, django_adapter: DjangoORMAdapter
    ) -> None:
        # Covers the branch where deleted_tokens is empty
        deleted = await django_adapter.delete_all_user_sessions(999999)
        assert deleted == []

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_session_deletion_zero_count(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        await django_adapter.create_session(
            django_seeded_user.id, "zero_count_tok", datetime.now(timezone.utc)
        )
        # Mock adelete() to return 0 deleted rows, covering the fallback `return False`
        with patch("django.db.models.Model.adelete", return_value=(0, {})):
            assert await django_adapter.delete_session("zero_count_tok") is False
            assert (
                await django_adapter.delete_user_session(
                    django_seeded_user.id, "zero_count_tok"
                )
                is False
            )

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_extended_session_management(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        expires = datetime.now(timezone.utc)

        await django_adapter.create_session(django_seeded_user.id, "tok1", expires)
        await django_adapter.create_session(django_seeded_user.id, "tok2", expires)
        await django_adapter.create_session(django_seeded_user.id, "tok3", expires)

        sessions = await django_adapter.get_user_sessions(django_seeded_user.id)
        assert len(sessions) == 3

        deleted = await django_adapter.delete_user_session(
            django_seeded_user.id, "tok1"
        )
        assert deleted is True

        deleted_bad = await django_adapter.delete_user_session(
            django_seeded_user.id, "bad_tok"
        )
        assert deleted_bad is False

        deleted_none = await django_adapter.delete_user_session(
            django_seeded_user.id, None
        )
        assert deleted_none is False

        deleted_tokens = await django_adapter.delete_all_user_sessions(
            django_seeded_user.id, except_token="tok2"
        )
        assert len(deleted_tokens) == 1
        assert "tok3" in deleted_tokens

        sessions_left = await django_adapter.get_user_sessions(django_seeded_user.id)
        assert len(sessions_left) == 1
        assert sessions_left[0].token == "tok2"

        final_deleted = await django_adapter.delete_all_user_sessions(
            django_seeded_user.id
        )
        assert len(final_deleted) == 1
        assert final_deleted[0] == "tok2"


class TestDjangoAccountManagement:
    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_create_and_fetch_account(
        self, django_adapter: DjangoORMAdapter, django_seeded_user: Any
    ) -> None:
        account_data = AccountCreate(
            user_id=django_seeded_user.id,
            account_id="gh_123",
            provider_id="github",
            access_token="access_tok",
            refresh_token="refresh_tok",
            expires_at=datetime.now(timezone.utc),
            scope="read:user",
            id_token="id_tok",
        )

        created_account = await django_adapter.create_account(account_data)
        assert created_account.provider_id == "github"
        assert created_account.account_id == "gh_123"

        fetched = await django_adapter.get_account_by_provider("github", "gh_123")
        assert fetched is not None
        assert fetched.user_id == int(django_seeded_user.id)

        not_fetched = await django_adapter.get_account_by_provider("github", "wrong_id")
        assert not_fetched is None


class TestDjangoIntegration:
    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_session_validation_naive(
        self, django_adapter: DjangoORMAdapter
    ) -> None:
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
        )
        auth = Qulf(db=django_adapter, config=config)

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


class TestDjangoRBAC:
    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_permissions_crud(self, django_adapter: DjangoORMAdapter) -> None:
        await django_adapter.create_permission("read:users", "Read users")

        fetched_perm = await django_adapter.get_permission_by_name("read:users")
        assert fetched_perm is not None
        assert fetched_perm.name == "read:users"
        assert await django_adapter.get_permission_by_name("non_existent") is None

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_roles_crud(self, django_adapter: DjangoORMAdapter) -> None:
        await django_adapter.create_role("admin", "Admin role")

        fetched_role = await django_adapter.get_role_by_name("admin")
        assert fetched_role is not None
        assert fetched_role.name == "admin"
        assert await django_adapter.get_role_by_name("non_existent") is None

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_grant_permissions_to_roles(
        self, django_adapter: DjangoORMAdapter, django_seeded_rbac: None
    ) -> None:
        await django_adapter.grant_permission_to_role("admin", "read:users")

        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await django_adapter.grant_permission_to_role("fake_role", "read:users")

        with pytest.raises(ValueError, match="Permission 'fake_perm' does not exist."):
            await django_adapter.grant_permission_to_role("admin", "fake_perm")

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_user_role_assignment_and_removal(
        self,
        django_adapter: DjangoORMAdapter,
        django_seeded_user: Any,
        django_seeded_rbac: None,
    ) -> None:
        assert await django_adapter.get_user_roles(django_seeded_user.id) == []
        assert await django_adapter.get_user_permissions(django_seeded_user.id) == []

        await django_adapter.assign_role_to_user(django_seeded_user.id, "admin")
        await django_adapter.assign_role_to_user(django_seeded_user.id, "user")

        await django_adapter.assign_role_to_user(django_seeded_user.id, "admin")

        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await django_adapter.assign_role_to_user(django_seeded_user.id, "fake_role")

        roles = await django_adapter.get_user_roles(django_seeded_user.id)
        role_names = [r.name for r in roles]
        assert "admin" in role_names
        assert "user" in role_names

        permissions = await django_adapter.get_user_permissions(django_seeded_user.id)
        perm_names = [p.name for p in permissions]
        assert "read:users" in perm_names
        assert "write:users" in perm_names

        await django_adapter.remove_role_from_user(django_seeded_user.id, "admin")

        updated_roles = await django_adapter.get_user_roles(django_seeded_user.id)
        updated_role_names = [r.name for r in updated_roles]
        assert "admin" not in updated_role_names
        assert "user" in updated_role_names

        updated_permissions = await django_adapter.get_user_permissions(
            django_seeded_user.id
        )
        updated_perm_names = [p.name for p in updated_permissions]
        assert "write:users" not in updated_perm_names
        assert "read:users" in updated_perm_names

        await django_adapter.remove_role_from_user(django_seeded_user.id, "fake_role")
        await django_adapter.assign_role_to_user(django_seeded_user.id, "admin")
        await django_adapter.assign_role_to_user(django_seeded_user.id, "admin")

        await django_adapter.remove_role_from_user(django_seeded_user.id, "ghost_role")

    @pytest.mark.django_db
    @pytest.mark.asyncio
    async def test_rbac_integrity_errors(
        self,
        django_adapter: DjangoORMAdapter,
        django_seeded_user: Any,
        django_seeded_rbac: None,
    ) -> None:
        from django.db import IntegrityError

        # Covers `except IntegrityError: pass` in assign_role_to_user
        with patch.object(
            django_adapter.user_role_model.objects,
            "acreate",
            side_effect=IntegrityError,
        ):
            await django_adapter.assign_role_to_user(django_seeded_user.id, "admin")

        # Covers `except IntegrityError: pass` in grant_permission_to_role
        with patch.object(
            django_adapter.role_permission_model.objects,
            "acreate",
            side_effect=IntegrityError,
        ):
            await django_adapter.grant_permission_to_role("admin", "read:users")
