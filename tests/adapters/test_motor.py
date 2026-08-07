from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.motor import MotorAdapter
from qulf.config import DeletionStrategy, QulfConfig
from qulf.core import Qulf
from qulf.types import AccountCreate, UserCreate


@pytest.fixture
async def seeded_user(motor_adapter):
    return await motor_adapter.create_user(
        UserCreate(
            name="Seeded User",
            email="seeded@test.com",
            username="seededuser",
            password="p",
            password_confirmation="p",
        ),
        "hashed",
    )


@pytest.fixture
async def motor_seeded_rbac(motor_adapter):
    await motor_adapter.create_permission("read:users", "Read users")
    await motor_adapter.create_permission("write:users", "Write users")
    await motor_adapter.create_role("admin", "Admin role")
    await motor_adapter.create_role("user", "User role")
    await motor_adapter.grant_permission_to_role("admin", "read:users")
    await motor_adapter.grant_permission_to_role("admin", "write:users")
    await motor_adapter.grant_permission_to_role("user", "read:users")


@pytest.mark.asyncio
class TestMotorFlows:
    async def test_motor_adapter_flow(self, motor_adapter: MotorAdapter) -> None:
        user_data = UserCreate(
            name="Mongo User",
            email="mongo@test.com",
            username="mongou",
            password="p",
            password_confirmation="p",
        )

        user = await motor_adapter.create_user(user_data, "fake_hashed_password")
        assert user.email == "mongo@test.com"
        assert user.id is not None

        fetched_by_email = await motor_adapter.get_user_by_email("mongo@test.com")
        assert fetched_by_email is not None
        assert fetched_by_email.hashed_password == "fake_hashed_password"

        fetched_by_id = await motor_adapter.get_user_by_id(user.id)
        assert fetched_by_id is not None
        assert fetched_by_id.email == "mongo@test.com"

        assert await motor_adapter.get_user_by_email("nobody@test.com") is None
        assert await motor_adapter.get_user_by_id("000000000000000000000000") is None
        assert await motor_adapter.get_user_by_id("not-a-valid-id") is None

        expires = datetime.now(timezone.utc) + timedelta(days=1)
        session = await motor_adapter.create_session(user.id, "tok123", expires)
        assert session.token == "tok123"
        assert str(session.user_id) == str(user.id)

        fetched_sess = await motor_adapter.get_session("tok123")
        assert fetched_sess is not None
        assert await motor_adapter.get_session("bad_token") is None

        deleted = await motor_adapter.delete_session("tok123")
        assert deleted is True
        assert await motor_adapter.get_session("tok123") is None

        assert await motor_adapter.delete_session("tok123") is False

    async def test_motor_session_validation(self, motor_adapter: MotorAdapter) -> None:
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
        )
        auth = Qulf(db=motor_adapter, config=config)

        user_data = UserCreate(
            name="Mongo Auth User",
            email="mongoauth@test.com",
            username="mongoauthu",
            password="p",
            password_confirmation="p",
        )
        await auth.sign_up(user_data)
        session = await auth.sign_in("mongoauth@test.com", "p")

        result = await auth.validate_session(session.token)
        assert result is not None

        session_obj, user = result
        assert user.email == "mongoauth@test.com"
        assert session_obj is not None


@pytest.mark.asyncio
class TestMotorUpdates:
    async def test_motor_update_user(self, motor_adapter: MotorAdapter) -> None:
        user = await motor_adapter.create_user(
            UserCreate(
                name="Update Me",
                email="update@test.com",
                username="updater",
                password="p",
                password_confirmation="p",
            ),
            "hash",
        )

        updated = await motor_adapter.update_user(user.id, {"name": "Updated Name"})
        assert updated.name == "Updated Name"
        assert updated.updated_at is not None

        with pytest.raises(ValueError, match="User not found"):
            await motor_adapter.update_user("000000000000000000000000", {"name": "X"})

        with pytest.raises(ValueError, match="User not found"):
            await motor_adapter.update_user("not-valid", {"name": "X"})


@pytest.mark.asyncio
class TestMotorSessionManagement:
    async def test_motor_session_management(self, motor_adapter: MotorAdapter) -> None:
        user = await motor_adapter.create_user(
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

        s1 = await motor_adapter.create_session(user.id, "sess-tok-1", expires)
        s2 = await motor_adapter.create_session(user.id, "sess-tok-2", expires)
        await motor_adapter.create_session(user.id, "sess-tok-3", expires)

        all_sessions = await motor_adapter.get_user_sessions(user.id)
        assert len(all_sessions) == 3

        deleted = await motor_adapter.delete_user_session(user.id, s1.token)
        assert deleted is True

        remaining = await motor_adapter.get_user_sessions(user.id)
        assert len(remaining) == 2

        assert await motor_adapter.delete_user_session(user.id, "ghost-token") is False

        deleted_tokens = await motor_adapter.delete_all_user_sessions(
            user.id, except_token=s2.token
        )
        assert len(deleted_tokens) == 1

        still_alive = await motor_adapter.get_user_sessions(user.id)
        assert len(still_alive) == 1
        assert still_alive[0].token == s2.token

        await motor_adapter.delete_all_user_sessions(user.id)
        assert await motor_adapter.get_user_sessions(user.id) == []


class TestMotorAccountManagement:
    @pytest.mark.asyncio
    async def test_create_and_fetch_account(self, motor_adapter, seeded_user):
        account_data = AccountCreate(
            user_id=seeded_user.id,
            provider_id="github",
            account_id="gh-12345",
            access_token="access_abc",
            refresh_token=None,
            expires_at=None,
            scope="read:user",
            id_token=None,
        )

        account = await motor_adapter.create_account(account_data)

        assert account.provider_id == "github"
        assert account.account_id == "gh-12345"

        fetched = await motor_adapter.get_account_by_provider("github", "gh-12345")
        assert fetched is not None
        assert fetched.scope == "read:user"

        assert await motor_adapter.get_account_by_provider("github", "unknown") is None
        assert (
            await motor_adapter.get_account_by_provider("unknown", "gh-12345") is None
        )


class TestMotorUserDeletion:
    @pytest.mark.asyncio
    async def test_hard_deletes_and_misses(self, motor_adapter):
        await motor_adapter.delete_user("fake-id", DeletionStrategy.HARD)

        assert await motor_adapter.get_user_by_email_with_password("a@b.com") is None
        assert await motor_adapter.get_user_by_id_with_password("fake-id") is None

    @pytest.mark.asyncio
    async def test_soft_deletes_and_gets(self, motor_adapter, seeded_user):
        user_id = str(seeded_user.id)

        u1 = await motor_adapter.get_user_by_id_with_password(user_id)
        assert u1 is not None and u1.hashed_password == "hashed"

        u2 = await motor_adapter.get_user_by_email_with_password(seeded_user.email)
        assert u2 is not None and u2.hashed_password == "hashed"

        await motor_adapter.delete_user(user_id, DeletionStrategy.SOFT)

        deleted_user = await motor_adapter.get_user_by_id(user_id)
        assert deleted_user is not None
        assert deleted_user.deleted_at is not None


class TestMotorRBAC:
    @pytest.mark.asyncio
    async def test_permissions_crud(self, motor_adapter):
        perm_read = await motor_adapter.create_permission("read:users", "Read users")
        await motor_adapter.create_permission("write:users", "Write users")

        assert perm_read.name == "read:users"

        fetched_perm = await motor_adapter.get_permission_by_name("read:users")
        assert fetched_perm is not None
        assert fetched_perm.name == "read:users"

        missing_perm = await motor_adapter.get_permission_by_name("non_existent")
        assert missing_perm is None

    @pytest.mark.asyncio
    async def test_roles_crud(self, motor_adapter):
        role_admin = await motor_adapter.create_role("admin", "Admin role")
        await motor_adapter.create_role("user", "User role")

        assert role_admin.name == "admin"

        fetched_role = await motor_adapter.get_role_by_name("admin")
        assert fetched_role is not None
        assert fetched_role.name == "admin"

        missing_role = await motor_adapter.get_role_by_name("non_existent")
        assert missing_role is None

    @pytest.mark.asyncio
    async def test_grant_permissions_to_roles(self, motor_adapter, motor_seeded_rbac):
        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await motor_adapter.grant_permission_to_role("fake_role", "read:users")

        with pytest.raises(ValueError, match="Permission 'fake_perm' does not exist."):
            await motor_adapter.grant_permission_to_role("admin", "fake_perm")

    @pytest.mark.asyncio
    async def test_user_role_assignment_and_removal(
        self, motor_adapter, seeded_user, motor_seeded_rbac
    ):
        assert await motor_adapter.get_user_roles(seeded_user.id) == []
        assert await motor_adapter.get_user_permissions(seeded_user.id) == []

        await motor_adapter.assign_role_to_user(seeded_user.id, "admin")
        await motor_adapter.assign_role_to_user(seeded_user.id, "user")

        with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
            await motor_adapter.assign_role_to_user(seeded_user.id, "fake_role")

        roles = await motor_adapter.get_user_roles(seeded_user.id)
        role_names = [r.name for r in roles]
        assert "admin" in role_names
        assert "user" in role_names
        assert len(roles) == 2

        permissions = await motor_adapter.get_user_permissions(seeded_user.id)
        perm_names = [p.name for p in permissions]
        assert "read:users" in perm_names
        assert "write:users" in perm_names
        assert len(permissions) == 2

        await motor_adapter.remove_role_from_user(seeded_user.id, "admin")

        updated_roles = await motor_adapter.get_user_roles(seeded_user.id)
        updated_role_names = [r.name for r in updated_roles]
        assert "admin" not in updated_role_names
        assert "user" in updated_role_names

        updated_permissions = await motor_adapter.get_user_permissions(seeded_user.id)
        updated_perm_names = [p.name for p in updated_permissions]
        assert "write:users" not in updated_perm_names
        assert "read:users" in updated_perm_names

    @pytest.mark.asyncio
    async def test_empty_role_yields_no_permissions(self, motor_adapter, seeded_user):
        await motor_adapter.create_role("empty_role", "No permissions mapped")
        await motor_adapter.assign_role_to_user(seeded_user.id, "empty_role")

        empty_permissions = await motor_adapter.get_user_permissions(seeded_user.id)
        assert empty_permissions == []
