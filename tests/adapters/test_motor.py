from datetime import datetime, timedelta, timezone

import pytest

from qulf.adapters.motor import MotorAdapter
from qulf.config import DeletionStrategy
from qulf.types import AccountCreate, UserCreate


@pytest.mark.asyncio
async def test_motor_adapter_flow(motor_adapter: MotorAdapter):
    adapter = motor_adapter

    user_data = UserCreate(
        name="Mongo User",
        email="mongo@test.com",
        username="mongou",
        password="p",
        password_confirmation="p",
    )

    user = await adapter.create_user(user_data, "fake_hashed_password")
    assert user.email == "mongo@test.com"
    assert user.id  # Should be a non-empty string (ObjectId)

    fetched_by_email = await adapter.get_user_by_email("mongo@test.com")
    assert fetched_by_email is not None
    assert fetched_by_email.hashed_password == "fake_hashed_password"

    fetched_by_id = await adapter.get_user_by_id(user.id)
    assert fetched_by_id is not None
    assert fetched_by_id.email == "mongo@test.com"

    # Non-existent lookups
    assert await adapter.get_user_by_email("nobody@test.com") is None
    assert await adapter.get_user_by_id("000000000000000000000000") is None
    # Invalid ObjectId string should return None gracefully
    assert await adapter.get_user_by_id("not-a-valid-id") is None

    expires = datetime.now(timezone.utc) + timedelta(days=1)
    session = await adapter.create_session(user.id, "tok123", expires)
    assert session.token == "tok123"
    assert str(session.user_id) == str(user.id)

    fetched_sess = await adapter.get_session("tok123")
    assert fetched_sess is not None
    assert await adapter.get_session("bad_token") is None

    deleted = await adapter.delete_session("tok123")
    assert deleted is True
    assert await adapter.get_session("tok123") is None

    # Deleting an already-deleted token returns False
    assert await adapter.delete_session("tok123") is False


@pytest.mark.asyncio
async def test_motor_session_validation(motor_adapter: MotorAdapter):
    from qulf.config import QulfConfig
    from qulf.core import Qulf

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
async def test_motor_update_user(motor_adapter: MotorAdapter):
    adapter = motor_adapter

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
    assert updated.updated_at is not None

    # Non-existent user should raise ValueError
    with pytest.raises(ValueError, match="User not found"):
        await adapter.update_user("000000000000000000000000", {"name": "X"})

    # Invalid ObjectId format should also raise ValueError
    with pytest.raises(ValueError, match="User not found"):
        await adapter.update_user("not-valid", {"name": "X"})


@pytest.mark.asyncio
async def test_motor_session_management(motor_adapter: MotorAdapter):
    adapter = motor_adapter

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
async def test_motor_account_management(motor_adapter: MotorAdapter):
    adapter = motor_adapter

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
async def test_motor_hard_deletes_and_misses(motor_adapter: MotorAdapter):
    await motor_adapter.delete_user("fake-id", DeletionStrategy.HARD)
    assert (
        await motor_adapter.get_user_by_email_with_password("nobody@nowhere.com")
        is None
    )
    assert await motor_adapter.get_user_by_id_with_password("fake-id") is None


@pytest.mark.asyncio
async def test_motor_soft_deletes_and_gets(motor_adapter: MotorAdapter):
    from qulf.types import UserCreate

    user = await motor_adapter.create_user(
        UserCreate(
            name="a",
            email="soft@test.com",
            username="softu",
            password="p",
            password_confirmation="p",
        ),
        "hashed",
    )

    u1 = await motor_adapter.get_user_by_id_with_password(str(user.id))
    assert u1 is not None and u1.hashed_password == "hashed"

    u2 = await motor_adapter.get_user_by_email_with_password("soft@test.com")
    assert u2 is not None and u2.hashed_password == "hashed"

    await motor_adapter.delete_user(str(user.id), DeletionStrategy.SOFT)
    deleted_user = await motor_adapter.get_user_by_id(str(user.id))
    assert deleted_user is not None
    assert deleted_user.deleted_at is not None


@pytest.mark.asyncio
async def test_motor_rbac_management(motor_adapter: MotorAdapter):
    adapter = motor_adapter

    # 1. PERMISSIONS
    perm_read = await adapter.create_permission("read:users", "Read users")
    _ = await adapter.create_permission("write:users", "Write users")

    assert perm_read.name == "read:users"

    fetched_perm = await adapter.get_permission_by_name("read:users")
    assert fetched_perm is not None
    assert fetched_perm.name == "read:users"

    missing_perm = await adapter.get_permission_by_name("non_existent")
    assert missing_perm is None

    # 2. ROLES
    role_admin = await adapter.create_role("admin", "Admin role")
    _ = await adapter.create_role("user", "User role")

    assert role_admin.name == "admin"

    fetched_role = await adapter.get_role_by_name("admin")
    assert fetched_role is not None
    assert fetched_role.name == "admin"

    missing_role = await adapter.get_role_by_name("non_existent")
    assert missing_role is None

    # 3. GRANT PERMISSIONS TO ROLES
    await adapter.grant_permission_to_role("admin", "read:users")
    await adapter.grant_permission_to_role("admin", "write:users")
    await adapter.grant_permission_to_role("user", "read:users")

    with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
        await adapter.grant_permission_to_role("fake_role", "read:users")

    with pytest.raises(ValueError, match="Permission 'fake_perm' does not exist."):
        await adapter.grant_permission_to_role("admin", "fake_perm")

    # 4. USER CREATION
    user = await adapter.create_user(
        UserCreate(
            name="RBAC User",
            email="rbac@test.com",
            username="rbacuser",
            password="p",
            password_confirmation="p",
        ),
        "hash",
    )

    # Check edge cases (new user has no roles/permissions yet)
    assert await adapter.get_user_roles(user.id) == []
    assert await adapter.get_user_permissions(user.id) == []

    # 5. ASSIGN ROLES TO USER
    await adapter.assign_role_to_user(user.id, "admin")
    await adapter.assign_role_to_user(user.id, "user")

    with pytest.raises(ValueError, match="Role 'fake_role' does not exist."):
        await adapter.assign_role_to_user(user.id, "fake_role")

    # 6. FETCH USER ROLES & PERMISSIONS
    roles = await adapter.get_user_roles(user.id)
    role_names = [r.name for r in roles]
    assert "admin" in role_names
    assert "user" in role_names
    assert len(roles) == 2

    permissions = await adapter.get_user_permissions(user.id)
    perm_names = [p.name for p in permissions]
    assert "read:users" in perm_names
    assert "write:users" in perm_names
    assert len(permissions) == 2

    # 7. REMOVE ROLE FROM USER
    await adapter.remove_role_from_user(user.id, "admin")

    updated_roles = await adapter.get_user_roles(user.id)
    updated_role_names = [r.name for r in updated_roles]
    assert "admin" not in updated_role_names
    assert "user" in updated_role_names

    updated_permissions = await adapter.get_user_permissions(user.id)
    updated_perm_names = [p.name for p in updated_permissions]
    assert "write:users" not in updated_perm_names
    assert "read:users" in updated_perm_names

    await adapter.create_role("empty_role", "A role with no permissions")

    empty_user = await adapter.create_user(
        UserCreate(
            name="Empty User",
            email="empty@test.com",
            username="emptyuser",
            password="p",
            password_confirmation="p",
        ),
        "hash",
    )

    await adapter.assign_role_to_user(empty_user.id, "empty_role")

    # This will hit the `if not perm_names: return []` branch
    empty_permissions = await adapter.get_user_permissions(empty_user.id)
    assert empty_permissions == []
