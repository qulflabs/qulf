import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from litestar import Litestar, get
from litestar.di import Provide
from litestar.testing import TestClient as LitestarTestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.frameworks.fastapi import (
    RequiresPermission as FastApiRequiresPermission,
)
from qulf.frameworks.fastapi import (
    RequiresRole as FastApiRequiresRole,
)
from qulf.frameworks.litestar import (
    RequiresPermission as LitestarRequiresPermission,
)
from qulf.frameworks.litestar import (
    RequiresRole as LitestarRequiresRole,
)
from qulf.types import User, UserCreate


@pytest.fixture
def test_config() -> QulfConfig:
    return QulfConfig(secret_key="super_secret_test_key_that_is_at_least_32_bytes_long")


@pytest.mark.asyncio
async def test_core_rbac_management(memory_db, test_config):
    """Test core creation, assignment, and Qulf engine checks."""
    auth = Qulf(db=memory_db, config=test_config)

    # 1. Setup RBAC Data
    await auth.db.create_role("admin", "Administrator")
    await auth.db.create_role("editor", "Content Editor")
    await auth.db.create_permission("delete_post")
    await auth.db.create_permission("write_post")

    await auth.db.grant_permission_to_role("admin", "delete_post")
    await auth.db.grant_permission_to_role("admin", "write_post")
    await auth.db.grant_permission_to_role("editor", "write_post")

    # 2. Setup User
    user = await auth.sign_up(
        UserCreate(
            email="rbac@test.com",
            password="password123",
            password_confirmation="password123",
            name="RBAC Tester",
            username="rbactester",
        )
    )

    await auth.db.assign_role_to_user(user.id, "editor")

    assert await auth.has_role(user, "editor") is True
    assert await auth.has_role(user, "admin") is False
    assert await auth.has_permission(user, "write_post") is True
    assert await auth.has_permission(user, "delete_post") is False

    # 4. Remove Role & Re-test
    await auth.db.remove_role_from_user(user.id, "editor")

    user.roles = None
    user.permissions = None

    # since invalidating the cache means the test will
    # return False even if `remove_role_from_user` didn't work
    fresh_user = await auth.db.get_user_by_id(user.id)
    assert fresh_user
    assert await auth.has_role(fresh_user, "editor") is False
    assert await auth.has_permission(fresh_user, "write_post") is False


@pytest.mark.asyncio
async def test_rbac_edge_cases(memory_db, test_config):
    """Ensure invalid RBAC actions raise appropriate errors."""
    auth = Qulf(db=memory_db, config=test_config)
    await auth.db.create_role("real_role")
    await auth.db.create_permission("real_perm")

    with pytest.raises(ValueError, match="does not exist"):
        await auth.db.assign_role_to_user("123", "ghost_role")

    with pytest.raises(ValueError, match="does not exist"):
        await auth.db.grant_permission_to_role("ghost_role", "real_perm")

    with pytest.raises(ValueError, match="does not exist"):
        await auth.db.grant_permission_to_role("real_role", "ghost_perm")


@pytest.mark.asyncio
async def test_fastapi_rbac_dependencies(memory_db, test_config):
    """Test the native FastAPI Depends() classes."""
    auth = Qulf(db=memory_db, config=test_config)

    # Setup DB
    await auth.db.create_role("admin")
    await auth.db.create_role("manager")
    await auth.db.create_permission("read_reports")

    await auth.db.grant_permission_to_role("admin", "read_reports")

    # Setup User & Session
    user = await auth.sign_up(
        UserCreate(
            email="fastapi@test.com",
            password="p",
            password_confirmation="p",
            name="F",
            username="f",
        )
    )
    await auth.db.assign_role_to_user(user.id, "manager")
    session = await auth.create_session(user)

    # Build FastAPI App
    app = FastAPI()

    @app.get("/admin-only", dependencies=[Depends(FastApiRequiresRole(auth, "admin"))])
    def admin_only():
        return {"msg": "ok"}

    @app.get(
        "/any-role",
        dependencies=[
            Depends(FastApiRequiresRole(auth, ["admin", "manager"], mode="any"))
        ],
    )
    def any_role():
        return {"msg": "ok"}

    @app.get(
        "/reports",
        dependencies=[Depends(FastApiRequiresPermission(auth, "read_reports"))],
    )
    def reports():
        return {"msg": "ok"}

    client = TestClient(app)

    # 1. Unauthenticated
    assert client.get("/admin-only").status_code == 401

    # 2. Authenticated but Unauthorized (Has 'manager', needs 'admin')
    client.cookies.set(test_config.cookies.name, session.token)
    assert client.get("/admin-only").status_code == 403
    assert client.get("/reports").status_code == 403

    # 3. Authenticated & Authorized ('manager' satisfies 'any' condition)
    assert client.get("/any-role").status_code == 200


@pytest.mark.asyncio
async def test_litestar_rbac_dependencies(memory_db, test_config):
    """Test the native Litestar Provide() injection classes."""
    auth = Qulf(db=memory_db, config=test_config)

    await auth.db.create_role("admin")
    await auth.db.create_permission("sudo")
    await auth.db.grant_permission_to_role("admin", "sudo")

    user = await auth.sign_up(
        UserCreate(
            email="litestar@test.com",
            password="p",
            password_confirmation="p",
            name="L",
            username="l",
        )
    )
    await auth.db.assign_role_to_user(user.id, "admin")
    session = await auth.create_session(user)

    @get("/admin", dependencies={"u": Provide(LitestarRequiresRole(auth, "admin"))})
    async def admin_route(u: User) -> dict:
        return {"msg": "ok"}

    @get("/sudo", dependencies={"u": Provide(LitestarRequiresPermission(auth, "sudo"))})
    async def sudo_route(u: User) -> dict:
        return {"msg": "ok"}

    app = Litestar(route_handlers=[admin_route, sudo_route])

    with LitestarTestClient(app=app) as client:
        # Unauthenticated
        assert client.get("/admin").status_code == 401

        # Authenticated & Authorized
        client.cookies.set(test_config.cookies.name, session.token)
        assert client.get("/admin").status_code == 200
        assert client.get("/sudo").status_code == 200
