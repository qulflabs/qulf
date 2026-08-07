import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from litestar import Litestar, get
from litestar.di import NamedDependency, Provide
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


class TestCoreRBAC:
    @pytest.mark.asyncio
    async def test_core_rbac_management(self, memory_db, test_config):
        auth = Qulf(db=memory_db, config=test_config)

        await auth.db.create_role("admin", "Administrator")
        await auth.db.create_role("editor", "Content Editor")
        await auth.db.create_permission("delete_post")
        await auth.db.create_permission("write_post")

        await auth.db.grant_permission_to_role("admin", "delete_post")
        await auth.db.grant_permission_to_role("admin", "write_post")
        await auth.db.grant_permission_to_role("editor", "write_post")

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

        await auth.db.remove_role_from_user(user.id, "editor")

        user.roles = None
        user.permissions = None

        # Invalidating the cache means the test will return False
        # even if `remove_role_from_user` didn't work.
        fresh_user = await auth.db.get_user_by_id(user.id)
        assert fresh_user
        assert await auth.has_role(fresh_user, "editor") is False
        assert await auth.has_permission(fresh_user, "write_post") is False

    @pytest.mark.asyncio
    async def test_rbac_edge_cases(self, memory_db, test_config):
        auth = Qulf(db=memory_db, config=test_config)
        await auth.db.create_role("real_role")
        await auth.db.create_permission("real_perm")

        with pytest.raises(ValueError, match="does not exist"):
            await auth.db.assign_role_to_user("123", "ghost_role")

        with pytest.raises(ValueError, match="does not exist"):
            await auth.db.grant_permission_to_role("ghost_role", "real_perm")

        with pytest.raises(ValueError, match="does not exist"):
            await auth.db.grant_permission_to_role("real_role", "ghost_perm")


class TestFastAPIRBACDependencies:
    @pytest.fixture
    def app(self, auth_mock):
        fastapi_app = FastAPI()

        @fastapi_app.get(
            "/admin-only",
            dependencies=[Depends(FastApiRequiresRole(auth_mock, "admin"))],
        )
        def admin_only():
            return {"msg": "ok"}

        @fastapi_app.get(
            "/any-role",
            dependencies=[
                Depends(
                    FastApiRequiresRole(auth_mock, ["admin", "manager"], mode="any")
                )
            ],
        )
        def any_role():
            return {"msg": "ok"}

        @fastapi_app.get(
            "/reports",
            dependencies=[
                Depends(FastApiRequiresPermission(auth_mock, "read_reports"))
            ],
        )
        def reports():
            return {"msg": "ok"}

        return fastapi_app

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_fastapi_rbac_dependencies(
        self, client, auth_mock, dummy_user, dummy_session
    ):
        # 1. Unauthenticated
        auth_mock.get_session_from_cookies.return_value = None
        assert client.get("/admin-only").status_code == 401

        # 2. Authenticated but Unauthorized
        auth_mock.get_session_from_cookies.return_value = (dummy_session, dummy_user)
        client.cookies.set(auth_mock.config.cookies.name, dummy_session.token)

        auth_mock.has_role.return_value = False
        auth_mock.has_permission.return_value = False

        assert client.get("/admin-only").status_code == 403
        assert client.get("/reports").status_code == 403

        # 3. Authenticated & Authorized
        auth_mock.has_role.return_value = True
        auth_mock.has_permission.return_value = True

        assert client.get("/any-role").status_code == 200
        assert client.get("/admin-only").status_code == 200
        assert client.get("/reports").status_code == 200


class TestLitestarRBACDependencies:
    @pytest.fixture
    def app(self, auth_mock):
        @get(
            "/admin",
            dependencies={"u": Provide(LitestarRequiresRole(auth_mock, "admin"))},
        )
        async def admin_route(u: NamedDependency[User]) -> dict:
            return {"msg": "ok"}

        @get(
            "/sudo",
            dependencies={"u": Provide(LitestarRequiresPermission(auth_mock, "sudo"))},
        )
        async def sudo_route(u: NamedDependency[User]) -> dict:
            return {"msg": "ok"}

        return Litestar(route_handlers=[admin_route, sudo_route])

    @pytest.fixture
    def client(self, app):
        with LitestarTestClient(app=app) as test_client:
            yield test_client

    def test_litestar_rbac_dependencies(
        self, client, auth_mock, dummy_user, dummy_session
    ):
        # 1. Unauthenticated
        auth_mock.get_session_from_cookies.return_value = None
        assert client.get("/admin").status_code == 401

        # 2. Authenticated & Authorized
        auth_mock.get_session_from_cookies.return_value = (dummy_session, dummy_user)
        client.cookies.set(auth_mock.config.cookies.name, dummy_session.token)

        auth_mock.has_role.return_value = True
        auth_mock.has_permission.return_value = True

        assert client.get("/admin").status_code == 200
        assert client.get("/sudo").status_code == 200

        # 3. Authenticated but Unauthorized
        auth_mock.has_role.return_value = False
        auth_mock.has_permission.return_value = False

        assert client.get("/admin").status_code == 403
        assert client.get("/sudo").status_code == 403
