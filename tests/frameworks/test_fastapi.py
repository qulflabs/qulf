from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.fastapi import serve_qulf


def test_fastapi_auth_flow(memory_db):
    auth = Qulf(db=memory_db)
    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    res = client.post(
        "/sign-up",
        json={
            "name": "API User",
            "email": "api@test.com",
            "username": "api_u",
            "password": "pass",
            "password_confirmation": "pass",
        },
    )
    assert res.status_code == 200

    bad_res = client.post(
        "/sign-up",
        json={
            "name": "API User",
            "email": "api@test.com",
            "username": "api_u2",
            "password": "pass",
            "password_confirmation": "pass",
        },
    )
    assert bad_res.status_code == 400

    res = client.post("/sign-in", json={"email": "api@test.com", "password": "pass"})
    assert res.status_code == 200
    assert "qulf_session" in res.cookies

    bad_res2 = client.post(
        "/sign-in", json={"email": "api@test.com", "password": "wrong"}
    )
    assert bad_res2.status_code == 400

    client.cookies.set(
        auth.config.secret_key, str(res.cookies.get(auth.config.secret_key))
    )

    res = client.post("/sign-out")

    assert res.status_code == 200
    assert not res.cookies.get(auth.config.secret_key)


def test_fastapi_sign_out_no_cookie(memory_db):
    auth = Qulf(db=memory_db)
    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    res = client.post("/sign-out")
    assert res.status_code == 200


def test_fastapi_account_management_routes(memory_db):
    auth = Qulf(db=memory_db)
    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    # Sad Paths
    assert (
        client.post("/forgot-password", json={"email": "bad@email.com"}).status_code
        == 400
    )
    assert (
        client.post(
            "/reset-password", json={"token": "bad", "new_password": "p"}
        ).status_code
        == 400
    )
    assert client.post("/verify-email", json={"token": "bad"}).status_code == 400
    assert (
        client.post(
            "/change-password", json={"old_password": "o", "new_password": "p"}
        ).status_code
        == 401
    )
    assert client.delete("/account").status_code == 401

    # Happy Paths
    from unittest.mock import AsyncMock

    auth.reset_password = AsyncMock()
    auth.verify_email = AsyncMock()
    auth.change_password = AsyncMock()
    auth.delete_account = AsyncMock()

    client.post(
        "/sign-up",
        json={
            "name": "A",
            "email": "a@a.com",
            "username": "a",
            "password": "p",
            "password_confirmation": "p",
        },
    )
    res = client.post("/sign-in", json={"email": "a@a.com", "password": "p"})
    cookie = res.cookies.get(auth.config.cookies.name)
    client.cookies.set(auth.config.cookies.name, cookie)

    assert (
        client.post(
            "/reset-password", json={"token": "good", "new_password": "p"}
        ).status_code
        == 200
    )
    assert client.post("/verify-email", json={"token": "good"}).status_code == 200
    assert (
        client.post(
            "/change-password", json={"old_password": "p", "new_password": "new"}
        ).status_code
        == 200
    )
    assert client.delete("/account").status_code == 200


def test_fastapi_core_exceptions(memory_db):
    auth = Qulf(db=memory_db)
    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    # Mock core methods to throw QulfExceptions
    from unittest.mock import AsyncMock

    auth.reset_password = AsyncMock(side_effect=QulfException("Core Reset Error"))
    auth.verify_email = AsyncMock(side_effect=QulfException("Core Verify Error"))
    auth.change_password = AsyncMock(side_effect=QulfException("Core Change Error"))
    auth.delete_account = AsyncMock(side_effect=QulfException("Core Delete Error"))

    # Bypass auth helper for authenticated routes
    client.cookies.set(auth.config.cookies.name, "fake-token")
    auth.validate_session = AsyncMock(return_value=(MagicMock(), MagicMock(id="user1")))

    assert (
        client.post(
            "/reset-password", json={"token": "good", "new_password": "p"}
        ).status_code
        == 400
    )
    assert client.post("/verify-email", json={"token": "good"}).status_code == 400
    assert (
        client.post(
            "/change-password", json={"old_password": "p", "new_password": "new"}
        ).status_code
        == 400
    )
    assert client.delete("/account").status_code == 400


def test_fastapi_sign_up_sign_in_exceptions(memory_db):
    auth = Qulf(db=memory_db)
    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    from unittest.mock import AsyncMock

    auth.sign_up = AsyncMock(side_effect=QulfException("Sign up error"))
    auth.sign_in = AsyncMock(side_effect=QulfException("Sign in error"))

    assert (
        client.post(
            "/sign-up",
            json={
                "name": "A",
                "email": "a@a.com",
                "username": "a",
                "password": "p",
                "password_confirmation": "p",
            },
        ).status_code
        == 400
    )
    assert (
        client.post("/sign-in", json={"email": "a@a.com", "password": "p"}).status_code
        == 400
    )


@pytest.mark.asyncio
async def test_fastapi_rbac_enforcement():
    from datetime import datetime, timezone

    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from qulf.config import QulfConfig
    from qulf.core import Qulf
    from qulf.frameworks.fastapi import RequiresPermission, RequiresRole, serve_qulf
    from qulf.plugins.base import QulfPlugin
    from qulf.routing import HttpMethod, QulfRequest, QulfResponse, QulfRoute
    from qulf.types import User

    # 1. Mock the Core Qulf Engine
    auth_mock = MagicMock(spec=Qulf)
    auth_mock.config = QulfConfig(secret_key="test_secret_key_needs_to_be_long_enough")
    auth_mock.get_session_from_cookies = AsyncMock()
    auth_mock.has_role = AsyncMock()
    auth_mock.has_permission = AsyncMock()

    dummy_user = User(
        id="123",
        email="test@example.com",
        name="Test User",
        username="testuser",
        created_at=datetime.now(timezone.utc),
    )

    # 2. Create a Mock Plugin to test `serve_qulf` dynamic route protection
    class MockRBACPlugin(QulfPlugin):
        name = "mock_rbac"

        def get_routes(self) -> list[QulfRoute]:
            async def handler(req: QulfRequest) -> QulfResponse:
                return QulfResponse(status_code=200, body={"ok": True})

            return [
                QulfRoute(
                    path="/plugin-role",
                    methods=[HttpMethod.GET],
                    handler=handler,
                    require_roles=["admin"],
                ),
                QulfRoute(
                    path="/plugin-perm",
                    methods=[HttpMethod.GET],
                    handler=handler,
                    require_permissions=["write:docs"],
                ),
            ]

    auth_mock.plugins = {"mock": MockRBACPlugin()}

    # 3. Bootstrap FastAPI App & test native Dependencies (`Depends`)
    app = FastAPI()
    app.include_router(serve_qulf(auth_mock))

    @app.get("/dep-roles-all")
    def roles_all_route(
        user: User = Depends(RequiresRole(auth_mock, ["admin", "editor"], mode="all")),
    ):
        return {"ok": True}

    @app.get("/dep-roles-any")
    def roles_any_route(
        user: User = Depends(RequiresRole(auth_mock, ["admin", "editor"], mode="any")),
    ):
        return {"ok": True}

    @app.get("/dep-perms-all")
    def perms_all_route(
        user: User = Depends(
            RequiresPermission(auth_mock, ["read", "write"], mode="all")
        ),
    ):
        return {"ok": True}

    @app.get("/dep-perms-any")
    def perms_any_route(
        user: User = Depends(
            RequiresPermission(auth_mock, ["read", "write"], mode="any")
        ),
    ):
        return {"ok": True}

    client = TestClient(app)

    # ---------------------------------------------------------
    # PART A: Test Plugin Route Protection
    # ---------------------------------------------------------

    # Unauthenticated -> 401
    auth_mock.get_session_from_cookies.return_value = None
    assert client.get("/plugin-role").status_code == 401
    assert client.get("/plugin-perm").status_code == 401

    # Authenticated, but missing role/permission -> 403
    auth_mock.get_session_from_cookies.return_value = ("fake_session", dummy_user)
    auth_mock.has_role.return_value = False
    auth_mock.has_permission.return_value = False

    assert client.get("/plugin-role").status_code == 403
    assert client.get("/plugin-perm").status_code == 403

    # Authenticated, has role/permission -> 200
    auth_mock.has_role.return_value = True
    auth_mock.has_permission.return_value = True

    assert client.get("/plugin-role").status_code == 200
    assert client.get("/plugin-perm").status_code == 200

    # ---------------------------------------------------------
    # PART B: Test Dependency Protection
    # ---------------------------------------------------------

    # 1. ROLES (mode="all")
    auth_mock.has_role.side_effect = lambda user, role: role == "admin"
    assert client.get("/dep-roles-all").status_code == 403

    auth_mock.has_role.side_effect = lambda user, role: True
    assert client.get("/dep-roles-all").status_code == 200

    # 2. ROLES (mode="any")
    auth_mock.has_role.side_effect = lambda user, role: False
    assert client.get("/dep-roles-any").status_code == 403

    auth_mock.has_role.side_effect = lambda user, role: role == "editor"
    assert client.get("/dep-roles-any").status_code == 200

    # 3. PERMISSIONS (mode="all")
    auth_mock.has_permission.side_effect = lambda user, perm: perm == "read"
    assert client.get("/dep-perms-all").status_code == 403

    auth_mock.has_permission.side_effect = lambda user, perm: True
    assert client.get("/dep-perms-all").status_code == 200

    # 4. PERMISSIONS (mode="any")
    auth_mock.has_permission.side_effect = lambda user, perm: False
    assert client.get("/dep-perms-any").status_code == 403

    auth_mock.has_permission.side_effect = lambda user, perm: perm == "write"
    assert client.get("/dep-perms-any").status_code == 200

    # 5. Dependency Unauthenticated Fallback -> 401
    auth_mock.get_session_from_cookies.return_value = None
    assert client.get("/dep-roles-all").status_code == 401
    assert client.get("/dep-perms-all").status_code == 401
