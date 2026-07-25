from typing import Any
from unittest.mock import MagicMock

from litestar import Litestar
from litestar.testing import TestClient

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.litestar import serve_qulf
from qulf.routing import (
    CookieOptions,
    HttpMethod,
    QulfRequest,
    QulfResponse,
    QulfRoute,
)


def test_litestar_auth_flow(memory_db: Any) -> None:
    auth = Qulf(db=memory_db)
    app = Litestar(route_handlers=[serve_qulf(auth)])
    client = TestClient(app)

    # Sign Up Success
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
    assert res.status_code == 201  # Litestar defaults POST to 201 Created!

    # Sign Up Duplicate (Sad Path)
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

    # Sign In Success
    res = client.post("/sign-in", json={"email": "api@test.com", "password": "pass"})
    assert res.status_code == 200  # Litestar defaults POST to 201 Created!
    assert auth.config.cookies.name in res.cookies

    # Sign In Invalid (Sad Path)
    bad_res2 = client.post(
        "/sign-in", json={"email": "api@test.com", "password": "wrong"}
    )
    assert bad_res2.status_code == 400

    # Sign Out
    client.cookies.set(
        auth.config.cookies.name, str(res.cookies.get(auth.config.cookies.name))
    )

    res = client.post("/sign-out")
    assert res.status_code == 200
    # httpx drops max_age=0 cookies from the jar, so it will evaluate to falsy
    assert not res.cookies.get(auth.config.cookies.name)


def test_litestar_sign_out_no_cookie(memory_db: Any) -> None:
    auth = Qulf(db=memory_db)
    app = Litestar(route_handlers=[serve_qulf(auth)])
    client = TestClient(app)

    res = client.post("/sign-out")
    assert res.status_code == 200


def test_plugin_dynamic_routing(memory_db: Any) -> None:
    auth = Qulf(db=memory_db)

    async def dummy_handler(request: QulfRequest) -> QulfResponse:
        return QulfResponse(
            status_code=202,
            body={"echo_body": request.body, "echo_query": request.query_params},
            headers={"X-Custom-Header": "FrameworkAgnostic"},
            set_cookies=[
                CookieOptions(key="plugin_cookie", value="abc", samesite="strict")
            ],
            delete_cookies=["old_cookie"],
        )

    class DummyPlugin:
        def get_routes(self) -> list[QulfRoute]:
            return [
                QulfRoute(
                    path="/my-plugin",
                    methods=[HttpMethod.POST],
                    handler=dummy_handler,
                )
            ]

    # Inject our dummy plugin directly into the auth instance
    auth.plugins = {"dummy": DummyPlugin()}

    app = Litestar(route_handlers=[serve_qulf(auth)])

    with TestClient(app=app) as client:
        # Happy Path
        res = client.post("/my-plugin?test=123", json={"hello": "world"})
        assert res.status_code == 202
        assert res.json() == {
            "echo_body": {"hello": "world"},
            "echo_query": {"test": "123"},
        }
        assert res.headers["x-custom-header"] == "FrameworkAgnostic"
        assert res.cookies.get("plugin_cookie") == "abc"
        assert not res.cookies.get("old_cookie")

        # Sad Path: Testing JSON parsing swallow (empty body on POST)
        res_bad = client.post(
            "/my-plugin",
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        )
        assert res_bad.status_code == 202
        assert res_bad.json()["echo_body"] == {}


def test_litestar_account_management_routes(memory_db):
    auth = Qulf(db=memory_db)
    app = Litestar(route_handlers=[serve_qulf(auth)])
    client = TestClient(app)

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
    assert cookie is not None
    client.cookies.set(auth.config.cookies.name, cookie)

    assert (
        client.post(
            "/reset-password", json={"token": "good", "new_password": "p"}
        ).status_code
        == 201
    )
    assert client.post("/verify-email", json={"token": "good"}).status_code == 201
    assert (
        client.post(
            "/change-password", json={"old_password": "p", "new_password": "new"}
        ).status_code
        == 201
    )
    assert client.delete("/account").status_code == 200


def test_litestar_core_exceptions(memory_db):
    auth = Qulf(db=memory_db)
    app = Litestar(route_handlers=[serve_qulf(auth)])
    client = TestClient(app)

    from unittest.mock import AsyncMock

    auth.reset_password = AsyncMock(side_effect=QulfException("Core Reset Error"))
    auth.verify_email = AsyncMock(side_effect=QulfException("Core Verify Error"))
    auth.change_password = AsyncMock(side_effect=QulfException("Core Change Error"))
    auth.delete_account = AsyncMock(side_effect=QulfException("Core Delete Error"))

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


def test_litestar_sign_up_sign_in_exceptions(memory_db):
    auth = Qulf(db=memory_db)
    app = Litestar(route_handlers=[serve_qulf(auth)])
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
