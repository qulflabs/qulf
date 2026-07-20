from typing import Any

from litestar import Litestar
from litestar.testing import TestClient

from qulf.core import Qulf
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

    # 1. Sign Up Success
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

    # 2. Sign Up Duplicate (Sad Path)
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

    # 3. Sign In Success
    res = client.post("/sign-in", json={"email": "api@test.com", "password": "pass"})
    assert res.status_code == 200  # Litestar defaults POST to 201 Created!
    assert auth.config.cookies.name in res.cookies

    # 4. Sign In Invalid (Sad Path)
    bad_res2 = client.post(
        "/sign-in", json={"email": "api@test.com", "password": "wrong"}
    )
    assert bad_res2.status_code == 400

    # 5. Sign Out
    # Make sure we carry the session cookie over to the sign out request
    client.cookies.set(
        auth.config.cookies.name, str(res.cookies.get(auth.config.cookies.name))
    )

    res = client.post("/sign-out")
    assert res.status_code == 200  # Litestar defaults POST to 201 Created!
    # httpx drops max_age=0 cookies from the jar, so it will evaluate to falsy
    assert not res.cookies.get(auth.config.cookies.name)


def test_litestar_sign_out_no_cookie(memory_db: Any) -> None:
    auth = Qulf(db=memory_db)
    app = Litestar(route_handlers=[serve_qulf(auth)])
    client = TestClient(app)

    res = client.post("/sign-out")
    assert res.status_code == 200  # Litestar defaults POST to 201 Created!


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
