from unittest.mock import MagicMock

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
