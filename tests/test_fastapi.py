from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.core import Qulf
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
