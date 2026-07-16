# tests/test_totp.py
import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import Requires2FAError
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.totp import TOTPPlugin
from qulf.types import UserCreate


@pytest.fixture
def totp_app(memory_db):
    plugin = TOTPPlugin()
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
    )
    auth = Qulf(db=memory_db, config=config, plugins=[plugin])

    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)
    return app, auth, client


@pytest.mark.asyncio
async def test_totp_full_flow(totp_app):
    app, auth, client = totp_app

    # Create User & Standard Login
    await auth.sign_up(
        UserCreate(
            name="T",
            email="t@t.com",
            username="t",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("t@t.com", "p")

    client.cookies.set("qulf_session", session.token)

    # Setup 2FA
    res_setup = client.post("/2fa/setup")
    assert res_setup.status_code == 200
    assert "otpauth://" in res_setup.json()["uri"]

    user = await auth.db.get_user_by_email("t@t.com")
    secret = user.model_extra["two_factor_secret"]
    assert secret is not None

    # Enable 2FA (with valid code)
    valid_code = pyotp.TOTP(secret).now()
    res_enable = client.post("/2fa/enable", json={"code": valid_code})
    assert res_enable.status_code == 200

    # Test 2FA Interception (The Lifecycle Hook)
    # They try to log in again with their password...
    with pytest.raises(Requires2FAError) as exc_info:
        await auth.sign_in("t@t.com", "p")

    # Qulf intercepted it and threw the error with the temp_token
    temp_token = str(exc_info.value)

    # Verify 2FA Login
    new_valid_code = pyotp.TOTP(secret).now()
    res_verify = client.post(
        "/2fa/verify_login", json={"temp_token": temp_token, "code": new_valid_code}
    )

    assert res_verify.status_code == 200
    assert "qulf_session" in res_verify.cookies
    assert res_verify.json()["user"]["email"] == "t@t.com"


@pytest.mark.asyncio
async def test_totp_bad_flows(totp_app):
    app, auth, client = totp_app

    await auth.sign_up(
        UserCreate(
            name="B",
            email="b@b.com",
            username="b",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("b@b.com", "p")
    client.cookies.set("qulf_session", session.token)

    # Try enabling without setting up
    res_enable = client.post("/2fa/enable", json={"code": "123456"})
    assert res_enable.status_code == 400
    assert "2FA not set up" in res_enable.json()["detail"]

    # Try setting up without a session
    client.cookies.delete("qulf_session")
    res_setup = client.post("/2fa/setup")
    assert res_setup.status_code == 401

    # Try verifying with bad temp_token
    res_verify = client.post(
        "/2fa/verify_login", json={"temp_token": "garbage", "code": "123456"}
    )
    assert res_verify.status_code == 401
    assert "Invalid or expired token" in res_verify.json()["detail"]
