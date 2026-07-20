from datetime import datetime, timedelta, timezone
from unittest.mock import PropertyMock, patch

import jwt
import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import QulfException, Requires2FAError
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


@pytest.mark.asyncio
async def test_totp_enable_edge_cases(totp_app):
    """Covers missed branches in totp_enable: lines 66, 72, 77, 91."""
    app, auth, client = totp_app

    # Setup test user
    user = await auth.sign_up(
        UserCreate(
            name="E",
            email="e@e.com",
            username="e",
            password="p",
            password_confirmation="p",
        )
    )
    session = await auth.sign_in("e@e.com", "p")

    # Line 66: Call enable with no cookies (session_data is None)
    res = client.post("/2fa/enable", json={"code": "123456"})
    assert res.status_code == 401

    # Attach cookies for the remaining tests
    client.cookies.set("qulf_session", session.token)
    client.post("/2fa/setup")  # Generates the secret so we can reach the next lines

    # Line 72: Call enable without "code" in the payload
    res = client.post("/2fa/enable", json={})
    assert res.status_code == 400
    assert "2FA code missing" in res.json()["detail"]

    # Line 91: Call enable with invalid code
    res = client.post("/2fa/enable", json={"code": "000000"})
    assert res.status_code == 401
    assert "Invalid 2FA code" in res.json()["detail"]

    # Line 77: Session is None but user exists.
    # This happens in edge cases where the
    # adapter returns (None, user). We patch to simulate it.
    with patch.object(auth, "get_session_from_cookies", return_value=(None, user)):
        res = client.post("/2fa/enable", json={"code": "123456"})
        assert res.status_code == 400
        assert "Invalid or expired session" in res.json()["detail"]


@pytest.mark.asyncio
async def test_totp_verify_login_edge_cases(totp_app):
    app, auth, client = totp_app

    user = await auth.sign_up(
        UserCreate(
            name="V",
            email="v@v.com",
            username="v",
            password="p",
            password_confirmation="p",
        )
    )

    # Line 106: Missing code
    res = client.post("/2fa/verify_login", json={"temp_token": "token"})
    assert res.status_code == 400
    assert "2FA code missing" in res.json()["detail"]

    # Line 111: Missing temp_token
    res = client.post("/2fa/verify_login", json={"code": "123456"})
    assert res.status_code == 400
    assert "Temporary Auth token missing" in res.json()["detail"]

    # Generate a valid JWT temporary token directly to test deeper conditions
    valid_payload = {
        "sub": user.id,
        "type": "2fa_pending",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    valid_temp_token = jwt.encode(valid_payload, auth.config.secret_key)

    # Line 131: User not found in DB (Simulate by using a fake sub in the token)
    bad_payload = {**valid_payload, "sub": "fake-id"}
    bad_token = jwt.encode(bad_payload, auth.config.secret_key)
    res = client.post(
        "/2fa/verify_login", json={"temp_token": bad_token, "code": "123456"}
    )
    assert res.status_code == 400
    assert "User not found" in res.json()["detail"]

    # Initialize model_extra so we bypass Line 136 and reach Line 141.
    # We do this by setting a known extra column, but leaving the secret empty.
    await auth.db.update_user(user.id, {"two_factor_enabled": False})

    # Line 141: User found, model_extra exists, but secret not setup yet
    res = client.post(
        "/2fa/verify_login", json={"temp_token": valid_temp_token, "code": "123456"}
    )
    assert res.status_code == 401
    assert "not set up" in res.json()["detail"]

    # Now let's manually inject a secret so we can test the remaining lines
    secret = pyotp.random_base32()
    await auth.db.update_user(user.id, {"two_factor_secret": secret})

    # Line 147: Invalid TOTP code
    res = client.post(
        "/2fa/verify_login", json={"temp_token": valid_temp_token, "code": "000000"}
    )
    assert res.status_code == 401
    assert "Invalid 2FA code" in res.json()["detail"]

    # Lines 155-156: valid token, valid code, but create_session fails
    valid_code = pyotp.TOTP(secret).now()
    with patch.object(
        auth, "create_session", side_effect=QulfException("Rate limited")
    ):
        res = client.post(
            "/2fa/verify_login",
            json={"temp_token": valid_temp_token, "code": valid_code},
        )
        assert res.status_code == 400
        assert "Rate limited" in res.json()["detail"]

    # Pydantic Edge Case where model_extra is None.
    # We patch the class's property to simulate model_extra evaluating to None
    with patch.object(
        type(user), "model_extra", new_callable=PropertyMock, return_value=None
    ):
        with patch.object(auth.db, "get_user_by_id", return_value=user):
            res = client.post(
                "/2fa/verify_login",
                json={"temp_token": valid_temp_token, "code": valid_code},
            )
            assert res.status_code == 401
            assert "User not found" in res.json()["detail"]
