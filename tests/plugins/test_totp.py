from datetime import datetime, timedelta, timezone
from typing import Any
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
def totp_app(memory_db: Any) -> tuple[FastAPI, Qulf, TestClient]:
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
class TestTOTPFlows:
    async def test_totp_full_flow(
        self, totp_app: tuple[FastAPI, Qulf, TestClient]
    ) -> None:
        app, auth, client = totp_app

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

        res_setup = client.post("/2fa/setup")
        assert res_setup.status_code == 200
        assert "otpauth://" in res_setup.json()["uri"]

        user = await auth.db.get_user_by_email("t@t.com")
        assert user is not None
        assert user.model_extra is not None
        secret = user.model_extra["two_factor_secret"]
        assert secret is not None

        valid_code = pyotp.TOTP(secret).now()
        res_enable = client.post("/2fa/enable", json={"code": valid_code})
        assert res_enable.status_code == 200

        with pytest.raises(Requires2FAError) as exc_info:
            await auth.sign_in("t@t.com", "p")

        temp_token = str(exc_info.value)

        new_valid_code = pyotp.TOTP(secret).now()
        res_verify = client.post(
            "/2fa/verify_login", json={"temp_token": temp_token, "code": new_valid_code}
        )

        assert res_verify.status_code == 200
        assert "qulf_session" in res_verify.cookies
        assert res_verify.json()["user"]["email"] == "t@t.com"

    async def test_totp_bad_flows(
        self, totp_app: tuple[FastAPI, Qulf, TestClient]
    ) -> None:
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

        res_enable = client.post("/2fa/enable", json={"code": "123456"})
        assert res_enable.status_code == 400
        assert "2FA not set up" in res_enable.json()["detail"]

        client.cookies.delete("qulf_session")
        res_setup = client.post("/2fa/setup")
        assert res_setup.status_code == 401

        res_verify = client.post(
            "/2fa/verify_login", json={"temp_token": "garbage", "code": "123456"}
        )
        assert res_verify.status_code == 401
        assert "Invalid or expired token" in res_verify.json()["detail"]


@pytest.mark.asyncio
class TestTOTPEdgeCases:
    async def test_totp_enable_edge_cases(
        self, totp_app: tuple[FastAPI, Qulf, TestClient]
    ) -> None:
        app, auth, client = totp_app

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

        res = client.post("/2fa/enable", json={"code": "123456"})
        assert res.status_code == 401

        client.cookies.set("qulf_session", session.token)
        client.post("/2fa/setup")

        res_missing_code = client.post("/2fa/enable", json={})
        assert res_missing_code.status_code == 400
        assert "2FA code missing" in res_missing_code.json()["detail"]

        res_invalid_code = client.post("/2fa/enable", json={"code": "000000"})
        assert res_invalid_code.status_code == 401
        assert "Invalid 2FA code" in res_invalid_code.json()["detail"]

        with patch.object(auth, "get_session_from_cookies", return_value=(None, user)):
            res_bad_session = client.post("/2fa/enable", json={"code": "123456"})
            assert res_bad_session.status_code == 400
            assert "Invalid or expired session" in res_bad_session.json()["detail"]

    async def test_totp_verify_login_edge_cases(
        self, totp_app: tuple[FastAPI, Qulf, TestClient]
    ) -> None:
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

        res_missing_code = client.post(
            "/2fa/verify_login", json={"temp_token": "token"}
        )
        assert res_missing_code.status_code == 400
        assert "2FA code missing" in res_missing_code.json()["detail"]

        res_missing_token = client.post("/2fa/verify_login", json={"code": "123456"})
        assert res_missing_token.status_code == 400
        assert "Temporary Auth token missing" in res_missing_token.json()["detail"]

        valid_payload = {
            "sub": user.id,
            "type": "2fa_pending",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
        valid_temp_token = jwt.encode(valid_payload, auth.config.secret_key)

        bad_payload = {**valid_payload, "sub": "fake-id"}
        bad_token = jwt.encode(bad_payload, auth.config.secret_key)
        res_bad_sub = client.post(
            "/2fa/verify_login", json={"temp_token": bad_token, "code": "123456"}
        )
        assert res_bad_sub.status_code == 400
        assert "User not found" in res_bad_sub.json()["detail"]

        await auth.db.update_user(user.id, {"two_factor_enabled": False})

        res_not_setup = client.post(
            "/2fa/verify_login", json={"temp_token": valid_temp_token, "code": "123456"}
        )
        assert res_not_setup.status_code == 401
        assert "not set up" in res_not_setup.json()["detail"]

        secret = pyotp.random_base32()
        await auth.db.update_user(user.id, {"two_factor_secret": secret})

        res_invalid_code = client.post(
            "/2fa/verify_login", json={"temp_token": valid_temp_token, "code": "000000"}
        )
        assert res_invalid_code.status_code == 401
        assert "Invalid 2FA code" in res_invalid_code.json()["detail"]

        valid_code = pyotp.TOTP(secret).now()
        with patch.object(
            auth, "create_session", side_effect=QulfException("Rate limited")
        ):
            res_rate_limited = client.post(
                "/2fa/verify_login",
                json={"temp_token": valid_temp_token, "code": valid_code},
            )
            assert res_rate_limited.status_code == 400
            assert "Rate limited" in res_rate_limited.json()["detail"]

        with patch.object(
            type(user), "model_extra", new_callable=PropertyMock, return_value=None
        ):
            with patch.object(auth.db, "get_user_by_id", return_value=user):
                res_no_model_extra = client.post(
                    "/2fa/verify_login",
                    json={"temp_token": valid_temp_token, "code": valid_code},
                )
                assert res_no_model_extra.status_code == 401
                assert "User not found" in res_no_model_extra.json()["detail"]
