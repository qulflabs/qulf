from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import ConfigurationError, InvalidTokenError, SessionExpiredError
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.magic_link import MagicLinkPlugin
from qulf.types import UserCreate


class FakeEmailSender:
    def __init__(self) -> None:
        self.last_email: str | None = None
        self.last_token: str | None = None

    async def send(self, email: str, token: str) -> None:
        self.last_email = email
        self.last_token = token


@pytest.fixture
def email_sender() -> FakeEmailSender:
    return FakeEmailSender()


@pytest.mark.asyncio
class TestMagicLinkCore:
    async def test_uninitialized_plugin(self, email_sender: FakeEmailSender) -> None:
        plugin = MagicLinkPlugin(send_email_func=email_sender.send)

        with pytest.raises(ConfigurationError, match="has not been initialized"):
            await plugin.generate_and_send("test@test.com")

        with pytest.raises(ConfigurationError, match="has not been initialized"):
            await plugin.verify_and_sign_in("some_token")

    async def test_magic_link_flow_new_user(
        self, memory_db: Any, email_sender: FakeEmailSender
    ) -> None:
        plugin = MagicLinkPlugin(send_email_func=email_sender.send)
        Qulf(db=memory_db, plugins=[plugin])

        await plugin.generate_and_send("newuser@test.com")
        assert email_sender.last_email == "newuser@test.com"
        assert email_sender.last_token is not None

        session, user = await plugin.verify_and_sign_in(email_sender.last_token)
        assert user.email == "newuser@test.com"
        assert session.user_id == user.id

    async def test_magic_link_flow_existing_user(
        self, memory_db: Any, email_sender: FakeEmailSender
    ) -> None:
        plugin = MagicLinkPlugin(send_email_func=email_sender.send)
        auth = Qulf(db=memory_db, plugins=[plugin])

        await auth.sign_up(
            UserCreate(
                name="E",
                email="exist@test.com",
                username="e",
                password="p",
                password_confirmation="p",
            )
        )

        await plugin.generate_and_send("exist@test.com")
        assert email_sender.last_token is not None

        session, user = await plugin.verify_and_sign_in(email_sender.last_token)
        assert user.email == "exist@test.com"
        assert session.user_id == user.id

    async def test_magic_link_exceptions(
        self, memory_db: Any, email_sender: FakeEmailSender
    ) -> None:
        plugin = MagicLinkPlugin(send_email_func=email_sender.send)
        auth = Qulf(db=memory_db, plugins=[plugin])

        with pytest.raises(InvalidTokenError):
            await plugin.verify_and_sign_in("not_a_real_jwt")

        expired_payload = {
            "email": "test@test.com",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
        }
        expired_token = jwt.encode(
            expired_payload, auth.config.secret_key, algorithm="HS256"
        )

        with pytest.raises(SessionExpiredError):
            await plugin.verify_and_sign_in(expired_token)


class TestMagicLinkAPI:
    def test_magic_link_fastapi_routes(
        self, memory_db: Any, email_sender: FakeEmailSender
    ) -> None:
        plugin = MagicLinkPlugin(send_email_func=email_sender.send)

        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
        )
        auth = Qulf(db=memory_db, config=config, plugins=[plugin])

        app = FastAPI()
        app.include_router(serve_qulf(auth))
        client = TestClient(app)

        res_send = client.post("/magic-link/send", json={"email": "api@test.com"})
        assert res_send.status_code == 200
        assert email_sender.last_email == "api@test.com"

        token = email_sender.last_token
        assert token is not None

        res_verify = client.post("/magic-link/verify", json={"token": token})
        assert res_verify.status_code == 200
        assert "qulf_session" in res_verify.cookies
        assert res_verify.json()["user"]["email"] == "api@test.com"

        res_bad = client.post("/magic-link/verify", json={"token": "garbage"})
        assert res_bad.status_code == 400

        res_send_no_email = client.post("/magic-link/send", json={})
        assert res_send_no_email.status_code == 400
        assert res_send_no_email.json() == {"detail": "Email is required"}

        res_verify_no_token = client.post("/magic-link/verify", json={})
        assert res_verify_no_token.status_code == 400
        assert res_verify_no_token.json() == {"detail": "Token is required"}
