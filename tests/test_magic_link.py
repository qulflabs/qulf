from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.core import Qulf
from qulf.exceptions import ConfigurationError, InvalidTokenError, SessionExpiredError
from qulf.plugins.magic_link import MagicLinkPlugin

SECRET_KEY = "super_secret_test_key_that_is_at_least_32_bytes_long"


class FakeEmailSender:
    def __init__(self):
        self.last_email = None
        self.last_token = None

    async def send(self, email: str, token: str):
        self.last_email = email
        self.last_token = token


@pytest.fixture
def email_sender():
    return FakeEmailSender()


@pytest.mark.asyncio
async def test_uninitialized_plugin(email_sender):
    plugin = MagicLinkPlugin(send_email_func=email_sender.send)
    with pytest.raises(ConfigurationError, match="not been initialized"):
        await plugin.verify_and_sign_in("some_token")


@pytest.mark.asyncio
async def test_magic_link_flow_new_user(memory_db, email_sender):
    plugin = MagicLinkPlugin(send_email_func=email_sender.send)
    Qulf(db=memory_db, plugins=[plugin])

    await plugin.generate_and_send("newuser@test.com")
    assert email_sender.last_email == "newuser@test.com"
    assert email_sender.last_token is not None

    session, user = await plugin.verify_and_sign_in(email_sender.last_token)
    assert user.email == "newuser@test.com"
    assert session.user_id == user.id


@pytest.mark.asyncio
async def test_magic_link_flow_existing_user(memory_db, email_sender):
    plugin = MagicLinkPlugin(send_email_func=email_sender.send)
    auth = Qulf(db=memory_db, plugins=[plugin])

    from qulf.types import UserCreate

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
    session, user = await plugin.verify_and_sign_in(email_sender.last_token)

    assert user.email == "exist@test.com"
    assert session.user_id == user.id


@pytest.mark.asyncio
async def test_magic_link_exceptions(memory_db, email_sender):
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


def test_magic_link_fastapi_routes(memory_db, email_sender):
    from qulf import QulfConfig
    from qulf.frameworks.fastapi import serve_qulf

    plugin = MagicLinkPlugin(send_email_func=email_sender.send)


    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
    )
    auth = Qulf(db=memory_db, config=config, plugins=[plugin])

    # 3. Mount to FastAPI
    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    # 4. Test /send
    res_send = client.post("/magic-link/send", json={"email": "api@test.com"})
    assert res_send.status_code == 200
    assert email_sender.last_email == "api@test.com"

    token = email_sender.last_token

    # 5. Test /verify
    res_verify = client.post("/magic-link/verify", json={"token": token})
    assert res_verify.status_code == 200
    assert "qulf_session" in res_verify.cookies
    assert res_verify.json()["user"]["email"] == "api@test.com"

    # 6. Test /verify with bad token
    res_bad = client.post("/magic-link/verify", json={"token": "garbage"})
    assert res_bad.status_code == 400
