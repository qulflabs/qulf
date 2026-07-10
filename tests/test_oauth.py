from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.oauth import OAuthPlugin
from qulf.providers.base import BaseOAuthProvider, OAuthTokenResponse, OAuthUserProfile


class FakeOAuthProvider(BaseOAuthProvider):
    id = "fake"
    name = "Fake Provider"

    async def get_authorization_url(self, state: str) -> str:
        return f"https://fake.com/auth?state={state}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        if code == "bad_code":
            from qulf.exceptions import QulfException

            raise QulfException("Invalid code")

        return OAuthTokenResponse(
            access_token="fake_token",
            token_type="bearer",
            expires_in=3600,
            refresh_token=None,
            scope="email",
        )

    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        return OAuthUserProfile(
            id="12345",
            email="oauth@test.com",
            name="OAuth User",
            username="oauthuser",
            avatar_url=None,
            raw_data={},
        )


def test_oauth_plugin_fastapi_routes(memory_db):
    provider = FakeOAuthProvider(
        client_id="id", client_secret="secret", redirect_uri="http://localhost/callback"
    )
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
        oauth_providers=[provider],
    )

    plugin = OAuthPlugin()
    auth = Qulf(db=memory_db, config=config, plugins=[plugin])

    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    # TEST 1: LOGIN, Redirect
    res_login = client.get("/oauth/fake/login", follow_redirects=False)
    assert res_login.status_code == 302
    assert "https://fake.com/auth" in res_login.headers["location"]

    state_cookie_val = res_login.cookies.get("qulf_oauth_state_fake")
    assert state_cookie_val is not None

    location = res_login.headers["location"]
    state_from_url = location.split("state=")[1]
    assert state_cookie_val == state_from_url

    # TEST 2: CALLBACK, Success
    client.cookies.set("qulf_oauth_state_fake", state_cookie_val)

    res_callback = client.get(
        f"/oauth/fake/callback?code=good_code&state={state_from_url}"
    )
    assert res_callback.status_code == 200
    assert "qulf_session" in res_callback.cookies
    assert res_callback.json()["user"]["email"] == "oauth@test.com"

    assert not res_callback.cookies.get("qulf_oauth_state_fake")

    # TEST 3: CALLBACK, CSRF Failure
    client.cookies.set("qulf_oauth_state_fake", "wrong_cookie_state")
    res_bad_csrf = client.get(
        f"/oauth/fake/callback?code=good_code&state={state_from_url}"
    )
    assert res_bad_csrf.status_code == 400
    assert "CSRF attempt blocked" in res_bad_csrf.json()["detail"]