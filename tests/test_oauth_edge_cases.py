import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import ConfigurationError, QulfException
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.oauth import OAuthPlugin
from qulf.providers.base import BaseOAuthProvider, OAuthTokenResponse, OAuthUserProfile
from qulf.types import AccountCreate


class ErrorProneProvider(BaseOAuthProvider):
    id = "error_provider"
    name = "Error Provider"

    async def get_authorization_url(self, state: str) -> str:
        return f"https://error.com/auth?state={state}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        if code == "trigger_api_error":
            raise QulfException("Simulated API Error")
        return OAuthTokenResponse(access_token="fake_token", token_type="bearer")

    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        return OAuthUserProfile(
            id="999", email="test@test.com", name="Test", raw_data={}
        )


def test_oauth_plugin_uninitialized():
    with pytest.raises(ConfigurationError):
        OAuthPlugin().get_routes()


def test_oauth_routing_edge_cases():
    """Test the 404 and 400 error branches using TestClient."""
    provider = ErrorProneProvider(
        client_id="id", client_secret="secret", redirect_uri="http://localhost"
    )
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
        oauth_providers=[provider],
    )

    auth = Qulf(
        db=None,  # type: ignore
        config=config,
        plugins=[OAuthPlugin()],
    )  # DB not needed for these checks
    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    # Login with unknown provider
    assert client.get("/oauth/unknown/login", follow_redirects=False).status_code == 404

    # Callback with unknown provider
    assert client.get("/oauth/unknown/callback").status_code == 404

    # Callback missing code or state
    res_missing = client.get("/oauth/error_provider/callback")
    assert res_missing.status_code == 400
    assert "Missing code or state" in res_missing.json()["detail"]

    # Callback CSRF mismatch (Cookie doesn't match URL state)
    client.cookies.set("qulf_oauth_state_error_provider", "cookie_state")
    res_csrf = client.get("/oauth/error_provider/callback?code=123&state=url_state")
    assert res_csrf.status_code == 400
    assert "State mismatch" in res_csrf.json()["detail"]

    # Callback Provider API Exception
    client.cookies.set("qulf_oauth_state_error_provider", "match")
    res_api_err = client.get(
        "/oauth/error_provider/callback?code=trigger_api_error&state=match"
    )
    assert res_api_err.status_code == 400
    assert "Simulated API Error" in res_api_err.json()["detail"]


@pytest.mark.asyncio
async def test_oauth_db_integrity_error(sqlite_adapter):
    """Test the 500 error when an Account exists but the User was deleted."""
    provider = ErrorProneProvider(
        client_id="id", client_secret="secret", redirect_uri="http://localhost"
    )
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
        oauth_providers=[provider],
    )

    auth = Qulf(db=sqlite_adapter, config=config, plugins=[OAuthPlugin()])

    # Manually inject an orphaned account into the database
    # (User ID 99999 does not exist)
    await sqlite_adapter.create_account(
        AccountCreate(user_id=99999, account_id="999", provider_id="error_provider")
    )

    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    # Trigger the callback which will find the account, but fail to find the user
    client.cookies.set("qulf_oauth_state_error_provider", "match")
    res = client.get("/oauth/error_provider/callback?code=good_code&state=match")

    assert res.status_code == 500
    assert "Database integrity error" in res.json()["detail"]
