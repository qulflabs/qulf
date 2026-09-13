from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.crypto import hash_password
from qulf.exceptions import QulfException
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.oauth import OAuthPlugin
from qulf.providers.base import BaseOAuthProvider, OAuthTokenResponse, OAuthUserProfile
from qulf.types import AccountCreate, UserCreate


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


class FakeOAuthProvider(BaseOAuthProvider):
    id = "fake"
    name = "Fake Provider"

    async def get_authorization_url(self, state: str) -> str:
        return f"https://fake.com/auth?state={state}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        if code == "bad_code":
            raise QulfException("Invalid code")

        refresh = "new_refresh_token" if "refresh" in code else None
        token = code if code.startswith("token_") else "fake_token"

        return OAuthTokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=3600,
            refresh_token=refresh,
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


class TestOAuthPluginFastAPIRoutes:
    def test_oauth_plugin_fastapi_routes(self, memory_db: Any) -> None:
        provider = FakeOAuthProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/callback",
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

        res_login = client.get("/oauth/fake/login", follow_redirects=False)
        assert res_login.status_code == 302
        assert "https://fake.com/auth" in res_login.headers["location"]

        state_cookie_val = res_login.cookies.get("qulf_oauth_state_fake")
        assert state_cookie_val is not None

        location = res_login.headers["location"]
        state_from_url = location.split("state=")[1]
        assert state_cookie_val == state_from_url

        client.cookies.set("qulf_oauth_state_fake", state_cookie_val)

        res_callback = client.get(
            f"/oauth/fake/callback?code=good_code&state={state_from_url}"
        )
        assert res_callback.status_code == 200
        assert "qulf_session" in res_callback.cookies
        assert res_callback.json()["user"]["email"] == "oauth@test.com"
        assert not res_callback.cookies.get("qulf_oauth_state_fake")

        client.cookies.set("qulf_oauth_state_fake", "wrong_cookie_state")
        res_bad_csrf = client.get(
            f"/oauth/fake/callback?code=good_code&state={state_from_url}"
        )
        assert res_bad_csrf.status_code == 400
        assert "CSRF attempt blocked" in res_bad_csrf.json()["detail"]

    @pytest.mark.asyncio
    async def test_oauth_token_refresh_on_existing_account(
        self, memory_db: Any
    ) -> None:
        provider = FakeOAuthProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/callback",
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

        # First login - initial account creation
        client.cookies.set("qulf_oauth_state_fake", "state1")
        res1 = client.get("/oauth/fake/callback?code=token_first&state=state1")
        assert res1.status_code == 200

        acc = await auth.db.get_account_by_provider("fake", "12345")
        assert acc is not None
        assert acc.access_token == "token_first"
        assert acc.refresh_token is None

        # Second login - token refresh with new access and refresh token
        client.cookies.set("qulf_oauth_state_fake", "state2")
        res2 = client.get(
            "/oauth/fake/callback?code=token_second_with_refresh&state=state2"
        )
        assert res2.status_code == 200

        acc_updated = await auth.db.get_account_by_provider("fake", "12345")
        assert acc_updated is not None
        assert acc_updated.access_token == "token_second_with_refresh"
        assert acc_updated.refresh_token == "new_refresh_token"

    @pytest.mark.asyncio
    async def test_oauth_rejects_soft_deleted_linked_user(self, memory_db: Any) -> None:
        provider = FakeOAuthProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/callback",
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

        # First login creates account & user
        client.cookies.set("qulf_oauth_state_fake", "state1")
        res1 = client.get("/oauth/fake/callback?code=good_code&state=state1")
        assert res1.status_code == 200

        # Soft delete the user
        user = await auth.db.get_user_by_email("oauth@test.com")
        assert user is not None
        now = datetime.now(timezone.utc)
        await auth.db.update_user(user.id, {"deleted_at": now})

        # Attempt to login again via OAuth
        client.cookies.set("qulf_oauth_state_fake", "state2")
        res2 = client.get("/oauth/fake/callback?code=good_code&state=state2")
        assert res2.status_code == 400
        assert res2.json()["detail"] == "User account has been deleted or deactivated"

    @pytest.mark.asyncio
    async def test_oauth_rejects_soft_deleted_email_match_user(
        self, memory_db: Any
    ) -> None:
        provider = FakeOAuthProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/callback",
        )
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
            oauth_providers=[provider],
        )

        plugin = OAuthPlugin()
        auth = Qulf(db=memory_db, config=config, plugins=[plugin])

        # Pre-create user with same email but no linked OAuth account, soft-deleted
        user_data = UserCreate(
            email="oauth@test.com",
            name="Deleted User",
            username="deleteduser",
            password="Password123!",
            password_confirmation="Password123!",
        )
        created_user = await auth.db.create_user(
            user_data, hash_password("Password123!")
        )
        now = datetime.now(timezone.utc)
        await auth.db.update_user(created_user.id, {"deleted_at": now})

        app = FastAPI()
        app.include_router(serve_qulf(auth))
        client = TestClient(app)

        client.cookies.set("qulf_oauth_state_fake", "state1")
        res = client.get("/oauth/fake/callback?code=good_code&state=state1")
        assert res.status_code == 400
        assert res.json()["detail"] == "User account has been deleted or deactivated"


class TestOAuthRoutingEdgeCases:
    def test_oauth_routing_edge_cases(self) -> None:
        provider = ErrorProneProvider(
            client_id="id", client_secret="secret", redirect_uri="http://localhost"
        )
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
            oauth_providers=[provider],
        )

        auth = Qulf(
            db=MagicMock(),
            config=config,
            plugins=[OAuthPlugin()],
        )

        app = FastAPI()
        app.include_router(serve_qulf(auth))
        client = TestClient(app)

        assert (
            client.get("/oauth/unknown/login", follow_redirects=False).status_code
            == 404
        )

        assert client.get("/oauth/unknown/callback").status_code == 404

        res_missing = client.get("/oauth/error_provider/callback")
        assert res_missing.status_code == 400
        assert "Missing code or state" in res_missing.json()["detail"]

        client.cookies.set("qulf_oauth_state_error_provider", "cookie_state")
        res_csrf = client.get("/oauth/error_provider/callback?code=123&state=url_state")
        assert res_csrf.status_code == 400
        assert "State mismatch" in res_csrf.json()["detail"]

        client.cookies.set("qulf_oauth_state_error_provider", "match")
        res_api_err = client.get(
            "/oauth/error_provider/callback?code=trigger_api_error&state=match"
        )
        assert res_api_err.status_code == 400
        assert "Simulated API Error" in res_api_err.json()["detail"]

    @pytest.mark.asyncio
    async def test_oauth_db_integrity_error(self, sqlalchemy_adapter: Any) -> None:
        provider = ErrorProneProvider(
            client_id="id", client_secret="secret", redirect_uri="http://localhost"
        )
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
            oauth_providers=[provider],
        )

        auth = Qulf(db=sqlalchemy_adapter, config=config, plugins=[OAuthPlugin()])

        await sqlalchemy_adapter.create_account(
            AccountCreate(user_id=99999, account_id="999", provider_id="error_provider")
        )

        app = FastAPI()
        app.include_router(serve_qulf(auth))
        client = TestClient(app)

        client.cookies.set("qulf_oauth_state_error_provider", "match")
        res = client.get("/oauth/error_provider/callback?code=good_code&state=match")

        assert res.status_code == 500
        assert "Database integrity error" in res.json()["detail"]
