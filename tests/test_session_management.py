import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import ConfigurationError
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.session import SessionManagementPlugin
from qulf.types import UserCreate


class TestSessionManagementPluginCore:
    def test_plugin_uninitialized(self):
        plugin = SessionManagementPlugin()
        with pytest.raises(ConfigurationError):
            _ = plugin.auth


class TestSessionManagementPluginRoutes:
    @pytest.fixture
    async def seeded_env(self, memory_db):
        config = QulfConfig(
            secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
        )
        plugin = SessionManagementPlugin()
        auth = Qulf(db=memory_db, config=config, plugins=[plugin])

        app = FastAPI()
        app.include_router(serve_qulf(auth))
        client = TestClient(app)

        user = await auth.sign_up(
            UserCreate(
                email="session_test@example.com",
                password="SecurePassword123!",
                password_confirmation="SecurePassword123!",
                username="session_tester",
                name="Session Tester",
            )
        )

        session1 = await auth.create_session(user, ip_address="192.168.1.1")
        session2 = await auth.create_session(user, ip_address="192.168.1.2")
        session3 = await auth.create_session(user, ip_address="192.168.1.3")

        return auth, client, config, user, session1, session2, session3

    @pytest.mark.asyncio
    async def test_get_sessions_list(self, seeded_env):
        auth, client, config, user, session1, _, _ = seeded_env

        res_unauth = client.get("/session/list")
        assert res_unauth.status_code == 401

        client.cookies.set(config.cookies.name, session1.token)
        res = client.get("/session/list")

        assert res.status_code == 200

        data = res.json()
        assert len(data["sessions"]) == 3
        assert "token" not in data["sessions"][0]

    @pytest.mark.asyncio
    async def test_revoke_session(self, seeded_env):
        auth, client, config, user, session1, session2, _ = seeded_env
        client.cookies.set(config.cookies.name, session1.token)

        res_bad_body = client.post("/session/revoke", json={"wrong_key": "bad_data"})
        assert res_bad_body.status_code == 400

        res_not_found = client.post("/session/revoke", json={"token": "fake_token_123"})
        assert res_not_found.status_code == 404

        res_success = client.post("/session/revoke", json={"token": session2.token})
        assert res_success.status_code == 200

        remaining = await auth.get_user_sessions(user.id)
        assert len(remaining) == 2

    @pytest.mark.asyncio
    async def test_revoke_all_sessions(self, seeded_env):
        auth, client, config, user, session1, _, _ = seeded_env
        client.cookies.set(config.cookies.name, session1.token)

        res = client.post("/session/revoke-all")
        assert res.status_code == 200

        # We start with 3 sessions. Revoking all except the current one should remove 2.
        assert res.json()["revoked_count"] == 2

        final_sessions = await auth.get_user_sessions(user.id)
        assert len(final_sessions) == 1
        assert final_sessions[0].token == session1.token

    @pytest.mark.asyncio
    async def test_invalid_session_tokens(self, seeded_env):
        _, client, config, _, session1, _, _ = seeded_env

        client.cookies.set(config.cookies.name, "this_is_a_fake_and_invalid_token")

        res_list = client.get("/session/list")
        assert res_list.status_code == 401
        assert res_list.json() == {"detail": "Invalid or expired session."}

        res_revoke = client.post("/session/revoke", json={"token": session1.token})
        assert res_revoke.status_code == 401
        assert res_revoke.json() == {"detail": "Invalid or expired session."}

        res_revoke_all = client.post("/session/revoke-all")
        assert res_revoke_all.status_code == 401
        assert res_revoke_all.json() == {"detail": "Invalid or expired session."}

    @pytest.mark.asyncio
    async def test_missing_auth_for_post_routes(self, seeded_env):
        _, client, _, _, session1, _, _ = seeded_env

        res_revoke = client.post("/session/revoke", json={"token": session1.token})
        assert res_revoke.status_code == 401

        res_revoke_all = client.post("/session/revoke-all")
        assert res_revoke_all.status_code == 401
