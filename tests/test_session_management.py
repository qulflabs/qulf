import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import ConfigurationError
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.session import SessionManagementPlugin
from qulf.types import UserCreate


def test_session_plugin_uninitialized():
    """Test that the plugin fails fast if it hasn't been initialized."""
    plugin = SessionManagementPlugin()
    with pytest.raises(ConfigurationError):
        plugin.auth


@pytest.mark.asyncio
async def test_session_management_routes(memory_db):
    """
    Comprehensive E2E Test for Session Management Plugin.
    Guarantees 100% test coverage for all routes and error handlers.
    """
    # 1. Setup Configuration & Plugin
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long",
    )
    plugin = SessionManagementPlugin()
    auth = Qulf(db=memory_db, config=config, plugins=[plugin])

    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app)

    # 2. Seed Database with User and 3 Sessions
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
    _session3 = await auth.create_session(user, ip_address="192.168.1.3")

    # ==========================================
    # ROUTE: GET /session/list
    # ==========================================

    res_list_unauth = client.get("/session/list")
    assert res_list_unauth.status_code == 401, res_list_unauth.json()

    client.cookies.set(config.cookies.name, session1.token)
    res_list = client.get("/session/list")
    assert res_list.status_code == 200, res_list.json()
    assert len(res_list.json()["sessions"]) == 3
    assert "token" not in res_list.json()["sessions"][0]

    # ==========================================
    # ROUTE: POST /session/revoke
    # ==========================================

    res_revoke_bad_body = client.post("/session/revoke", json={"wrong_key": "bad_data"})
    assert res_revoke_bad_body.status_code == 400, res_revoke_bad_body.json()

    res_revoke_not_found = client.post(
        "/session/revoke", json={"token": "fake_token_123"}
    )
    assert res_revoke_not_found.status_code == 404, res_revoke_not_found.json()

    res_revoke = client.post("/session/revoke", json={"token": session2.token})
    assert res_revoke.status_code == 200, res_revoke.json()

    remaining = await auth.get_user_sessions(user.id)
    assert len(remaining) == 2

    # ==========================================
    # ROUTE: POST /session/revoke-all
    # ==========================================

    res_revoke_all = client.post("/session/revoke-all")
    assert res_revoke_all.status_code == 200, res_revoke_all.json()
    assert res_revoke_all.json()["revoked_count"] == 1

    final = await auth.get_user_sessions(user.id)
    assert len(final) == 1
    assert final[0].token == session1.token

    # ==========================================
    # FINAL SAD PATHS: Missing Auth for POST routes
    # ==========================================

    client.cookies.delete(config.cookies.name)

    res_revoke_unauth = client.post("/session/revoke", json={"token": session1.token})
    assert res_revoke_unauth.status_code == 401, res_revoke_unauth.json()

    res_revoke_all_unauth = client.post("/session/revoke-all")
    assert res_revoke_all_unauth.status_code == 401, res_revoke_all_unauth.json()

    client.cookies.set(config.cookies.name, "this_is_a_fake_and_invalid_token")

    # Hits Line 25
    res_list_invalid = client.get("/session/list")
    assert res_list_invalid.status_code == 401
    assert res_list_invalid.json() == {"detail": "Invalid or expired session."}

    # Hits Line 50
    res_revoke_invalid = client.post("/session/revoke", json={"token": session1.token})
    assert res_revoke_invalid.status_code == 401
    assert res_revoke_invalid.json() == {"detail": "Invalid or expired session."}

    # Hits Line 86
    res_revoke_all_invalid = client.post("/session/revoke-all")
    assert res_revoke_all_invalid.status_code == 401
    assert res_revoke_all_invalid.json() == {"detail": "Invalid or expired session."}
