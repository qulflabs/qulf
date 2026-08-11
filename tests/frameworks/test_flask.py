from unittest import mock

import pytest
from flask import Flask, Request

from qulf.exceptions import QulfException, Requires2FAError
from qulf.frameworks.flask import requires_permission, requires_role, serve_qulf


@pytest.fixture
def app(auth_mock):
    flask_app = Flask(__name__)
    flask_app.register_blueprint(serve_qulf(auth_mock))

    # Async Decorators
    @flask_app.route("/dep-roles-all")
    @requires_role(auth_mock, ["admin", "editor"], mode="all")
    async def roles_all_route():
        return {"ok": True}

    @flask_app.route("/dep-perms-all")
    @requires_permission(auth_mock, ["read", "write"], mode="all")
    async def perms_all_route():
        return {"ok": True}

    # Sync Decorators (Hits lines 279 and 316)
    @flask_app.route("/sync-role")
    @requires_role(auth_mock, "admin")
    def sync_role():
        return {"ok": True}

    @flask_app.route("/sync-perm")
    @requires_permission(auth_mock, "write")
    def sync_perm():
        return {"ok": True}

    @flask_app.route("/dep-roles-any")
    @requires_role(auth_mock, ["admin", "editor"], mode="any")
    async def roles_any_route():
        return {"ok": True}

    @flask_app.route("/dep-perms-any")
    @requires_permission(auth_mock, ["read", "write"], mode="any")
    async def perms_any_route():
        return {"ok": True}

    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


class TestFlaskAuthEndpoints:
    def test_sign_up(self, client, auth_mock, dummy_user):
        auth_mock.sign_up.return_value = dummy_user
        res = client.post(
            "/sign-up",
            json={
                "email": "a@b.c",
                "password": "p",
                "password_confirmation": "p",
                "username": "u",
                "name": "n",
            },
        )
        assert res.status_code == 200

        auth_mock.sign_up.side_effect = QulfException("Bad Data")
        res = client.post("/sign-up", json={})
        assert res.status_code == 400

    def test_sign_in(self, client, auth_mock, dummy_session):
        auth_mock.sign_in.return_value = dummy_session
        res = client.post("/sign-in", json={"email": "a@b.c", "password": "p"})
        assert res.status_code == 200
        assert "Set-Cookie" in res.headers

        auth_mock.sign_in.side_effect = QulfException("Invalid credentials")
        res = client.post("/sign-in", json={"email": "a@b.c", "password": "bad"})
        assert res.status_code == 400

    def test_flask_sign_in_requires_2fa(self, client, auth_mock) -> None:
        temp_token = "temporary-2fa-token"
        auth_mock.sign_in.side_effect = Requires2FAError(temp_token)

        response = client.post(
            "/sign-in",
            json={"email": "a@b.c", "password": "bad"},
        )

        assert response.status_code == 401
        assert response.get_json() == {
            "detail": "2FA required",
            "temp_token": temp_token,
        }

    def test_sign_out(self, client, auth_mock):
        client.set_cookie(auth_mock.config.cookies.name, "valid_token")
        res = client.post("/sign-out")
        assert res.status_code == 200

        client.delete_cookie(auth_mock.config.cookies.name)
        res = client.post("/sign-out")
        assert res.status_code == 401

    def test_change_password_valid_session(
        self, client, auth_mock, dummy_session, dummy_user
    ):
        auth_mock.validate_session.return_value = (dummy_session, dummy_user)
        client.set_cookie(auth_mock.config.cookies.name, "valid_token")
        res = client.post(
            "/change-password", json={"old_password": "o", "new_password": "n"}
        )
        assert res.status_code == 200

    def test_change_password_invalid_session(self, client, auth_mock):
        # Token exists in request, but validate_session returns None
        auth_mock.validate_session.return_value = None
        client.set_cookie(auth_mock.config.cookies.name, "bad_token")
        res = client.post(
            "/change-password", json={"old_password": "o", "new_password": "n"}
        )
        assert res.status_code == 401

        # Test with NO token at all
        client.delete_cookie(auth_mock.config.cookies.name)
        res = client.post(
            "/change-password", json={"old_password": "o", "new_password": "n"}
        )
        assert res.status_code == 401

    def test_forgot_password(self, client, auth_mock):
        auth_mock.generate_password_reset_token.return_value = None
        res = client.post("/forgot-password", json={"email": "a@b.c"})
        assert res.status_code == 200

        auth_mock.generate_password_reset_token.side_effect = QulfException("Error")
        res = client.post("/forgot-password", json={"email": "a@b.c"})
        assert res.status_code == 400

    def test_reset_password(self, client, auth_mock):
        auth_mock.reset_password.return_value = None
        res = client.post("/reset-password", json={"token": "tok", "new_password": "p"})
        assert res.status_code == 200

        auth_mock.reset_password.side_effect = QulfException("Error")
        res = client.post("/reset-password", json={"token": "tok", "new_password": "p"})
        assert res.status_code == 400

    def test_verify_email(self, client, auth_mock):
        auth_mock.verify_email.return_value = None
        res = client.post("/verify-email", json={"token": "tok"})
        assert res.status_code == 200

        auth_mock.verify_email.side_effect = QulfException("Error")
        res = client.post("/verify-email", json={"token": "tok"})
        assert res.status_code == 400

    def test_delete_account(self, client, auth_mock, dummy_session, dummy_user):
        auth_mock.validate_session.return_value = (dummy_session, dummy_user)
        client.set_cookie(auth_mock.config.cookies.name, "valid_token")
        auth_mock.delete_account.return_value = None
        res = client.delete("/delete-account")
        assert res.status_code == 200

        auth_mock.validate_session.return_value = None
        res = client.delete("/delete-account")
        assert res.status_code == 401


class TestFlaskPlugins:
    def test_plugin_headers_and_cookies(self, client, auth_mock):
        res = client.post("/plugin-complex", json={"dummy": "data"})
        assert res.status_code == 201
        assert res.headers.get("X-Custom-Header") == "qulf-rocks"

        cookies = res.headers.getlist("Set-Cookie")
        assert any("new_cookie=val" in c for c in cookies)
        assert any("old_cookie" in c and ("=;" in c or '=""' in c) for c in cookies)

    def test_plugin_invalid_json_body(self, client):
        # Hits the silent exception catch during `request.get_json()` in plugins
        res = client.put(
            "/plugin-complex",
            data="this-is-not-valid-json",
            content_type="application/json",
        )
        assert res.status_code == 201

    def test_plugin_rbac(self, client, auth_mock, dummy_user):
        # Missing session
        auth_mock.get_session_from_cookies.return_value = None
        assert client.get("/plugin-role").status_code == 401
        assert client.get("/plugin-perm").status_code == 401

        # Authorized
        auth_mock.get_session_from_cookies.return_value = ("fake_session", dummy_user)
        auth_mock.has_role.return_value = True
        auth_mock.has_permission.return_value = True
        assert client.get("/plugin-role").status_code == 200
        assert client.get("/plugin-perm").status_code == 200

        # Unauthorized
        auth_mock.has_role.return_value = False
        auth_mock.has_permission.return_value = False
        assert client.get("/plugin-role").status_code == 403
        assert client.get("/plugin-perm").status_code == 403

    def test_plugin_json_exception(self, client, auth_mock):
        with mock.patch.object(Request, "get_json", side_effect=Exception("Boom")):
            res = client.post("/plugin-complex", json={"dummy": "data"})
            assert res.status_code == 201


class TestFlaskDecorators:
    def test_sync_decorators(self, client, auth_mock, dummy_user):
        auth_mock.get_session_from_cookies.return_value = ("fake_session", dummy_user)

        # Test Role
        auth_mock.has_role.return_value = True
        assert client.get("/sync-role").status_code == 200
        auth_mock.has_role.return_value = False
        assert client.get("/sync-role").status_code == 403

        # Test Permission
        auth_mock.has_permission.return_value = True
        assert client.get("/sync-perm").status_code == 200
        auth_mock.has_permission.return_value = False
        assert client.get("/sync-perm").status_code == 403

    def test_async_decorators_unauthenticated(self, client, auth_mock):
        auth_mock.get_session_from_cookies.return_value = None
        assert client.get("/dep-roles-all").status_code == 401
        assert client.get("/dep-perms-all").status_code == 401

    def test_async_decorators_all(self, client, auth_mock, dummy_user):
        auth_mock.get_session_from_cookies.return_value = ("fake_session", dummy_user)

        # Test Roles All (Requires admin AND editor)
        auth_mock.has_role.side_effect = lambda user, role: True
        assert client.get("/dep-roles-all").status_code == 200
        auth_mock.has_role.side_effect = lambda user, role: role == "admin"
        assert client.get("/dep-roles-all").status_code == 403

        # Test Perms All (Requires read AND write)
        auth_mock.has_permission.side_effect = lambda user, perm: True
        assert client.get("/dep-perms-all").status_code == 200
        auth_mock.has_permission.side_effect = lambda user, perm: perm == "read"
        assert client.get("/dep-perms-all").status_code == 403

    def test_async_decorators_any(self, client, auth_mock, dummy_user):
        auth_mock.get_session_from_cookies.return_value = ("fake_session", dummy_user)

        # Test Roles Any
        auth_mock.has_role.side_effect = lambda user, role: role == "editor"
        assert client.get("/dep-roles-any").status_code == 200
        auth_mock.has_role.side_effect = lambda user, role: False
        assert client.get("/dep-roles-any").status_code == 403

        # Test Perms Any
        auth_mock.has_permission.side_effect = lambda user, perm: perm == "write"
        assert client.get("/dep-perms-any").status_code == 200
        auth_mock.has_permission.side_effect = lambda user, perm: False
        assert client.get("/dep-perms-any").status_code == 403


class TestFlaskSessionRoute:
    def test_get_session(self, client, auth_mock, dummy_user, dummy_session):
        # 1. Valid Session
        auth_mock.get_session_from_cookies.return_value = (dummy_session, dummy_user)
        res = client.get("/session")
        assert res.status_code == 200
        assert res.json["user"]["id"] == dummy_user.id

        # 2. Invalid Session
        auth_mock.get_session_from_cookies.return_value = None
        res = client.get("/session")
        assert res.status_code == 401

        # 3. Exception thrown during lookup
        from qulf.exceptions import QulfException

        auth_mock.get_session_from_cookies.side_effect = QulfException("Database Error")
        res = client.get("/session")
        assert res.status_code == 401


class TestFlaskDependencies:
    @pytest.mark.asyncio
    async def test_get_current_user_and_session(
        self, app, auth_mock, dummy_user, dummy_session
    ):
        from qulf.exceptions import QulfException
        from qulf.frameworks.flask import get_current_session, get_current_user

        # Ensure we don't carry over the side_effect from the previous test
        auth_mock.get_session_from_cookies.side_effect = None

        # Flask requires an active request context to access `request.cookies`
        with app.test_request_context(headers={"Cookie": "qulf_token=valid"}):
            # 1. Valid Session
            auth_mock.get_session_from_cookies.return_value = (
                dummy_session,
                dummy_user,
            )

            user = await get_current_user(auth_mock)()
            assert user.id == dummy_user.id

            session = await get_current_session(auth_mock)()
            assert session.token == dummy_session.token

            # 2. Invalid Session -> Raises QulfException
            auth_mock.get_session_from_cookies.return_value = None

            with pytest.raises(QulfException, match="Unauthorized"):
                await get_current_user(auth_mock)()

            with pytest.raises(QulfException, match="Unauthorized"):
                await get_current_session(auth_mock)()
