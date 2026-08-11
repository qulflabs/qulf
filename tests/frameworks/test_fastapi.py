import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from qulf.exceptions import QulfException, Requires2FAError
from qulf.frameworks.fastapi import (
    RequiresPermission,
    RequiresRole,
    get_current_session,
    get_current_user,
    serve_qulf,
)
from qulf.types import Session, User


@pytest.fixture
def app(auth_mock):
    fastapi_app = FastAPI()
    fastapi_app.include_router(serve_qulf(auth_mock))

    # Async Dependency Routes (RBAC)
    @fastapi_app.get("/dep-roles-all")
    def roles_all_route(
        user: User = Depends(RequiresRole(auth_mock, ["admin", "editor"], mode="all")),
    ):
        return {"ok": True}

    @fastapi_app.get("/dep-roles-any")
    def roles_any_route(
        user: User = Depends(RequiresRole(auth_mock, ["admin", "editor"], mode="any")),
    ):
        return {"ok": True}

    @fastapi_app.get("/dep-perms-all")
    def perms_all_route(
        user: User = Depends(
            RequiresPermission(auth_mock, ["read", "write"], mode="all")
        ),
    ):
        return {"ok": True}

    @fastapi_app.get("/dep-perms-any")
    def perms_any_route(
        user: User = Depends(
            RequiresPermission(auth_mock, ["read", "write"], mode="any")
        ),
    ):
        return {"ok": True}

    # Custom Dependency Routes (User / Session extraction)
    @fastapi_app.get("/custom-user")
    def custom_user_route(user: User = Depends(get_current_user(auth_mock))):
        return {"user_id": user.id}

    @fastapi_app.get("/custom-session")
    def custom_session_route(
        session: Session = Depends(get_current_session(auth_mock)),
    ):
        return {"session_token": session.token}

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestFastAPIAuthEndpoints:
    SIGN_UP_DATA = {
        "email": "a@b.c",
        "password": "p",
        "password_confirmation": "p",
        "username": "u",
        "name": "n",
    }

    def test_sign_up(self, client, auth_mock, dummy_user):
        auth_mock.sign_up.return_value = dummy_user
        res = client.post(
            "/sign-up",
            json=self.SIGN_UP_DATA,
        )
        assert res.status_code == 200

        auth_mock.sign_up.side_effect = QulfException("Bad Data")
        res = client.post("/sign-up", json={})
        assert res.status_code == 422

    def test_sign_in(self, client, auth_mock, dummy_session):
        auth_mock.sign_in.return_value = dummy_session
        res = client.post("/sign-in", json={"email": "a@b.c", "password": "p"})
        assert res.status_code == 200
        assert "set-cookie" in res.headers

        auth_mock.sign_in.side_effect = QulfException("Invalid credentials")
        res = client.post("/sign-in", json={"email": "a@b.c", "password": "bad"})
        assert res.status_code == 400

    def test_fastapi_sign_in_requires_2fa(self, client, auth_mock) -> None:
        temp_token = "temporary-2fa-token"
        auth_mock.sign_in.side_effect = Requires2FAError(temp_token)

        response = client.post(
            "/sign-in",
            json={"email": "a@b.c", "password": "p"},
        )

        assert response.status_code == 401
        assert response.json() == {
            "detail": {
                "detail": "2FA required",
                "temp_token": temp_token,
            }
        }

    def test_sign_out(self, client, auth_mock):
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        res = client.post("/sign-out")
        assert res.status_code == 200

        client.cookies.clear()
        res = client.post("/sign-out")
        assert res.status_code == 200

    def test_change_password(self, client, auth_mock, dummy_session, dummy_user):
        auth_mock.validate_session.return_value = (dummy_session, dummy_user)
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        res = client.post(
            "/change-password", json={"old_password": "o", "new_password": "n"}
        )
        assert res.status_code == 200

        # Token exists in request, but validate_session returns None
        auth_mock.validate_session.return_value = None
        res = client.post(
            "/change-password", json={"old_password": "o", "new_password": "n"}
        )
        assert res.status_code == 401

        # Test with NO token at all
        client.cookies.clear()
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
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        auth_mock.delete_account.return_value = None
        res = client.delete("/delete-account")
        assert res.status_code == 200

        auth_mock.validate_session.return_value = None
        res = client.delete("/delete-account")
        assert res.status_code == 401

    def test_sign_up_exception(self, client, auth_mock):
        auth_mock.sign_up.side_effect = QulfException("Email already taken")
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
        # Hits lines 84-85
        assert res.status_code == 400
        assert res.json()["detail"] == "Email already taken"

    def test_authenticated_user_id_exception(self, client, auth_mock):
        # Force validate_session to raise an exception instead of returning None
        auth_mock.validate_session.side_effect = QulfException("Database offline")
        client.cookies.set(auth_mock.config.cookies.name, "bad_token")

        # Calling delete-account triggers _get_authenticated_user_id
        res = client.delete("/delete-account")

        # Hits line 78
        assert res.status_code == 401
        assert res.json()["detail"] == "Database offline"

    def test_change_password_exception(
        self, client, auth_mock, dummy_session, dummy_user
    ):
        auth_mock.validate_session.return_value = (dummy_session, dummy_user)
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")

        # Core engine throws an error (e.g. wrong old password)
        auth_mock.change_password.side_effect = QulfException("Wrong password")
        res = client.post(
            "/change-password", json={"old_password": "bad", "new_password": "n"}
        )

        # Hits lines 165-166
        assert res.status_code == 400
        assert res.json()["detail"] == "Wrong password"

    def test_delete_account_exception(
        self, client, auth_mock, dummy_session, dummy_user
    ):
        auth_mock.validate_session.return_value = (dummy_session, dummy_user)
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")

        # Core engine throws an error
        auth_mock.delete_account.side_effect = QulfException("Cannot delete admin")
        res = client.delete("/delete-account")

        # Hits lines 173-174
        assert res.status_code == 400
        assert res.json()["detail"] == "Cannot delete admin"


class TestFastAPISessionRoute:
    def test_get_session(self, client, auth_mock, dummy_user, dummy_session):
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")

        # 1. Valid Session
        auth_mock.get_session_from_cookies.return_value = (dummy_session, dummy_user)
        res = client.get("/session")
        assert res.status_code == 200
        assert res.json()["user"]["id"] == dummy_user.id

        # 2. Invalid Session
        auth_mock.get_session_from_cookies.return_value = None
        res = client.get("/session")
        assert res.status_code == 401


class TestFastAPIPlugins:
    def test_plugin_headers_and_cookies(self, client, auth_mock):
        res = client.post("/plugin-complex", json={"dummy": "data"})
        assert res.status_code == 201
        assert res.headers.get("x-custom-header") == "qulf-rocks"
        assert "set-cookie" in res.headers

    def test_plugin_invalid_json_body(self, client):
        # Hits the silent exception catch during `request.json()` logic in plugins
        res = client.put(
            "/plugin-complex",
            content="this-is-not-valid-json",
            headers={"Content-Type": "application/json"},
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


class TestFastAPIDecoratorsAndDependencies:
    def test_rbac_dependencies_all(self, client, auth_mock, dummy_user):
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        auth_mock.get_session_from_cookies.return_value = ("fake_session", dummy_user)

        # Test Roles All
        auth_mock.has_role.side_effect = lambda user, role: True
        assert client.get("/dep-roles-all").status_code == 200
        auth_mock.has_role.side_effect = lambda user, role: role == "admin"
        assert client.get("/dep-roles-all").status_code == 403

        # Test Perms All
        auth_mock.has_permission.side_effect = lambda user, perm: True
        assert client.get("/dep-perms-all").status_code == 200
        auth_mock.has_permission.side_effect = lambda user, perm: perm == "read"
        assert client.get("/dep-perms-all").status_code == 403

    def test_rbac_dependencies_any(self, client, auth_mock, dummy_user):
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
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

    def test_dependencies_unauthenticated(self, client, auth_mock):
        auth_mock.get_session_from_cookies.return_value = None
        assert client.get("/dep-roles-all").status_code == 401
        assert client.get("/dep-perms-all").status_code == 401
        assert client.get("/custom-user").status_code == 401
        assert client.get("/custom-session").status_code == 401

    def test_current_user_and_session_dependencies(
        self, client, auth_mock, dummy_user, dummy_session
    ):
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        auth_mock.get_session_from_cookies.return_value = (dummy_session, dummy_user)

        res_user = client.get("/custom-user")
        assert res_user.status_code == 200
        assert res_user.json()["user_id"] == dummy_user.id

        res_session = client.get("/custom-session")
        assert res_session.status_code == 200
        assert res_session.json()["session_token"] == dummy_session.token
