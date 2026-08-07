from unittest.mock import MagicMock

import pytest
from litestar import Litestar, get
from litestar.di import NamedDependency, Provide
from litestar.testing import TestClient

from qulf.exceptions import QulfException
from qulf.frameworks.litestar import (
    RequiresPermission,
    RequiresRole,
    get_current_session,
    get_current_user,
    serve_qulf,
)
from qulf.types import Session, User

# REUSABLE TEST VARIABLES
VALID_SIGN_UP_PAYLOAD = {
    "email": "a@b.c",
    "password": "p",
    "password_confirmation": "p",
    "username": "u",
    "name": "n",
}
VALID_SIGN_IN_PAYLOAD = {"email": "a@b.c", "password": "p"}
VALID_CHANGE_PW_PAYLOAD = {"old_password": "o", "new_password": "n"}
VALID_RESET_PW_PAYLOAD = {"token": "tok", "new_password": "p"}
VALID_FORGOT_PW_PAYLOAD = {"email": "a@b.c"}
VALID_VERIFY_EMAIL_PAYLOAD = {"token": "tok"}


# FIXTURES
@pytest.fixture
def app(auth_mock):
    @get(
        "/dep-roles-all",
        dependencies={
            "user": Provide(RequiresRole(auth_mock, ["admin", "editor"], mode="all"))
        },
    )
    async def roles_all_route(user: NamedDependency[User]) -> dict[str, bool]:
        return {"ok": True}

    @get(
        "/dep-roles-any",
        dependencies={
            "user": Provide(RequiresRole(auth_mock, ["admin", "editor"], mode="any"))
        },
    )
    async def roles_any_route(user: NamedDependency[User]) -> dict[str, bool]:
        return {"ok": True}

    @get(
        "/dep-perms-all",
        dependencies={
            "user": Provide(
                RequiresPermission(auth_mock, ["read", "write"], mode="all")
            )
        },
    )
    async def perms_all_route(user: NamedDependency[User]) -> dict[str, bool]:
        return {"ok": True}

    @get(
        "/dep-perms-any",
        dependencies={
            "user": Provide(
                RequiresPermission(auth_mock, ["read", "write"], mode="any")
            )
        },
    )
    async def perms_any_route(user: NamedDependency[User]) -> dict[str, bool]:
        return {"ok": True}

    @get("/custom-user", dependencies={"user": Provide(get_current_user(auth_mock))})
    async def custom_user_route(user: NamedDependency[User]) -> dict[str, str]:
        return {"user_id": str(user.id)}

    @get(
        "/custom-session",
        dependencies={"session": Provide(get_current_session(auth_mock))},
    )
    async def custom_session_route(session: NamedDependency[Session]) -> dict[str, str]:
        return {"session_token": session.token}

    return Litestar(
        route_handlers=[
            serve_qulf(auth_mock),
            roles_all_route,
            roles_any_route,
            perms_all_route,
            perms_any_route,
            custom_user_route,
            custom_session_route,
        ]
    )


@pytest.fixture
def client(app):
    return TestClient(app=app)


# TEST SUITES
class TestLitestarAuthEndpoints:
    def test_sign_up(self, client: TestClient, auth_mock: MagicMock, dummy_user: User):
        auth_mock.sign_up.return_value = dummy_user
        res = client.post("/sign-up", json=VALID_SIGN_UP_PAYLOAD)
        assert res.status_code == 201

        auth_mock.sign_up.side_effect = QulfException("Bad Data")
        res = client.post("/sign-up", json=VALID_SIGN_UP_PAYLOAD)
        assert res.status_code == 400

    def test_sign_in(
        self, client: TestClient, auth_mock: MagicMock, dummy_session: Session
    ):
        auth_mock.sign_in.return_value = dummy_session
        res = client.post("/sign-in", json=VALID_SIGN_IN_PAYLOAD)
        assert res.status_code == 200
        assert "set-cookie" in res.headers

        auth_mock.sign_in.side_effect = QulfException("Invalid credentials")
        res = client.post("/sign-in", json=VALID_SIGN_IN_PAYLOAD)
        assert res.status_code == 400

    def test_sign_out(self, client: TestClient, auth_mock: MagicMock):
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        res = client.post("/sign-out")
        assert res.status_code == 200

        client.cookies.clear()
        res = client.post("/sign-out")
        assert res.status_code == 200

    def test_change_password(
        self,
        client: TestClient,
        auth_mock: MagicMock,
        dummy_session: Session,
        dummy_user: User,
    ):
        # 1. Valid Session (Hits the `if validated_session:` block)
        auth_mock.validate_session.return_value = (dummy_session, dummy_user)
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        res = client.post("/change-password", json=VALID_CHANGE_PW_PAYLOAD)
        assert res.status_code == 200

        # 2. Exception from Core Engine
        auth_mock.change_password.side_effect = QulfException("Wrong old password")
        res = client.post("/change-password", json=VALID_CHANGE_PW_PAYLOAD)
        assert res.status_code == 400
        auth_mock.change_password.side_effect = None

        # 3. Invalid Session - Missing Token (Hits `if not token:` block)
        client.cookies.clear()
        res = client.post("/change-password", json=VALID_CHANGE_PW_PAYLOAD)
        assert res.status_code == 401

        # 4. Invalid Session - Bad Token (Hits the final `raise QulfException` block)
        client.cookies.set(auth_mock.config.cookies.name, "bad_token")
        auth_mock.validate_session.return_value = None
        res = client.post("/change-password", json=VALID_CHANGE_PW_PAYLOAD)
        assert res.status_code == 401

    def test_forgot_password(self, client: TestClient, auth_mock: MagicMock):
        auth_mock.generate_password_reset_token.return_value = None
        res = client.post("/forgot-password", json=VALID_FORGOT_PW_PAYLOAD)
        assert res.status_code == 200

        auth_mock.generate_password_reset_token.side_effect = QulfException("Error")
        res = client.post("/forgot-password", json=VALID_FORGOT_PW_PAYLOAD)
        assert res.status_code == 400

    def test_reset_password(self, client: TestClient, auth_mock: MagicMock):
        auth_mock.reset_password.return_value = None
        res = client.post("/reset-password", json=VALID_RESET_PW_PAYLOAD)
        assert res.status_code == 200

        auth_mock.reset_password.side_effect = QulfException("Error")
        res = client.post("/reset-password", json=VALID_RESET_PW_PAYLOAD)
        assert res.status_code == 400

    def test_verify_email(self, client: TestClient, auth_mock: MagicMock):
        auth_mock.verify_email.return_value = None
        res = client.post("/verify-email", json=VALID_VERIFY_EMAIL_PAYLOAD)
        assert res.status_code == 200

        auth_mock.verify_email.side_effect = QulfException("Error")
        res = client.post("/verify-email", json=VALID_VERIFY_EMAIL_PAYLOAD)
        assert res.status_code == 400

    def test_delete_account(
        self,
        client: TestClient,
        auth_mock: MagicMock,
        dummy_session: Session,
        dummy_user: User,
    ):
        auth_mock.validate_session.return_value = (dummy_session, dummy_user)
        client.cookies.set(auth_mock.config.cookies.name, "valid_token")
        auth_mock.delete_account.return_value = None
        res = client.delete("/delete-account")
        assert res.status_code == 200

        auth_mock.delete_account.side_effect = QulfException("Cannot delete admin")
        res = client.delete("/delete-account")
        assert res.status_code == 400
        auth_mock.delete_account.side_effect = None

        client.cookies.clear()
        res = client.delete("/delete-account")
        assert res.status_code == 401

        client.cookies.set(auth_mock.config.cookies.name, "bad_token")
        auth_mock.validate_session.return_value = None
        res = client.delete("/delete-account")
        assert res.status_code == 401


class TestLitestarSessionRoute:
    def test_get_session(
        self,
        client: TestClient,
        auth_mock: MagicMock,
        dummy_user: User,
        dummy_session: Session,
    ):
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


class TestLitestarPlugins:
    def test_plugin_headers_and_cookies(self, client: TestClient):
        res = client.post("/plugin-complex", json={"dummy": "data"})
        assert res.status_code == 201
        assert res.headers.get("x-custom-header") == "qulf-rocks"
        assert "set-cookie" in res.headers

    def test_plugin_invalid_json_body(self, client):
        res = client.post(
            "/plugin-complex",
            content=b"this-is-not-valid-json",
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


class TestLitestarDecoratorsAndDependencies:
    def test_rbac_dependencies_all(
        self, client: TestClient, auth_mock: MagicMock, dummy_user: User
    ):
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
