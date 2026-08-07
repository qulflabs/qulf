import json
from typing import Any
from unittest.mock import MagicMock

import django
import pytest
from django.conf import settings
from django.http import JsonResponse, QueryDict

# Ensure Django settings are configured before importing any Django internals.
if not settings.configured:
    settings.configure(DEFAULT_CHARSET="utf-8")
    django.setup()

from django.test import RequestFactory

from qulf import CookieOptions, HttpMethod, QulfRequest, QulfResponse, QulfRoute
from qulf.exceptions import QulfException
from qulf.frameworks.django import (
    _get_client_ip,
    _get_user_agent,
    get_current_session,
    get_current_user,
    requires_permission,
    requires_role,
    serve_qulf,
)

# ==========================================
# REUSABLE TEST VARIABLES
# ==========================================
VALID_SIGN_UP_PAYLOAD = {
    "email": "test@test.com",
    "name": "Test User",
    "username": "testuser",
    "password": "pwd12345",
    "password_confirmation": "pwd12345",
}
VALID_SIGN_IN_PAYLOAD = {"email": "test@test.com", "password": "pwd12345"}
VALID_CHANGE_PW_PAYLOAD = {"old_password": "o", "new_password": "p"}
VALID_RESET_PW_PAYLOAD = {"token": "t", "new_password": "p"}
VALID_FORGOT_PW_PAYLOAD = {"email": "a@a.com"}
VALID_VERIFY_EMAIL_PAYLOAD = {"token": "t"}


# ==========================================
# FIXTURES
# ==========================================
@pytest.fixture
def rf() -> RequestFactory:
    return RequestFactory()


@pytest.fixture
def django_views(auth_mock: MagicMock) -> dict[str, Any]:
    urlpatterns = serve_qulf(auth_mock)
    return {
        p.pattern._route: p.callback
        for p in urlpatterns
        if hasattr(p.pattern, "_route")
    }


class DummyRequest:
    pass


# TEST SUITES
class TestDjangoHelpers:
    def test_get_client_ip(self) -> None:
        # Standard Forwarded
        req1 = DummyRequest()
        req1.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        assert _get_client_ip(req1) == "192.168.1.1"

        # Headers exist, but X-Forwarded-For is missing (Falls back to META)
        req_no_xfwd = DummyRequest()
        req_no_xfwd.headers = {"Other": "Value"}
        req_no_xfwd.META = {"REMOTE_ADDR": "10.0.0.5"}
        assert _get_client_ip(req_no_xfwd) == "10.0.0.5"

        # Standard META HTTP_X_FORWARDED_FOR
        req2 = DummyRequest()
        req2.META = {"HTTP_X_FORWARDED_FOR": "10.0.0.2"}
        assert _get_client_ip(req2) == "10.0.0.2"

        # Empty string in META (Falls back to REMOTE_ADDR)
        req_empty_xfwd = DummyRequest()
        req_empty_xfwd.META = {
            "HTTP_X_FORWARDED_FOR": "",
            "REMOTE_ADDR": "192.168.1.200",
        }
        assert _get_client_ip(req_empty_xfwd) == "192.168.1.200"

        # Invalid type in META (Falls back to REMOTE_ADDR)
        req_bad_type = DummyRequest()
        req_bad_type.META = {
            "HTTP_X_FORWARDED_FOR": ["10.0.0.2"],
            "REMOTE_ADDR": "192.168.1.100",
        }
        assert _get_client_ip(req_bad_type) == "192.168.1.100"

        # No headers, empty META
        req4 = DummyRequest()
        req4.META = {}
        assert _get_client_ip(req4) is None

    def test_get_user_agent(self) -> None:
        # Standard Header
        req1 = DummyRequest()
        req1.headers = {"User-Agent": "TestBrowser/1.0"}
        assert _get_user_agent(req1) == "TestBrowser/1.0"

        # Headers exist, but User-Agent is missing
        req_no_ua = DummyRequest()
        req_no_ua.headers = {"Other": "yes"}
        assert _get_user_agent(req_no_ua) is None

        # Standard META
        req2 = DummyRequest()
        req2.META = {"HTTP_USER_AGENT": "LegacyBrowser/1.0"}
        assert _get_user_agent(req2) == "LegacyBrowser/1.0"

        # No headers, empty META
        req3 = DummyRequest()
        req3.META = {}
        assert _get_user_agent(req3) is None

    def test_helpers_no_attributes_at_all(self) -> None:
        bare_req = DummyRequest()

        assert _get_client_ip(bare_req) is None
        assert _get_user_agent(bare_req) is None


@pytest.mark.asyncio
class TestDjangoAuthEndpoints:
    async def test_sign_up(
        self,
        rf: RequestFactory,
        auth_mock: MagicMock,
        dummy_user: MagicMock,
        django_views: dict[str, Any],
    ) -> None:
        view = django_views["sign-up"]

        auth_mock.sign_up.return_value = dummy_user
        req = rf.post(
            "/sign-up",
            data=json.dumps(VALID_SIGN_UP_PAYLOAD),
            content_type="application/json",
        )
        res = await view(req)

        assert res.status_code == 200
        assert json.loads(res.content)["id"] == "123"
        assert (await view(rf.get("/sign-up"))).status_code == 405
        assert (
            await view(
                rf.post("/sign-up", data="bad-json", content_type="application/json")
            )
        ).status_code == 400

        auth_mock.sign_up.side_effect = QulfException("User already exists")
        res_exc = await view(
            rf.post(
                "/sign-up",
                data=json.dumps(VALID_SIGN_UP_PAYLOAD),
                content_type="application/json",
            )
        )
        assert res_exc.status_code == 400
        assert "User already exists" in json.loads(res_exc.content)["detail"]

    async def test_sign_in(
        self,
        rf: RequestFactory,
        auth_mock: MagicMock,
        dummy_session: MagicMock,
        django_views: dict[str, Any],
    ) -> None:
        view = django_views["sign-in"]

        auth_mock.sign_in.return_value = dummy_session
        req = rf.post(
            "/sign-in",
            data=json.dumps(VALID_SIGN_IN_PAYLOAD),
            content_type="application/json",
        )
        req.META["REMOTE_ADDR"] = "1.1.1.1"
        req.META["HTTP_USER_AGENT"] = "TestAgent"

        res = await view(req)
        assert res.status_code == 200
        assert "qulf_session" in res.cookies
        assert res.cookies["qulf_session"].value == dummy_session.token

        assert (await view(rf.get("/sign-in"))).status_code == 405

        auth_mock.sign_in.side_effect = QulfException("Invalid credentials")
        res_exc = await view(
            rf.post(
                "/sign-in",
                data=json.dumps(VALID_SIGN_IN_PAYLOAD),
                content_type="application/json",
            )
        )
        assert res_exc.status_code == 400

    async def test_sign_in_no_samesite(
        self,
        rf: RequestFactory,
        auth_mock: MagicMock,
        dummy_session: MagicMock,
        django_views: dict[str, Any],
    ) -> None:
        auth_mock.config.cookies.same_site = None
        auth_mock.sign_in.return_value = dummy_session
        view = django_views["sign-in"]

        req = rf.post(
            "/sign-in",
            data=json.dumps(VALID_SIGN_IN_PAYLOAD),
            content_type="application/json",
        )
        res = await view(req)

        assert res.status_code == 200
        assert res.cookies["qulf_session"]["samesite"] == "Lax"

    async def test_sign_out(
        self, rf: RequestFactory, django_views: dict[str, Any]
    ) -> None:
        view = django_views["sign-out"]

        assert (await view(rf.get("/sign-out"))).status_code == 405

        req = rf.post("/sign-out")
        req.COOKIES["qulf_session"] = "existing-token"
        assert (await view(req)).status_code == 200

        req_no_cookie = rf.post("/sign-out")
        assert (await view(req_no_cookie)).status_code == 200

    async def test_forgot_password(
        self, rf: RequestFactory, django_views: dict[str, Any]
    ) -> None:
        view = django_views["forgot-password"]

        req = rf.post(
            "/forgot-password",
            data=json.dumps(VALID_FORGOT_PW_PAYLOAD),
            content_type="application/json",
        )
        assert (await view(req)).status_code == 200
        assert (await view(rf.get("/forgot-password"))).status_code == 405

        req_bad = rf.post(
            "/forgot-password", data="bad-json", content_type="application/json"
        )
        assert (await view(req_bad)).status_code == 400

    async def test_reset_password(
        self, rf: RequestFactory, django_views: dict[str, Any]
    ) -> None:
        view = django_views["reset-password"]

        req = rf.post(
            "/reset-password",
            data=json.dumps(VALID_RESET_PW_PAYLOAD),
            content_type="application/json",
        )
        assert (await view(req)).status_code == 200
        assert (await view(rf.get("/reset-password"))).status_code == 405

    async def test_verify_email(
        self, rf: RequestFactory, django_views: dict[str, Any]
    ) -> None:
        view = django_views["verify-email"]

        req = rf.post(
            "/verify-email",
            data=json.dumps(VALID_VERIFY_EMAIL_PAYLOAD),
            content_type="application/json",
        )
        assert (await view(req)).status_code == 200
        assert (await view(rf.get("/verify-email"))).status_code == 405

    async def test_change_password(
        self, rf: RequestFactory, auth_mock: MagicMock, django_views: dict[str, Any]
    ) -> None:
        view = django_views["change-password"]

        # Valid Request
        req = rf.post(
            "/change-password",
            data=json.dumps(VALID_CHANGE_PW_PAYLOAD),
            content_type="application/json",
        )
        req.COOKIES["qulf_session"] = "valid-token"
        auth_mock.validate_session.return_value = (MagicMock(), MagicMock(id="user_1"))
        assert (await view(req)).status_code == 200

        # Method Not Allowed
        assert (await view(rf.get("/change-password"))).status_code == 405

        # Missing Token
        req_missing = rf.post(
            "/change-password",
            data=json.dumps(VALID_CHANGE_PW_PAYLOAD),
            content_type="application/json",
        )
        assert (await view(req_missing)).status_code == 401

        # Invalid Token
        req_invalid = rf.post(
            "/change-password",
            data=json.dumps(VALID_CHANGE_PW_PAYLOAD),
            content_type="application/json",
        )
        req_invalid.COOKIES["qulf_session"] = "bad-token"
        auth_mock.validate_session.return_value = None
        assert (await view(req_invalid)).status_code == 401

    async def test_delete_account(
        self, rf: RequestFactory, auth_mock: MagicMock, django_views: dict[str, Any]
    ) -> None:
        view = django_views["delete-account"]

        # Valid Request
        req = rf.delete("/delete-account")
        req.COOKIES["qulf_session"] = "valid-token"
        auth_mock.validate_session.return_value = (MagicMock(), MagicMock(id="user_1"))
        assert (await view(req)).status_code == 200

        # Method Not Allowed
        assert (await view(rf.post("/delete-account"))).status_code == 405

        # Missing Token
        req_missing = rf.delete("/delete-account")
        assert (await view(req_missing)).status_code == 401

        # Invalid Token
        req_invalid = rf.delete("/delete-account")
        req_invalid.COOKIES["qulf_session"] = "bad-token"
        auth_mock.validate_session.return_value = None
        assert (await view(req_invalid)).status_code == 401

    async def test_django_core_exceptions(
        self, rf: RequestFactory, auth_mock: MagicMock, django_views: dict[str, Any]
    ) -> None:
        auth_mock.reset_password.side_effect = QulfException("Core Reset Error")
        auth_mock.verify_email.side_effect = QulfException("Core Verify Error")
        auth_mock.change_password.side_effect = QulfException("Core Change Error")
        auth_mock.delete_account.side_effect = QulfException("Core Delete Error")
        auth_mock.validate_session.return_value = (MagicMock(), MagicMock(id="user1"))

        req1 = rf.post(
            "/reset-password",
            data=json.dumps(VALID_RESET_PW_PAYLOAD),
            content_type="application/json",
        )
        assert (await django_views["reset-password"](req1)).status_code == 400

        req2 = rf.post(
            "/verify-email",
            data=json.dumps(VALID_VERIFY_EMAIL_PAYLOAD),
            content_type="application/json",
        )
        assert (await django_views["verify-email"](req2)).status_code == 400

        req3 = rf.post(
            "/change-password",
            data=json.dumps(VALID_CHANGE_PW_PAYLOAD),
            content_type="application/json",
        )
        req3.COOKIES["qulf_session"] = "valid-token"
        assert (await django_views["change-password"](req3)).status_code == 400

        req4 = rf.delete("/delete-account")
        req4.COOKIES["qulf_session"] = "valid-token"
        assert (await django_views["delete-account"](req4)).status_code == 400

    async def test_django_sign_up_sign_in_exceptions(
        self, rf: RequestFactory, auth_mock: MagicMock, django_views: dict[str, Any]
    ) -> None:
        auth_mock.sign_up.side_effect = QulfException("Sign up error")
        auth_mock.sign_in.side_effect = QulfException("Sign in error")

        req1 = rf.post(
            "/sign-up",
            data=json.dumps(VALID_SIGN_UP_PAYLOAD),
            content_type="application/json",
        )
        assert (await django_views["sign-up"](req1)).status_code == 400

        req2 = rf.post(
            "/sign-in",
            data=json.dumps(VALID_SIGN_IN_PAYLOAD),
            content_type="application/json",
        )
        assert (await django_views["sign-in"](req2)).status_code == 400

        # Trigger ValidationError with incomplete dict payloads
        req3 = rf.post(
            "/sign-up",
            data=json.dumps({"email": "incomplete"}),
            content_type="application/json",
        )
        assert (await django_views["sign-up"](req3)).status_code == 400

        req4 = rf.post(
            "/sign-in",
            data=json.dumps({"email": "incomplete"}),
            content_type="application/json",
        )
        assert (await django_views["sign-in"](req4)).status_code == 400


@pytest.mark.asyncio
class TestDjangoPlugins:
    async def test_plugin_dynamic_routing(
        self, rf: RequestFactory, auth_mock: MagicMock
    ) -> None:
        async def dummy_handler(request: QulfRequest) -> QulfResponse:
            return QulfResponse(
                status_code=201,
                body={"echo_body": request.body, "echo_query": request.query_params},
                headers={"X-Custom-Header": "FrameworkAgnostic"},
                set_cookies=[
                    CookieOptions(key="plugin_cookie", value="abc", samesite="strict"),
                    CookieOptions(key="plugin_cookie_2", value="xyz", samesite="none"),
                ],
                delete_cookies=["old_cookie"],
            )

        mock_plugin = MagicMock()
        mock_plugin.get_routes.return_value = [
            QulfRoute(
                path="/my-plugin", methods=[HttpMethod.POST], handler=dummy_handler
            )
        ]
        auth_mock.plugins = {"dummy": mock_plugin}

        urlpatterns = serve_qulf(auth_mock)
        plugin_view = urlpatterns[-1].callback

        request = rf.post(
            "/my-plugin?test=123",
            data=json.dumps({"hello": "world"}),
            content_type="application/json",
        )

        qd = QueryDict(mutable=True)
        qd.update({"test": "123"})
        request.GET = qd

        response = await plugin_view(request)

        assert response.status_code == 201

        content = json.loads(response.content)
        assert content["echo_body"] == {"hello": "world"}
        assert content["echo_query"] == {"test": "123"}
        assert response["X-Custom-Header"] == "FrameworkAgnostic"
        assert "plugin_cookie" in response.cookies
        assert "plugin_cookie_2" in response.cookies

        req_bad_json = rf.post(
            "/my-plugin", data="bad-json", content_type="application/json"
        )
        req_bad_json.GET = QueryDict()
        res_bad = await plugin_view(req_bad_json)
        assert res_bad.status_code == 201

    async def test_plugin_dynamic_routing_rbac(
        self, rf: RequestFactory, auth_mock: MagicMock, dummy_user: MagicMock
    ) -> None:
        async def dummy_handler(request: QulfRequest) -> QulfResponse:
            return QulfResponse(status_code=200, body={"msg": "ok"})

        mock_plugin = MagicMock()
        mock_plugin.get_routes.return_value = [
            QulfRoute(
                path="/secure-plugin",
                methods=[HttpMethod.GET],
                handler=dummy_handler,
                require_roles=["admin"],
                require_permissions=["read_post"],
            )
        ]
        auth_mock.plugins = {"dummy": mock_plugin}
        urlpatterns = serve_qulf(auth_mock)
        secure_view = urlpatterns[-1].callback

        req = rf.get("/secure-plugin")

        auth_mock.get_session_from_cookies.return_value = None
        assert (await secure_view(req)).status_code == 401

        req.COOKIES["qulf_session"] = "token"
        auth_mock.get_session_from_cookies.return_value = (MagicMock(), dummy_user)
        auth_mock.has_role.return_value = False
        res2 = await secure_view(req)
        assert res2.status_code == 403
        assert "role" in json.loads(res2.content)["detail"]

        auth_mock.has_role.return_value = True
        auth_mock.has_permission.return_value = False
        res3 = await secure_view(req)
        assert res3.status_code == 403
        assert "permission" in json.loads(res3.content)["detail"]

        auth_mock.has_permission.return_value = True
        assert (await secure_view(req)).status_code == 200


@pytest.mark.asyncio
class TestDjangoDecoratorsAndDependencies:
    async def test_requires_role_decorator(
        self, rf: RequestFactory, auth_mock: MagicMock, dummy_user: MagicMock
    ) -> None:
        @requires_role(auth_mock, "admin")
        async def admin_view(request):
            return JsonResponse({"msg": "ok"})

        @requires_role(auth_mock, ["admin", "editor"], mode="any")
        async def any_role_view(request):
            return JsonResponse({"msg": "ok"})

        req = rf.get("/test")

        auth_mock.get_session_from_cookies.return_value = None
        assert (await admin_view(req)).status_code == 401

        req.COOKIES["qulf_session"] = "token"
        auth_mock.get_session_from_cookies.return_value = (MagicMock(), dummy_user)
        auth_mock.has_role.return_value = False
        assert (await admin_view(req)).status_code == 403

        auth_mock.has_role.return_value = True
        assert (await admin_view(req)).status_code == 200

        auth_mock.has_role.side_effect = lambda user, role: False
        assert (await any_role_view(req)).status_code == 403

        auth_mock.has_role.side_effect = lambda user, role: role == "editor"
        assert (await any_role_view(req)).status_code == 200

    async def test_requires_permission_decorator(
        self, rf: RequestFactory, auth_mock: MagicMock, dummy_user: MagicMock
    ) -> None:
        @requires_permission(auth_mock, "delete_post")
        async def delete_view(request):
            return JsonResponse({"msg": "ok"})

        @requires_permission(auth_mock, ["write_post", "edit_post"], mode="any")
        async def any_perm_view(request):
            return JsonResponse({"msg": "ok"})

        req = rf.get("/test")

        auth_mock.get_session_from_cookies.return_value = None
        assert (await delete_view(req)).status_code == 401

        req.COOKIES["qulf_session"] = "token"
        auth_mock.get_session_from_cookies.return_value = (MagicMock(), dummy_user)
        auth_mock.has_permission.return_value = False
        assert (await delete_view(req)).status_code == 403

        auth_mock.has_permission.return_value = True
        assert (await delete_view(req)).status_code == 200

        auth_mock.has_permission.side_effect = lambda user, perm: False
        assert (await any_perm_view(req)).status_code == 403

        auth_mock.has_permission.side_effect = lambda user, perm: perm == "edit_post"
        assert (await any_perm_view(req)).status_code == 200

    async def test_current_user_and_session_dependencies(
        self,
        rf: RequestFactory,
        auth_mock: MagicMock,
        dummy_user: MagicMock,
        dummy_session: MagicMock,
    ) -> None:
        req = rf.get("/test")
        req.COOKIES["qulf_session"] = "valid"

        auth_mock.get_session_from_cookies.return_value = (dummy_session, dummy_user)
        user_dep = get_current_user(auth_mock)
        user = await user_dep(req)
        assert user.id == dummy_user.id

        session_dep = get_current_session(auth_mock)
        session = await session_dep(req)
        assert session.token == dummy_session.token

        auth_mock.get_session_from_cookies.return_value = None
        with pytest.raises(QulfException, match="Unauthorized"):
            await user_dep(req)
        with pytest.raises(QulfException, match="Unauthorized"):
            await session_dep(req)


@pytest.mark.asyncio
class TestDjangoSessionRoute:
    async def test_get_session_route(
        self,
        rf: RequestFactory,
        auth_mock: MagicMock,
        dummy_user: MagicMock,
        dummy_session: MagicMock,
        django_views: dict[str, Any],
    ) -> None:
        view = django_views["session"]

        req = rf.get("/session")
        req.COOKIES["qulf_session"] = "valid"

        auth_mock.get_session_from_cookies.return_value = (dummy_session, dummy_user)
        res = await view(req)
        assert res.status_code == 200
        assert json.loads(res.content)["user"]["id"] == dummy_user.id

        auth_mock.get_session_from_cookies.return_value = None
        res2 = await view(req)
        assert res2.status_code == 401

        bad_req = rf.post("/session")
        res3 = await view(bad_req)
        assert res3.status_code == 405
