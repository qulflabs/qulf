import json
from unittest.mock import AsyncMock, MagicMock

import django
import pytest
from django.conf import settings
from django.http import QueryDict

# Ensure Django settings are configured before importing any Django internals!
if not settings.configured:
    settings.configure(DEFAULT_CHARSET="utf-8")
    django.setup()

from django.http import JsonResponse
from django.test import RequestFactory

from qulf import CookieOptions, HttpMethod, QulfRequest, QulfResponse, QulfRoute
from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.django import (
    _get_client_ip,
    _get_user_agent,
    requires_permission,
    requires_role,
    serve_qulf,
)


# IP & User-Agent Helper Tests
# Using DummyRequest ensures MagicMock doesn't trick hasattr()
class DummyRequest:
    pass


def test_get_client_ip() -> None:
    req1 = DummyRequest()
    req1.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
    assert _get_client_ip(req1) == "192.168.1.1"

    req2 = DummyRequest()
    req2.META = {"HTTP_X_FORWARDED_FOR": "10.0.0.2"}
    assert _get_client_ip(req2) == "10.0.0.2"

    req3 = DummyRequest()
    req3.META = {"REMOTE_ADDR": "127.0.0.1"}
    assert _get_client_ip(req3) == "127.0.0.1"

    req4 = DummyRequest()
    assert _get_client_ip(req4) is None


def test_get_user_agent() -> None:
    req1 = DummyRequest()
    req1.headers = {"User-Agent": "TestBrowser/1.0"}
    assert _get_user_agent(req1) == "TestBrowser/1.0"

    req2 = DummyRequest()
    req2.META = {"HTTP_USER_AGENT": "LegacyBrowser/1.0"}
    assert _get_user_agent(req2) == "LegacyBrowser/1.0"

    req3 = DummyRequest()
    assert _get_user_agent(req3) is None


# View Translation Fixtures
@pytest.fixture
def rf() -> RequestFactory:
    return RequestFactory()


@pytest.fixture
def mock_auth() -> MagicMock:
    auth = MagicMock(spec=Qulf)

    auth.config = MagicMock()
    auth.config.cookies.name = "qulf_session"
    auth.config.cookies.http_only = True
    auth.config.cookies.secure = True
    auth.config.cookies.same_site = "lax"

    auth.sign_up = AsyncMock()
    auth.sign_in = AsyncMock()
    auth.sign_out = AsyncMock()
    auth.plugins = {}
    return auth


# Sign-Up View Tests
VALID_USER_PAYLOAD = {
    "email": "test@test.com",
    "name": "Test User",
    "username": "testuser",
    "password": "pwd12345",
    "password_confirmation": "pwd12345",
}


@pytest.mark.asyncio
async def test_sign_up_success(rf: RequestFactory, mock_auth: MagicMock) -> None:
    mock_user = MagicMock()
    mock_user.model_dump.return_value = {
        "id": "123",
        "email": "test@test.com",
        "name": "Test User",
    }
    mock_auth.sign_up.return_value = mock_user

    urlpatterns = serve_qulf(mock_auth)
    sign_up_view = urlpatterns[0].callback

    request = rf.post(
        "/sign-up",
        data=json.dumps(VALID_USER_PAYLOAD),
        content_type="application/json",
    )
    response = await sign_up_view(request)

    assert response.status_code == 200
    assert json.loads(response.content) == {
        "id": "123",
        "email": "test@test.com",
        "name": "Test User",
    }
    mock_auth.sign_up.assert_called_once()


@pytest.mark.asyncio
async def test_sign_up_sad_paths(rf: RequestFactory, mock_auth: MagicMock) -> None:
    urlpatterns = serve_qulf(mock_auth)
    sign_up_view = urlpatterns[0].callback

    # Not a POST method
    res1 = await sign_up_view(rf.get("/sign-up"))
    assert res1.status_code == 405

    # Invalid JSON
    res2 = await sign_up_view(
        rf.post("/sign-up", data="bad-json", content_type="application/json")
    )
    assert res2.status_code == 400

    # ValidationError
    invalid_payload = {
        "email": "test@test.com",
        "name": "Test User",
        "username": "testuser",
    }
    res3 = await sign_up_view(
        rf.post(
            "/sign-up",
            data=json.dumps(invalid_payload),
            content_type="application/json",
        )
    )
    assert res3.status_code == 400

    # QulfException thrown from core
    mock_auth.sign_up.side_effect = QulfException("User already exists")
    res4 = await sign_up_view(
        rf.post(
            "/sign-up",
            data=json.dumps(VALID_USER_PAYLOAD),
            content_type="application/json",
        )
    )
    assert res4.status_code == 400
    assert "User already exists" in json.loads(res4.content)["detail"]


# Sign-In View Tests
@pytest.mark.asyncio
async def test_sign_in_success(rf: RequestFactory, mock_auth: MagicMock) -> None:
    mock_session = MagicMock()
    mock_session.token = "secure-jwt-token"
    mock_auth.sign_in.return_value = mock_session

    urlpatterns = serve_qulf(mock_auth)
    sign_in_view = urlpatterns[1].callback

    request = rf.post(
        "/sign-in",
        data=json.dumps({"email": "test@test.com", "password": "pwd"}),
        content_type="application/json",
    )
    request.META["REMOTE_ADDR"] = "1.1.1.1"
    request.META["HTTP_USER_AGENT"] = "TestAgent"

    response = await sign_in_view(request)

    assert response.status_code == 200
    assert "qulf_session" in response.cookies
    assert response.cookies["qulf_session"].value == "secure-jwt-token"
    assert response.cookies["qulf_session"]["samesite"] == "Lax"


@pytest.mark.asyncio
async def test_sign_in_sad_paths(rf: RequestFactory, mock_auth: MagicMock) -> None:
    urlpatterns = serve_qulf(mock_auth)
    sign_in_view = urlpatterns[1].callback

    res1 = await sign_in_view(rf.get("/sign-in"))
    assert res1.status_code == 405

    mock_auth.sign_in.side_effect = QulfException("Invalid credentials")
    res2 = await sign_in_view(
        rf.post(
            "/sign-in",
            data=json.dumps({"email": "test@test.com", "password": "wrong"}),
            content_type="application/json",
        )
    )
    assert res2.status_code == 400
    assert "Invalid credentials" in json.loads(res2.content)["detail"]


# Sign-Out View Tests
@pytest.mark.asyncio
async def test_sign_out(rf: RequestFactory, mock_auth: MagicMock) -> None:
    urlpatterns = serve_qulf(mock_auth)
    sign_out_view = urlpatterns[3].callback

    assert (await sign_out_view(rf.get("/sign-out"))).status_code == 405

    req = rf.post("/sign-out")
    req.COOKIES["qulf_session"] = "existing-token"
    res = await sign_out_view(req)
    assert res.status_code == 200

    req2 = rf.post("/sign-out")
    await sign_out_view(req2)


# Generic Plugin Adapter Tests
@pytest.mark.asyncio
async def test_plugin_dynamic_routing(rf: RequestFactory, mock_auth: MagicMock) -> None:
    async def dummy_handler(request: QulfRequest) -> QulfResponse:
        return QulfResponse(
            status_code=201,
            body={"echo_body": request.body, "echo_query": request.query_params},
            headers={"X-Custom-Header": "FrameworkAgnostic"},
            set_cookies=[
                CookieOptions(key="plugin_cookie", value="abc", samesite="strict")
            ],
            delete_cookies=["old_cookie"],
        )

    mock_plugin = MagicMock()
    mock_plugin.get_routes.return_value = [
        QulfRoute(path="/my-plugin", methods=[HttpMethod.POST], handler=dummy_handler)
    ]
    mock_auth.plugins = {"dummy": mock_plugin}

    urlpatterns = serve_qulf(mock_auth)
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

    # Test JSON parsing exception swallowing
    req_bad_json = rf.post(
        "/my-plugin", data="bad-json", content_type="application/json"
    )
    req_bad_json.GET = QueryDict()
    res_bad = await plugin_view(req_bad_json)
    assert res_bad.status_code == 201


@pytest.mark.asyncio
async def test_django_account_management_routes(
    rf: RequestFactory, mock_auth: MagicMock
) -> None:
    urlpatterns = serve_qulf(mock_auth)
    # test Django's new routes by mocking the POSTs
    views = {
        p.pattern._route: p.callback
        for p in urlpatterns
        if hasattr(p.pattern, "_route")
    }

    # 1. Happy Paths
    req1 = rf.post(
        "/forgot-password",
        data=json.dumps({"email": "a@a.com"}),
        content_type="application/json",
    )
    assert (await views["forgot-password"](req1)).status_code == 200

    req2 = rf.post(
        "/reset-password",
        data=json.dumps({"token": "t", "new_password": "p"}),
        content_type="application/json",
    )
    assert (await views["reset-password"](req2)).status_code == 200

    req3 = rf.post(
        "/verify-email",
        data=json.dumps({"token": "t"}),
        content_type="application/json",
    )
    assert (await views["verify-email"](req3)).status_code == 200

    # Authenticated Happy Paths
    req4 = rf.post(
        "/change-password",
        data=json.dumps({"old_password": "o", "new_password": "p"}),
        content_type="application/json",
    )
    req4.COOKIES["qulf_session"] = "valid-token"
    mock_auth.validate_session.return_value = (MagicMock(), MagicMock(id="user_1"))
    assert (await views["change-password"](req4)).status_code == 200

    req5 = rf.delete("/delete-account")
    req5.COOKIES["qulf_session"] = "valid-token"
    assert (await views["delete-account"](req5)).status_code == 200

    # 2. Sad Paths
    assert (
        await views["forgot-password"](rf.get("/forgot-password"))
    ).status_code == 405
    assert (await views["reset-password"](rf.get("/reset-password"))).status_code == 405
    assert (await views["verify-email"](rf.get("/verify-email"))).status_code == 405
    assert (
        await views["change-password"](rf.get("/change-password"))
    ).status_code == 405
    assert (
        await views["delete-account"](rf.post("/delete-account"))
    ).status_code == 405

    # Sad path validation
    req_bad = rf.post(
        "/forgot-password", data="bad-json", content_type="application/json"
    )
    assert (await views["forgot-password"](req_bad)).status_code == 400


@pytest.mark.asyncio
async def test_django_core_exceptions(rf: RequestFactory, mock_auth: MagicMock):
    mock_auth.reset_password.side_effect = QulfException("Core Reset Error")
    mock_auth.verify_email.side_effect = QulfException("Core Verify Error")
    mock_auth.change_password.side_effect = QulfException("Core Change Error")
    mock_auth.delete_account.side_effect = QulfException("Core Delete Error")
    mock_auth.validate_session.return_value = (MagicMock(), MagicMock(id="user1"))

    urlpatterns = serve_qulf(mock_auth)
    views = {
        p.pattern._route: p.callback
        for p in urlpatterns
        if hasattr(p.pattern, "_route")
    }
    delete_view = next(
        p.callback
        for p in urlpatterns
        if hasattr(p.pattern, "_route") and "account" in p.pattern._route
    )

    req1 = rf.post(
        "/reset-password",
        data=json.dumps({"token": "t", "new_password": "p"}),
        content_type="application/json",
    )
    assert (await views["reset-password"](req1)).status_code == 400

    req2 = rf.post(
        "/verify-email",
        data=json.dumps({"token": "t"}),
        content_type="application/json",
    )
    assert (await views["verify-email"](req2)).status_code == 400

    req3 = rf.post(
        "/change-password",
        data=json.dumps({"old_password": "o", "new_password": "p"}),
        content_type="application/json",
    )
    req3.COOKIES["qulf_session"] = "valid-token"
    assert (await views["change-password"](req3)).status_code == 400

    req4 = rf.delete("/delete-account")
    req4.COOKIES["qulf_session"] = "valid-token"
    assert (await delete_view(req4)).status_code == 400


@pytest.mark.asyncio
async def test_django_sign_up_sign_in_exceptions(
    rf: RequestFactory, mock_auth: MagicMock
):
    mock_auth.sign_up.side_effect = QulfException("Sign up error")
    mock_auth.sign_in.side_effect = QulfException("Sign in error")

    urlpatterns = serve_qulf(mock_auth)
    views = {
        p.pattern._route: p.callback
        for p in urlpatterns
        if hasattr(p.pattern, "_route")
    }

    req1 = rf.post(
        "/sign-up",
        data=json.dumps(
            {
                "name": "A",
                "email": "a@a.com",
                "username": "a",
                "password": "p",
                "password_confirmation": "p",
            }
        ),
        content_type="application/json",
    )
    assert (await views["sign-up"](req1)).status_code == 400

    req2 = rf.post(
        "/sign-in",
        data=json.dumps({"email": "a@a.com", "password": "p"}),
        content_type="application/json",
    )
    assert (await views["sign-in"](req2)).status_code == 400


@pytest.mark.asyncio
async def test_plugin_dynamic_routing_rbac(
    rf: RequestFactory, mock_auth: MagicMock
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
    mock_auth.plugins = {"dummy": mock_plugin}
    urlpatterns = serve_qulf(mock_auth)
    secure_view = urlpatterns[-1].callback

    req = rf.get("/secure-plugin")

    # 1. Unauthenticated
    mock_auth.get_session_from_cookies.return_value = None
    res1 = await secure_view(req)
    assert res1.status_code == 401

    # 2. Missing Role
    req.COOKIES["qulf_session"] = "token"
    mock_user = MagicMock()
    mock_auth.get_session_from_cookies.return_value = (MagicMock(), mock_user)
    mock_auth.has_role.return_value = False
    res2 = await secure_view(req)
    assert res2.status_code == 403
    assert "role" in json.loads(res2.content)["detail"]

    # 3. Missing Permission
    mock_auth.has_role.return_value = True
    mock_auth.has_permission.return_value = False
    res3 = await secure_view(req)
    assert res3.status_code == 403
    assert "permission" in json.loads(res3.content)["detail"]

    # 4. Success
    mock_auth.has_permission.return_value = True
    res4 = await secure_view(req)
    assert res4.status_code == 200


@pytest.mark.asyncio
async def test_django_requires_role_decorator(rf: RequestFactory, mock_auth: MagicMock):
    @requires_role(mock_auth, "admin")
    async def admin_view(request):
        return JsonResponse({"msg": "ok"})

    @requires_role(mock_auth, ["admin", "editor"], mode="any")
    async def any_role_view(request):
        return JsonResponse({"msg": "ok"})

    req = rf.get("/test")

    # 1. Unauthenticated
    mock_auth.get_session_from_cookies.return_value = None
    assert (await admin_view(req)).status_code == 401

    # 2. Mode ALL - Missing Role
    req.COOKIES["qulf_session"] = "token"
    mock_auth.get_session_from_cookies.return_value = (MagicMock(), MagicMock())
    mock_auth.has_role.return_value = False
    assert (await admin_view(req)).status_code == 403

    # 3. Mode ALL - Success
    mock_auth.has_role.return_value = True
    assert (await admin_view(req)).status_code == 200

    # 4. Mode ANY - Missing Role
    mock_auth.has_role.side_effect = lambda user, role: False
    assert (await any_role_view(req)).status_code == 403

    # 5. Mode ANY - Success
    mock_auth.has_role.side_effect = lambda user, role: role == "editor"
    assert (await any_role_view(req)).status_code == 200


@pytest.mark.asyncio
async def test_django_requires_permission_decorator(
    rf: RequestFactory, mock_auth: MagicMock
):
    @requires_permission(mock_auth, "delete_post")
    async def delete_view(request):
        return JsonResponse({"msg": "ok"})

    @requires_permission(mock_auth, ["write_post", "edit_post"], mode="any")
    async def any_perm_view(request):
        return JsonResponse({"msg": "ok"})

    req = rf.get("/test")

    # Unauthenticated
    mock_auth.get_session_from_cookies.return_value = None
    assert (await delete_view(req)).status_code == 401

    # Mode = ALL - Missing Perm
    req.COOKIES["qulf_session"] = "token"
    mock_auth.get_session_from_cookies.return_value = (MagicMock(), MagicMock())
    mock_auth.has_permission.return_value = False
    assert (await delete_view(req)).status_code == 403

    # Mode = ALL - Success
    mock_auth.has_permission.return_value = True
    assert (await delete_view(req)).status_code == 200

    # Mode = ANY - Missing Perm
    mock_auth.has_permission.side_effect = lambda user, perm: False
    assert (await any_perm_view(req)).status_code == 403

    # Mode = ANY - Success
    mock_auth.has_permission.side_effect = lambda user, perm: perm == "edit_post"
    assert (await any_perm_view(req)).status_code == 200


@pytest.mark.asyncio
async def test_django_current_user_and_session(mock_auth: MagicMock):
    import json
    from datetime import datetime, timezone
    from unittest.mock import AsyncMock

    import pytest
    from django.http import HttpRequest

    from qulf.config import QulfConfig
    from qulf.exceptions import QulfException
    from qulf.frameworks.django import (
        get_current_session,
        get_current_user,
        serve_qulf,
    )
    from qulf.types import Session, User

    mock_auth.config = QulfConfig(secret_key="test_secret_key_needs_to_be_long_enough")
    mock_auth.get_session_from_cookies = AsyncMock()
    mock_auth.plugins = {}

    dummy_user = User(
        id="123",
        email="test@example.com",
        name="Test User",
        username="testuser",
        created_at=datetime.now(timezone.utc),
    )
    dummy_session = Session(
        id="sid_123",
        token="valid_token",
        user_id="123",
        expires_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )

    request = HttpRequest()
    request.method = "GET"
    request.COOKIES = {"qulf_token": "valid"}

    # ---------------------------------------------------------
    # PART A: Test Dependencies (get_current_user / session)
    # ---------------------------------------------------------

    # Valid Session
    mock_auth.get_session_from_cookies.return_value = (dummy_session, dummy_user)
    user_dep = get_current_user(mock_auth)
    user = await user_dep(request)
    assert user.id == dummy_user.id

    session_dep = get_current_session(mock_auth)
    session = await session_dep(request)
    assert session.token == dummy_session.token

    # Invalid Session -> Raises QulfException
    mock_auth.get_session_from_cookies.return_value = None
    with pytest.raises(QulfException, match="Unauthorized"):
        await user_dep(request)
    with pytest.raises(QulfException, match="Unauthorized"):
        await session_dep(request)

    # ---------------------------------------------------------
    # PART B: Test GET /session Route
    # ---------------------------------------------------------
    urls = serve_qulf(mock_auth)
    # Extract the get_session view from urlpatterns
    get_session_view = next(p.callback for p in urls if p.name == "get-session")

    # 1. Valid route
    mock_auth.get_session_from_cookies.return_value = (dummy_session, dummy_user)
    res = await get_session_view(request)
    assert res.status_code == 200
    data = json.loads(res.content)
    assert data["user"]["id"] == dummy_user.id

    # 2. Invalid session (No token or invalid)
    mock_auth.get_session_from_cookies.return_value = None
    res = await get_session_view(request)
    assert res.status_code == 401

    # 3. Wrong HTTP Method
    bad_req = HttpRequest()
    bad_req.method = "POST"
    res = await get_session_view(bad_req)
    assert res.status_code == 405
