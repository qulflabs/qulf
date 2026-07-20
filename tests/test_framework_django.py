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

from django.test import RequestFactory

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.django import _get_client_ip, _get_user_agent, serve_qulf
from qulf.routing import CookieOptions, QulfRequest, QulfResponse, QulfRoute


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
# We include 'name' and 'username' to satisfy the internal UserCreate Pydantic model
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

    # Path 1: Not a POST method
    res1 = await sign_up_view(rf.get("/sign-up"))
    assert res1.status_code == 405

    # Path 2: Invalid JSON
    res2 = await sign_up_view(
        rf.post("/sign-up", data="bad-json", content_type="application/json")
    )
    assert res2.status_code == 400

    # Path 3: ValidationError (missing password)
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

    # Path 4: QulfException thrown from core
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
    sign_out_view = urlpatterns[2].callback

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
        QulfRoute(path="/my-plugin", methods=["POST"], handler=dummy_handler)
    ]
    mock_auth.plugins = {"dummy": mock_plugin}

    urlpatterns = serve_qulf(mock_auth)
    plugin_view = urlpatterns[3].callback

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
