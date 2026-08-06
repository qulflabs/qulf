import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from django.test import RequestFactory
from fastapi import FastAPI
from fastapi.testclient import TestClient as FastAPITestClient
from litestar import Litestar
from litestar.testing import TestClient as LitestarTestClient

from qulf.config import EmailHooks
from qulf.core import Qulf, QulfConfig
from qulf.exceptions import QulfException
from qulf.frameworks.django import serve_qulf as django_serve
from qulf.frameworks.fastapi import serve_qulf as fastapi_serve
from qulf.frameworks.litestar import serve_qulf as litestar_serve
from qulf.types import AccountCreate, UserCreate


# CORE ENGINE GAPS
@pytest.mark.asyncio
async def test_core_coverage_gaps(memory_db):
    auth = Qulf(db=memory_db, config=QulfConfig())

    mock_send_verification = AsyncMock()
    auth.config.email_hooks = EmailHooks(send_verification=mock_send_verification)

    await auth.sign_up(
        UserCreate(
            name="A",
            email="a@test.com",
            username="a",
            password="p",
            password_confirmation="p",
        )
    )

    # Triggering the verification hook
    await auth.generate_email_verification_token("a@test.com")

    assert mock_send_verification.called

    # Wrong action in verify_email
    bad_token = jwt.encode(
        {
            "sub": "1",
            "action": "wrong_action",
            "exp": datetime.now(timezone.utc) + timedelta(days=1),
        },
        auth.config.secret_key,
        algorithm="HS256",
    )
    with pytest.raises(QulfException, match="Invalid action"):
        await auth.verify_email(bad_token)

    expired_verify_payload = {
        "sub": "1",
        "action": "verify_email",
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
    }
    expired_verify_token = jwt.encode(
        expired_verify_payload, auth.config.secret_key, algorithm="HS256"
    )
    with pytest.raises(QulfException, match="Token expired"):
        await auth.verify_email(expired_verify_token)


# FASTAPI GAPS
def test_fastapi_coverage_gaps(memory_db):
    auth = Qulf(db=memory_db)
    auth.sign_up = AsyncMock(side_effect=QulfException("Core Error"))
    auth.change_password = AsyncMock(side_effect=QulfException("Core Error"))
    auth.validate_session = AsyncMock(return_value=(MagicMock(), MagicMock(id="1")))

    app = FastAPI()
    app.include_router(fastapi_serve(auth))
    client = FastAPITestClient(app)

    # sign_up exception
    assert (
        client.post(
            "/sign-up",
            json={
                "name": "A",
                "email": "a@a.com",
                "username": "a",
                "password": "p",
                "password_confirmation": "p",
            },
        ).status_code
        == 400
    )

    # change_password exception
    client.cookies.set(auth.config.cookies.name, "fake-token")
    assert (
        client.post(
            "/change-password", json={"old_password": "o", "new_password": "n"}
        ).status_code
        == 400
    )


# LITESTAR GAPS
def test_litestar_coverage_gaps(memory_db):
    auth = Qulf(db=memory_db)
    auth.sign_up = AsyncMock(side_effect=QulfException("Core Error"))
    auth.change_password = AsyncMock(side_effect=QulfException("Core Error"))
    auth.validate_session = AsyncMock(return_value=(MagicMock(), MagicMock(id="1")))

    app = Litestar(route_handlers=[litestar_serve(auth)])
    client = LitestarTestClient(app)

    assert (
        client.post(
            "/sign-up",
            json={
                "name": "A",
                "email": "a@a.com",
                "username": "a",
                "password": "p",
                "password_confirmation": "p",
            },
        ).status_code
        == 400
    )

    client.cookies.set(auth.config.cookies.name, "fake-token")
    assert (
        client.post(
            "/change-password", json={"old_password": "o", "new_password": "n"}
        ).status_code
        == 400
    )


# DJANGO GAPS
@pytest.mark.asyncio
async def test_django_coverage_gaps(memory_db):
    rf = RequestFactory()
    auth = Qulf(db=memory_db)
    auth.sign_up = AsyncMock(side_effect=QulfException("Core Error"))
    auth.change_password = AsyncMock(side_effect=QulfException("Core Error"))
    auth.validate_session = AsyncMock(return_value=(MagicMock(), MagicMock(id="1")))

    urlpatterns = django_serve(auth)
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
        "/change-password",
        data=json.dumps({"old_password": "o", "new_password": "n"}),
        content_type="application/json",
    )
    req2.COOKIES[auth.config.cookies.name] = "fake-token"
    assert (await views["change-password"](req2)).status_code == 400


# SQLMODEL ARTIFACT GAPS
# We repeat the DB creation to force coverage to trace it
@pytest.mark.asyncio
async def test_sqlmodel_artifact_gaps(sqlalchemy_adapter):
    from qulf.adapters.sqlmodel import SQLModelAdapter

    if isinstance(sqlalchemy_adapter, SQLModelAdapter):
        user = await sqlalchemy_adapter.create_user(
            UserCreate(
                name="a",
                email="test@test.com",
                username="u",
                password="p",
                password_confirmation="p",
            ),
            "hash",
        )

        acc_data = AccountCreate(
            user_id=str(user.id),
            provider_id="gh",
            account_id="123",
            access_token="t",
            refresh_token="r",
            expires_at=datetime.now(timezone.utc),
            scope="read",
            id_token="id",
        )

        await sqlalchemy_adapter.create_account(acc_data)
        await sqlalchemy_adapter.get_account_by_provider("gh", "123")


@pytest.mark.asyncio
async def test_framework_auth_helpers_and_forgot_pw(memory_db):
    auth = Qulf(db=memory_db)
    # Mock the token generator to return success safely
    auth.generate_password_reset_token = AsyncMock()

    # FASTAPI
    app_fastapi = FastAPI()
    app_fastapi.include_router(fastapi_serve(auth))
    client_fa = FastAPITestClient(app_fastapi)

    # forgot_password happy path
    res_fa_forgot = client_fa.post("/forgot-password", json={"email": "good@email.com"})
    assert res_fa_forgot.status_code == 200
    assert res_fa_forgot.json() == {"message": "Reset link generated"}

    # auth helper -> No Cookie
    client_fa.cookies.clear()
    assert client_fa.delete("/delete-account").status_code == 401

    # auth helper -> Invalid Session
    auth.validate_session = AsyncMock(return_value=None)
    client_fa.cookies.set(auth.config.cookies.name, "bad")
    assert client_fa.delete("/delete-account").status_code == 401

    # auth helper -> Exception FastAPI specific except block
    auth.validate_session = AsyncMock(side_effect=QulfException("Auth Error"))
    assert client_fa.delete("/delete-account").status_code == 401

    # LITESTAR
    app_litestar = Litestar(route_handlers=[litestar_serve(auth)])
    client_ls = LitestarTestClient(app_litestar)

    # forgot_password happy path
    res_ls_forgot = client_ls.post("/forgot-password", json={"email": "good@email.com"})
    assert res_ls_forgot.status_code == 201
    assert res_ls_forgot.json() == {"message": "Reset link generated"}

    # Hit auth helper -> No Cookie
    client_ls.cookies.clear()
    assert client_ls.delete("/delete-account").status_code == 401

    # auth helper -> Invalid Session
    auth.validate_session = AsyncMock(return_value=None)
    client_ls.cookies.set(auth.config.cookies.name, "bad")
    assert client_ls.delete("/delete-account").status_code == 401

    # DJANGO
    rf = RequestFactory()
    urlpatterns = django_serve(auth)
    views = {
        p.pattern._route: p.callback
        for p in urlpatterns
        if hasattr(p.pattern, "_route")
    }

    # auth helper -> No Cookie
    req_no_auth = rf.post(
        "/change-password",
        data=json.dumps({"old_password": "o", "new_password": "n"}),
        content_type="application/json",
    )
    assert (await views["change-password"](req_no_auth)).status_code == 401

    # auth helper -> Invalid Session
    req_bad_auth = rf.post(
        "/change-password",
        data=json.dumps({"old_password": "o", "new_password": "n"}),
        content_type="application/json",
    )
    req_bad_auth.COOKIES[auth.config.cookies.name] = "bad"
    auth.validate_session = AsyncMock(return_value=None)
    assert (await views["change-password"](req_bad_auth)).status_code == 401
