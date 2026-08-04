"""
Unit tests for PasskeyPlugin (WebAuthn / FIDO2).

All four ``webauthn.*`` library calls are mocked so no real authenticator
hardware or browser is required. The ``MemoryAdapter`` from ``conftest.py``
is reused as the in-memory database backend.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import PasskeyVerificationError
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.passkey import _CHALLENGE_TYPE, PasskeyPlugin
from qulf.types import UserCreate

# Shared constants / helpers
SECRET = "super_secret_test_key_that_is_at_least_32_bytes_long"
RP_ID = "example.com"
RP_NAME = "Test App"
ORIGIN = "https://example.com"

# Fake raw bytes for credentials (arbitrary, deterministic)
FAKE_CHALLENGE = b"\x01\x02\x03\x04"
FAKE_CREDENTIAL_ID = b"\xaa\xbb\xcc\xdd"
FAKE_PUBLIC_KEY = b"\x11\x22\x33\x44"
FAKE_SIGN_COUNT = 1


def _make_plugin(**kwargs: object) -> PasskeyPlugin:
    return PasskeyPlugin(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        origin=ORIGIN,
        **kwargs,  # type: ignore[arg-type]
    )


def _make_options_mock(challenge: bytes) -> MagicMock:
    """Returns a fake PublicKeyCredential*Options object that can JSON-serialize."""
    mock = MagicMock()
    mock.challenge = challenge
    return mock


def _options_json(challenge: bytes) -> str:
    """Fake options_to_json output — just enough for round-trip tests."""
    return json.dumps({"challenge": challenge.hex(), "timeout": 60000})


# Fixtures
@pytest.fixture
def passkey_app(memory_db):
    plugin = _make_plugin()
    config = QulfConfig(secret_key=SECRET)
    auth = Qulf(db=memory_db, config=config, plugins=[plugin])

    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app, raise_server_exceptions=False)
    return app, auth, client, plugin


@pytest.fixture
async def registered_user(passkey_app):
    """Creates a user and injects a fake passkey credential directly."""
    app, auth, client, plugin = passkey_app

    user = await auth.sign_up(
        UserCreate(
            name="Alice",
            email="alice@example.com",
            username="alice",
            password="secret",
            password_confirmation="secret",
        )
    )
    # Inject a fake passkey credential so login_begin / login_complete can proceed
    await auth.db.update_user(
        user.id,
        {
            "passkey_credential_id": FAKE_CREDENTIAL_ID.hex(),
            "passkey_public_key": FAKE_PUBLIC_KEY.hex(),
            "passkey_sign_count": 0,
        },
    )
    return user, auth, client, plugin


# Internal helper tests
def test_encode_decode_challenge_roundtrip(passkey_app):
    _, auth, _, plugin = passkey_app
    token = plugin._encode_challenge(FAKE_CHALLENGE, "42")
    challenge_bytes, user_id = plugin._decode_challenge(token)
    assert challenge_bytes == FAKE_CHALLENGE
    assert user_id == "42"

def test_decode_challenge_expired(passkey_app):
    _, auth, _, plugin = passkey_app
    expired_payload = {
        "type": _CHALLENGE_TYPE,
        "challenge": FAKE_CHALLENGE.hex(),
        "user_id": "1",
        "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
    }
    token = jwt.encode(expired_payload, SECRET, algorithm="HS256")
    with pytest.raises(PasskeyVerificationError, match="expired"):
        plugin._decode_challenge(token)


def test_decode_challenge_wrong_type(passkey_app):
    _, auth, _, plugin = passkey_app
    payload = {
        "type": "wrong_type",
        "challenge": FAKE_CHALLENGE.hex(),
        "user_id": "1",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(PasskeyVerificationError, match="type"):
        plugin._decode_challenge(token)


def test_decode_challenge_invalid_signature(passkey_app):
    _, auth, _, plugin = passkey_app
    payload = {
        "type": _CHALLENGE_TYPE,
        "challenge": FAKE_CHALLENGE.hex(),
        "user_id": "1",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    token = jwt.encode(payload, "wrong-secret-key-that-is-32bytes!!", algorithm="HS256")
    with pytest.raises(PasskeyVerificationError, match="Invalid challenge token"):
        plugin._decode_challenge(token)


def test_get_custom_columns(passkey_app):
    _, _, _, plugin = passkey_app
    cols = plugin.get_custom_columns()
    assert "user" in cols
    assert "passkey_credential_id" in cols["user"]
    assert "passkey_public_key" in cols["user"]
    assert "passkey_sign_count" in cols["user"]

# POST /passkey/register/begin
@pytest.mark.asyncio
async def test_register_begin_requires_auth(passkey_app):
    _, _, client, _ = passkey_app
    # No session cookie
    res = client.post("/passkey/register/begin")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_register_begin_success(passkey_app):
    _, auth, client, _ = passkey_app

    await auth.sign_up(
        UserCreate(
            name="Bob",
            email="bob@example.com",
            username="bob",
            password="pw",
            password_confirmation="pw",
        )
    )
    session = await auth.sign_in("bob@example.com", "pw")
    client.cookies.set("qulf_session", session.token)

    fake_opts = _make_options_mock(FAKE_CHALLENGE)

    with (
        patch("webauthn.generate_registration_options", return_value=fake_opts),
        patch(
            "qulf.plugins.passkey.options_to_json",
            return_value=_options_json(FAKE_CHALLENGE),
        ),
    ):
        res = client.post("/passkey/register/begin")

    assert res.status_code == 200
    body = res.json()
    assert "publicKey" in body
    assert "challenge_token" in body

    # Decode the challenge token and verify it round-trips
    challenge_back = bytes.fromhex(
        jwt.decode(body["challenge_token"], SECRET, algorithms=["HS256"])["challenge"]
    )
    assert challenge_back == FAKE_CHALLENGE


# POST /passkey/register/complete
@pytest.mark.asyncio
async def test_register_complete_no_session(passkey_app):
    _, _, client, _ = passkey_app
    res = client.post(
        "/passkey/register/complete",
        json={"challenge_token": "tok", "credential": {}},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_register_complete_missing_fields(passkey_app):
    _, auth, client, plugin = passkey_app

    await auth.sign_up(
        UserCreate(
            name="Carol",
            email="carol@example.com",
            username="carol",
            password="pw",
            password_confirmation="pw",
        )
    )
    session = await auth.sign_in("carol@example.com", "pw")
    client.cookies.set("qulf_session", session.token)

    # Missing challenge_token
    res = client.post("/passkey/register/complete", json={"credential": {}})
    assert res.status_code == 400
    assert "challenge_token" in res.json()["detail"]

    # Missing credential
    challenge_tok = plugin._encode_challenge(FAKE_CHALLENGE, "1")
    res = client.post(
        "/passkey/register/complete", json={"challenge_token": challenge_tok}
    )
    assert res.status_code == 400
    assert "credential" in res.json()["detail"]


@pytest.mark.asyncio
async def test_register_complete_bad_challenge(passkey_app):
    _, auth, client, _ = passkey_app

    await auth.sign_up(
        UserCreate(
            name="Dave",
            email="dave@example.com",
            username="dave",
            password="pw",
            password_confirmation="pw",
        )
    )
    session = await auth.sign_in("dave@example.com", "pw")
    client.cookies.set("qulf_session", session.token)

    res = client.post(
        "/passkey/register/complete",
        json={"challenge_token": "garbage.token.here", "credential": {"id": "x"}},
    )
    assert res.status_code == 400
    assert "Invalid" in res.json()["detail"]


@pytest.mark.asyncio
async def test_register_complete_verification_fails(passkey_app):
    """webauthn.verify_registration_response raises → 400."""
    _, auth, client, plugin = passkey_app

    user = await auth.sign_up(
        UserCreate(
            name="Eve",
            email="eve@example.com",
            username="eve",
            password="pw",
            password_confirmation="pw",
        )
    )
    session = await auth.sign_in("eve@example.com", "pw")
    client.cookies.set("qulf_session", session.token)

    challenge_tok = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

    from webauthn.helpers.exceptions import InvalidRegistrationResponse

    with patch(
        "webauthn.verify_registration_response",
        side_effect=InvalidRegistrationResponse("bad attestation"),
    ):
        res = client.post(
            "/passkey/register/complete",
            json={"challenge_token": challenge_tok, "credential": {"id": "x"}},
        )
    assert res.status_code == 400
    assert "bad attestation" in res.json()["detail"]


@pytest.mark.asyncio
async def test_register_complete_success(passkey_app):
    """Happy path: attestation verified, credential stored, 201 returned."""
    _, auth, client, plugin = passkey_app

    user = await auth.sign_up(
        UserCreate(
            name="Frank",
            email="frank@example.com",
            username="frank",
            password="pw",
            password_confirmation="pw",
        )
    )
    session = await auth.sign_in("frank@example.com", "pw")
    client.cookies.set("qulf_session", session.token)

    challenge_tok = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

    mock_verified = MagicMock()
    mock_verified.credential_id = FAKE_CREDENTIAL_ID
    mock_verified.credential_public_key = FAKE_PUBLIC_KEY
    mock_verified.sign_count = FAKE_SIGN_COUNT

    with patch("webauthn.verify_registration_response", return_value=mock_verified):
        res = client.post(
            "/passkey/register/complete",
            json={"challenge_token": challenge_tok, "credential": {"id": "x"}},
        )

    assert res.status_code == 201
    assert "registered successfully" in res.json()["message"]

    # Verify the credential was persisted in the DB
    updated = await auth.db.get_user_by_id(user.id)
    assert updated.model_extra["passkey_credential_id"] == FAKE_CREDENTIAL_ID.hex()
    assert updated.model_extra["passkey_public_key"] == FAKE_PUBLIC_KEY.hex()
    assert updated.model_extra["passkey_sign_count"] == FAKE_SIGN_COUNT


# POST /passkey/login/begin
@pytest.mark.asyncio
async def test_login_begin_missing_email(passkey_app):
    _, _, client, _ = passkey_app
    res = client.post("/passkey/login/begin", json={})
    assert res.status_code == 400
    assert "email" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_begin_unknown_email(passkey_app):
    _, _, client, _ = passkey_app
    res = client.post("/passkey/login/begin", json={"email": "ghost@example.com"})
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_login_begin_no_passkey_registered(passkey_app):
    _, auth, client, _ = passkey_app

    await auth.sign_up(
        UserCreate(
            name="Grace",
            email="grace@example.com",
            username="grace",
            password="pw",
            password_confirmation="pw",
        )
    )
    res = client.post("/passkey/login/begin", json={"email": "grace@example.com"})
    assert res.status_code == 400
    assert "No passkey" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_begin_success(registered_user):
    user, auth, client, plugin = registered_user

    fake_opts = _make_options_mock(FAKE_CHALLENGE)

    with (
        patch("webauthn.generate_authentication_options", return_value=fake_opts),
        patch(
            "qulf.plugins.passkey.options_to_json",
            return_value=_options_json(FAKE_CHALLENGE),
        ),
    ):
        res = client.post(
            "/passkey/login/begin", json={"email": "alice@example.com"}
        )

    assert res.status_code == 200
    body = res.json()
    assert "publicKey" in body
    assert "challenge_token" in body


# POST /passkey/login/complete
@pytest.mark.asyncio
async def test_login_complete_missing_fields(passkey_app):
    _, _, client, _ = passkey_app

    res = client.post("/passkey/login/complete", json={"credential": {}})
    assert res.status_code == 400
    assert "challenge_token" in res.json()["detail"]

    res = client.post("/passkey/login/complete", json={"challenge_token": "tok"})
    assert res.status_code == 400
    assert "credential" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_complete_bad_challenge(registered_user):
    user, auth, client, plugin = registered_user

    res = client.post(
        "/passkey/login/complete",
        json={"challenge_token": "garbage", "credential": {"id": "x"}},
    )
    assert res.status_code == 400
    assert "Invalid" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_complete_user_not_found(passkey_app):
    _, auth, client, plugin = passkey_app

    # Craft a challenge token pointing at a non-existent user
    token = plugin._encode_challenge(FAKE_CHALLENGE, "nonexistent-id")
    res = client.post(
        "/passkey/login/complete",
        json={"challenge_token": token, "credential": {"id": "x"}},
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_login_complete_no_passkey_on_user(passkey_app):
    _, auth, client, plugin = passkey_app

    user = await auth.sign_up(
        UserCreate(
            name="Hank",
            email="hank@example.com",
            username="hank",
            password="pw",
            password_confirmation="pw",
        )
    )
    token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)
    res = client.post(
        "/passkey/login/complete",
        json={"challenge_token": token, "credential": {"id": "x"}},
    )
    assert res.status_code == 400
    assert "No passkey" in res.json()["detail"]


@pytest.mark.asyncio
async def test_login_complete_invalid_signature(registered_user):
    """verify_authentication_response raises PasskeyVerificationError → 500."""
    user, auth, client, plugin = registered_user

    token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

    from webauthn.helpers.exceptions import InvalidAuthenticationResponse

    # The route intentionally re-raises PasskeyVerificationError so that
    # framework adapters or middleware can translate it. Via the HTTP client
    # (raise_server_exceptions=False) this surfaces as a 500.
    with patch(
        "webauthn.verify_authentication_response",
        side_effect=InvalidAuthenticationResponse("signature mismatch"),
    ):
        res = client.post(
            "/passkey/login/complete",
            json={"challenge_token": token, "credential": {"id": "x"}},
        )
    assert res.status_code == 500


@pytest.mark.asyncio
async def test_login_complete_success(registered_user):
    """Full happy path: assertion verified → session cookie returned."""
    user, auth, client, plugin = registered_user

    token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

    mock_verified = MagicMock()
    mock_verified.new_sign_count = FAKE_SIGN_COUNT + 1

    with patch("webauthn.verify_authentication_response", return_value=mock_verified):
        res = client.post(
            "/passkey/login/complete",
            json={"challenge_token": token, "credential": {"id": "x"}},
        )

    assert res.status_code == 200
    assert "qulf_session" in res.cookies
    body = res.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "Signed in successfully" in body["message"]

    # Verify sign count was updated
    updated = await auth.db.get_user_by_id(user.id)
    assert updated.model_extra["passkey_sign_count"] == FAKE_SIGN_COUNT + 1
