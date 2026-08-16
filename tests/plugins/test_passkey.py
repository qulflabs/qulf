"""
Unit tests for PasskeyPlugin (WebAuthn / FIDO2) — multi-passkey support.

All four ``webauthn.*`` library calls are mocked so no real authenticator
hardware or browser is required. The ``MemoryAdapter`` from ``conftest.py``
is reused as the in-memory database backend.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from webauthn.helpers.exceptions import InvalidRegistrationResponse

from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.exceptions import PasskeyVerificationError, QulfException
from qulf.frameworks.fastapi import serve_qulf
from qulf.plugins.passkey import _CHALLENGE_TYPE, PasskeyPlugin
from qulf.types import PasskeyCredentialCreate, User, UserCreate

SECRET = "super_secret_test_key_that_is_at_least_32_bytes_long"
RP_ID = "example.com"
RP_NAME = "Test App"
ORIGIN = "https://example.com"

FAKE_CHALLENGE = b"\x01\x02\x03\x04"
FAKE_CREDENTIAL_ID = b"\xaa\xbb\xcc\xdd"
FAKE_CREDENTIAL_ID_2 = b"\x11\x22\x33\x44"
FAKE_PUBLIC_KEY = b"\x55\x66\x77\x88"
FAKE_PUBLIC_KEY_2 = b"\x99\xaa\xbb\xcc"
FAKE_SIGN_COUNT = 1


def _make_plugin(**kwargs: Any) -> PasskeyPlugin:
    return PasskeyPlugin(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        origin=ORIGIN,
        **kwargs,
    )


def _make_options_mock(challenge: bytes) -> MagicMock:
    mock = MagicMock()
    mock.challenge = challenge
    return mock


def _options_json(challenge: bytes) -> str:
    return json.dumps({"challenge": challenge.hex(), "timeout": 60000})


@pytest.fixture
def passkey_app(memory_db: Any) -> tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]:
    plugin = _make_plugin()
    config = QulfConfig(secret_key=SECRET)
    auth = Qulf(db=memory_db, config=config, plugins=[plugin])

    app = FastAPI()
    app.include_router(serve_qulf(auth))
    client = TestClient(app, raise_server_exceptions=False)
    return app, auth, client, plugin


@pytest.fixture
async def registered_user(
    passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin],
) -> tuple[User, Qulf, TestClient, PasskeyPlugin]:
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

    # Register the first passkey via the adapter directly (bypassing the HTTP layer).
    await auth.db.create_passkey(
        PasskeyCredentialCreate(
            user_id=user.id,
            credential_id=FAKE_CREDENTIAL_ID.hex(),
            public_key=FAKE_PUBLIC_KEY.hex(),
            sign_count=0,
            name="Alice's MacBook",
        )
    )
    return user, auth, client, plugin


class TestPasskeyInternalHelpers:
    def test_encode_decode_challenge_roundtrip(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, auth, _, plugin = passkey_app
        token = plugin._encode_challenge(FAKE_CHALLENGE, "42")
        challenge_bytes, user_id = plugin._decode_challenge(token)
        assert challenge_bytes == FAKE_CHALLENGE
        assert user_id == "42"

    def test_decode_challenge_expired(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

    def test_decode_challenge_wrong_type(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

    def test_decode_challenge_invalid_signature(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, auth, _, plugin = passkey_app
        payload = {
            "type": _CHALLENGE_TYPE,
            "challenge": FAKE_CHALLENGE.hex(),
            "user_id": "1",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
        token = jwt.encode(
            payload, "wrong-secret-key-that-is-32bytes!!", algorithm="HS256"
        )
        with pytest.raises(PasskeyVerificationError, match="Invalid challenge token"):
            plugin._decode_challenge(token)

    def test_get_custom_columns_returns_empty(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        """Columns are not injected into user table; passkeys have their own table."""
        _, _, _, plugin = passkey_app
        cols = plugin.get_custom_columns()
        assert cols == {}


@pytest.mark.asyncio
class TestPasskeyRegisterBegin:
    async def test_register_begin_requires_auth(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, _, client, _ = passkey_app
        res = client.post("/passkey/register/begin")
        assert res.status_code == 401

    async def test_register_begin_success(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

        challenge_back = bytes.fromhex(
            jwt.decode(body["challenge_token"], SECRET, algorithms=["HS256"])[
                "challenge"
            ]
        )
        assert challenge_back == FAKE_CHALLENGE


@pytest.mark.asyncio
class TestPasskeyRegisterComplete:
    async def test_register_complete_no_session(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, _, client, _ = passkey_app
        res = client.post(
            "/passkey/register/complete",
            json={"challenge_token": "tok", "credential": {}},
        )
        assert res.status_code == 401

    async def test_register_complete_missing_fields(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

        res = client.post("/passkey/register/complete", json={"credential": {}})
        assert res.status_code == 400
        assert "challenge_token" in res.json()["detail"]

        challenge_tok = plugin._encode_challenge(FAKE_CHALLENGE, "1")
        res = client.post(
            "/passkey/register/complete", json={"challenge_token": challenge_tok}
        )
        assert res.status_code == 400
        assert "credential" in res.json()["detail"]

    async def test_register_complete_bad_challenge(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

    async def test_register_complete_verification_fails(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

    async def test_register_complete_success(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

        # Credential is now in the passkeys table, NOT on the user record.
        passkeys = await auth.db.get_passkeys_by_user(user.id)
        assert len(passkeys) == 1
        assert passkeys[0].credential_id == FAKE_CREDENTIAL_ID.hex()
        assert passkeys[0].public_key == FAKE_PUBLIC_KEY.hex()
        assert passkeys[0].sign_count == FAKE_SIGN_COUNT

    async def test_register_second_passkey_success(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        """A user can register a second passkey (e.g. a hardware security key)."""
        user, auth, client, plugin = registered_user

        session = await auth.sign_in("alice@example.com", "secret")
        client.cookies.set("qulf_session", session.token)

        challenge_tok = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

        mock_verified = MagicMock()
        mock_verified.credential_id = FAKE_CREDENTIAL_ID_2
        mock_verified.credential_public_key = FAKE_PUBLIC_KEY_2
        mock_verified.sign_count = 0

        with patch("webauthn.verify_registration_response", return_value=mock_verified):
            res = client.post(
                "/passkey/register/complete",
                json={
                    "challenge_token": challenge_tok,
                    "credential": {"id": "x"},
                    "name": "YubiKey 5",
                },
            )

        assert res.status_code == 201
        passkeys = await auth.db.get_passkeys_by_user(user.id)
        assert len(passkeys) == 2  # original + new one
        names = {pk.name for pk in passkeys}
        assert "YubiKey 5" in names


@pytest.mark.asyncio
class TestPasskeyLoginBegin:
    async def test_login_begin_missing_email(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, _, client, _ = passkey_app
        res = client.post("/passkey/login/begin", json={})
        assert res.status_code == 400
        assert "email" in res.json()["detail"]

    async def test_login_begin_unknown_email(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, _, client, _ = passkey_app
        res = client.post("/passkey/login/begin", json={"email": "ghost@example.com"})
        assert res.status_code == 404

    async def test_login_begin_no_passkey_registered(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

    async def test_login_begin_success(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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

    async def test_login_begin_lists_all_credentials(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        """allow_credentials must include all registered passkeys for the user."""
        user, auth, client, plugin = registered_user

        # Register a second passkey directly.
        await auth.db.create_passkey(
            PasskeyCredentialCreate(
                user_id=user.id,
                credential_id=FAKE_CREDENTIAL_ID_2.hex(),
                public_key=FAKE_PUBLIC_KEY_2.hex(),
                sign_count=0,
                name="YubiKey",
            )
        )

        captured_kwargs: dict[str, Any] = {}

        def fake_gen_auth_opts(**kwargs: Any) -> MagicMock:
            captured_kwargs.update(kwargs)
            m = _make_options_mock(FAKE_CHALLENGE)
            return m

        with (
            patch(
                "webauthn.generate_authentication_options",
                side_effect=fake_gen_auth_opts,
            ),
            patch(
                "qulf.plugins.passkey.options_to_json",
                return_value=_options_json(FAKE_CHALLENGE),
            ),
        ):
            res = client.post(
                "/passkey/login/begin", json={"email": "alice@example.com"}
            )

        assert res.status_code == 200
        allow_creds = captured_kwargs.get("allow_credentials", [])
        cred_ids = {bytes(c.id).hex() for c in allow_creds}
        assert FAKE_CREDENTIAL_ID.hex() in cred_ids
        assert FAKE_CREDENTIAL_ID_2.hex() in cred_ids


@pytest.mark.asyncio
class TestPasskeyLoginComplete:
    async def test_login_complete_missing_fields(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, _, client, _ = passkey_app

        res = client.post("/passkey/login/complete", json={"credential": {}})
        assert res.status_code == 400
        assert "challenge_token" in res.json()["detail"]

        res2 = client.post("/passkey/login/complete", json={"challenge_token": "tok"})
        assert res2.status_code == 400
        assert "credential" in res2.json()["detail"]

    async def test_login_complete_bad_challenge(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user

        res = client.post(
            "/passkey/login/complete",
            json={"challenge_token": "garbage", "credential": {"id": "x"}},
        )
        assert res.status_code == 400
        assert "Invalid" in res.json()["detail"]

    async def test_login_complete_user_not_found(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, auth, client, plugin = passkey_app

        token = plugin._encode_challenge(FAKE_CHALLENGE, "nonexistent-id")
        res = client.post(
            "/passkey/login/complete",
            json={"challenge_token": token, "credential": {"id": "x"}},
        )
        assert res.status_code == 404

    async def test_login_complete_no_passkey_on_user(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
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
        # credential dict has no rawId/id → plugin returns 400
        res = client.post(
            "/passkey/login/complete",
            json={"challenge_token": token, "credential": {}},
        )
        assert res.status_code == 400
        assert "No passkey" in res.json()["detail"]

    async def test_login_complete_credential_id_not_found(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        """A credential ID that does not match any stored passkey returns 400."""
        user, auth, client, plugin = registered_user

        token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)
        unknown_cred_id = b"\xde\xad\xbe\xef".hex()
        res = client.post(
            "/passkey/login/complete",
            json={
                "challenge_token": token,
                "credential": {"rawId": unknown_cred_id},
            },
        )
        assert res.status_code == 400
        assert "No passkey" in res.json()["detail"]

    async def test_login_complete_invalid_signature(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user

        token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

        from webauthn.helpers.exceptions import InvalidAuthenticationResponse

        with patch(
            "webauthn.verify_authentication_response",
            side_effect=InvalidAuthenticationResponse("signature mismatch"),
        ):
            res = client.post(
                "/passkey/login/complete",
                json={
                    "challenge_token": token,
                    "credential": {"rawId": FAKE_CREDENTIAL_ID.hex()},
                },
            )
        assert res.status_code == 500

    async def test_login_complete_success(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user

        token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

        mock_verified = MagicMock()
        mock_verified.new_sign_count = FAKE_SIGN_COUNT + 1

        with patch(
            "webauthn.verify_authentication_response", return_value=mock_verified
        ):
            res = client.post(
                "/passkey/login/complete",
                json={
                    "challenge_token": token,
                    "credential": {"rawId": FAKE_CREDENTIAL_ID.hex()},
                },
            )

        assert res.status_code == 200
        assert "qulf_session" in res.cookies
        body = res.json()
        assert body["user"]["email"] == "alice@example.com"
        assert "Signed in successfully" in body["message"]

        # Sign count updated on the passkey row.
        updated = await auth.db.get_passkey_by_credential_id(FAKE_CREDENTIAL_ID.hex())
        assert updated is not None
        assert updated.sign_count == FAKE_SIGN_COUNT + 1

    async def test_login_complete_selects_correct_credential(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        """Login succeeds when using the *second* of two registered passkeys."""
        user, auth, client, plugin = registered_user

        # Register a second passkey.
        await auth.db.create_passkey(
            PasskeyCredentialCreate(
                user_id=user.id,
                credential_id=FAKE_CREDENTIAL_ID_2.hex(),
                public_key=FAKE_PUBLIC_KEY_2.hex(),
                sign_count=5,
                name="YubiKey",
            )
        )

        token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

        mock_verified = MagicMock()
        mock_verified.new_sign_count = 6

        with patch(
            "webauthn.verify_authentication_response", return_value=mock_verified
        ):
            res = client.post(
                "/passkey/login/complete",
                json={
                    "challenge_token": token,
                    # Use the second credential.
                    "credential": {"rawId": FAKE_CREDENTIAL_ID_2.hex()},
                },
            )

        assert res.status_code == 200
        # Second passkey's sign count updated; first is unchanged.
        pk2 = await auth.db.get_passkey_by_credential_id(FAKE_CREDENTIAL_ID_2.hex())
        assert pk2 is not None and pk2.sign_count == 6
        pk1 = await auth.db.get_passkey_by_credential_id(FAKE_CREDENTIAL_ID.hex())
        assert pk1 is not None and pk1.sign_count == 0

    async def test_login_complete_create_session_fails(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user

        token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

        mock_verified = MagicMock()
        mock_verified.new_sign_count = FAKE_SIGN_COUNT + 1

        auth.create_session = AsyncMock(
            side_effect=QulfException("Session creation blocked by core")
        )

        with patch(
            "webauthn.verify_authentication_response", return_value=mock_verified
        ):
            res = client.post(
                "/passkey/login/complete",
                json={
                    "challenge_token": token,
                    "credential": {"rawId": FAKE_CREDENTIAL_ID.hex()},
                },
            )

        assert res.status_code == 400
        assert "Session creation blocked by core" in res.json()["detail"]

    async def test_login_complete_base64url_credential_id(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        import base64

        user, auth, client, plugin = registered_user
        token = plugin._encode_challenge(FAKE_CHALLENGE, user.id)

        # Encode credential ID as base64url (non-hex) string
        b64url_id = (
            base64.urlsafe_b64encode(FAKE_CREDENTIAL_ID).decode("ascii").rstrip("=")
        )

        mock_verified = MagicMock()
        mock_verified.new_sign_count = FAKE_SIGN_COUNT + 1

        with patch(
            "webauthn.verify_authentication_response", return_value=mock_verified
        ):
            res = client.post(
                "/passkey/login/complete",
                json={
                    "challenge_token": token,
                    "credential": {"rawId": b64url_id},
                },
            )

        assert res.status_code == 200


@pytest.mark.asyncio
class TestPasskeyListEndpoint:
    async def test_list_requires_auth(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, _, client, _ = passkey_app
        res = client.get("/passkey/list")
        assert res.status_code == 401

    async def test_list_returns_empty_for_new_user(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, auth, client, _ = passkey_app

        await auth.sign_up(
            UserCreate(
                name="Ivan",
                email="ivan@example.com",
                username="ivan",
                password="pw",
                password_confirmation="pw",
            )
        )
        session = await auth.sign_in("ivan@example.com", "pw")
        client.cookies.set("qulf_session", session.token)

        res = client.get("/passkey/list")
        assert res.status_code == 200
        assert res.json()["passkeys"] == []

    async def test_list_returns_all_passkeys(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user

        # Register a second passkey.
        await auth.db.create_passkey(
            PasskeyCredentialCreate(
                user_id=user.id,
                credential_id=FAKE_CREDENTIAL_ID_2.hex(),
                public_key=FAKE_PUBLIC_KEY_2.hex(),
                sign_count=0,
                name="YubiKey",
            )
        )

        session = await auth.sign_in("alice@example.com", "secret")
        client.cookies.set("qulf_session", session.token)

        res = client.get("/passkey/list")
        assert res.status_code == 200
        passkeys = res.json()["passkeys"]
        assert len(passkeys) == 2
        names = {pk["name"] for pk in passkeys}
        assert "Alice's MacBook" in names
        assert "YubiKey" in names
        # Public key bytes must NOT be exposed.
        for pk in passkeys:
            assert "public_key" not in pk


@pytest.mark.asyncio
class TestPasskeyDeleteEndpoint:
    async def test_delete_requires_auth(
        self, passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        _, _, client, _ = passkey_app
        cred_id = FAKE_CREDENTIAL_ID.hex()
        res = client.request("DELETE", f"/passkey/{cred_id}")
        assert res.status_code == 401

    async def test_delete_passkey_success(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user

        session = await auth.sign_in("alice@example.com", "secret")
        client.cookies.set("qulf_session", session.token)

        cred_id = FAKE_CREDENTIAL_ID.hex()
        res = client.request("DELETE", f"/passkey/{cred_id}")
        assert res.status_code == 200
        assert "deleted" in res.json()["message"]

        # Credential is gone.
        remaining = await auth.db.get_passkeys_by_user(user.id)
        assert all(pk.credential_id != cred_id for pk in remaining)

    async def test_delete_passkey_not_found(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user

        session = await auth.sign_in("alice@example.com", "secret")
        client.cookies.set("qulf_session", session.token)

        res = client.request("DELETE", f"/passkey/{b'unknown'.hex()}")
        assert res.status_code == 404

    async def test_delete_passkey_other_user_returns_404(
        self,
        passkey_app: tuple[FastAPI, Qulf, TestClient, PasskeyPlugin],
        registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin],
    ) -> None:
        """Users cannot delete each other's passkeys."""
        user, auth, _, plugin = registered_user
        _, _, client, _ = passkey_app  # fresh client with no session

        # Sign in as a different user.
        await auth.sign_up(
            UserCreate(
                name="Judy",
                email="judy@example.com",
                username="judy",
                password="pw",
                password_confirmation="pw",
            )
        )
        session = await auth.sign_in("judy@example.com", "pw")
        client.cookies.set("qulf_session", session.token)

        cred_id = FAKE_CREDENTIAL_ID.hex()  # belongs to alice
        res = client.request("DELETE", f"/passkey/{cred_id}")
        assert res.status_code == 404

    async def test_delete_passkey_empty_credential_id(
        self, registered_user: tuple[User, Qulf, TestClient, PasskeyPlugin]
    ) -> None:
        user, auth, client, plugin = registered_user
        session = await auth.sign_in("alice@example.com", "secret")

        # Directly call handler with empty path_params to cover path_params.get fallback
        from qulf.routing import QulfRequest

        req = QulfRequest(
            cookies={"qulf_session": session.token},
            path_params={},
        )
        routes = plugin.get_routes()
        delete_route = next(r for r in routes if r.path == "/passkey/{credential_id}")
        res = await delete_route.handler(req)
        assert res.status_code == 400
        assert res.body is not None and "credential_id is required" in res.body["detail"]
