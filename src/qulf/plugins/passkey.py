"""
PasskeyPlugin - WebAuthn / FIDO2 passwordless authentication.

Stores a single passkey credential per user via `get_custom_columns()`,
following the same pattern as TOTPPlugin. Challenges are short-lived JWTs
(signed with the project's secret_key) so no additional database table is needed.

Routes
------
POST /passkey/register/begin     – Session-protected; returns registration options.
POST /passkey/register/complete  – Session-protected; verifies attestation + stores key.
POST /passkey/login/begin        – Accepts ``email``; returns authentication options.
POST /passkey/login/complete     – Verifies assertion + creates a full session.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import webauthn
from jwt import ExpiredSignatureError, InvalidTokenError
from webauthn import options_to_json
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from qulf.exceptions import PasskeyVerificationError, QulfException
from qulf.plugins.base import QulfPlugin
from qulf.routing import CookieOptions, QulfRequest, QulfResponse, QulfRoute

# Column names injected into the ``user`` table
_COL_CREDENTIAL_ID = "passkey_credential_id"
_COL_PUBLIC_KEY = "passkey_public_key"
_COL_SIGN_COUNT = "passkey_sign_count"

# JWT claim type used to distinguish passkey challenges from other short-lived tokens
_CHALLENGE_TYPE = "passkey_challenge"


class PasskeyPlugin(QulfPlugin):
    """
    **Passwordless authentication via WebAuthn / Passkeys (FIDO2).**

    Allows users to register and authenticate using platform authenticators
    such as FaceID, TouchID, or Windows Hello.

    Parameters
    ----------
    rp_id:
        The Relying Party ID, the effective domain of the application
        (e.g. ``"example.com"``). Must match the domain the browser sees.
    rp_name:
        Human-readable name for the Relying Party shown in the browser UI.
    origin:
        The full origin of the application (e.g. ``"https://example.com"``).
        Must exactly match ``window.location.origin`` in the browser.
    require_resident_key:
        If ``True`` the authenticator must support discoverable credentials
        (required for usernameless flows). Defaults to ``False``.
    require_user_verification:
        If ``True`` the authenticator must verify the user (e.g. biometric).
        Defaults to ``False`` (``preferred``).
    challenge_ttl_seconds:
        Lifetime in seconds of the short-lived challenge JWT.
        Defaults to 60 seconds.
    """

    name = "passkey"

    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        origin: str,
        require_resident_key: bool = False,
        require_user_verification: bool = False,
        challenge_ttl_seconds: int = 60,
    ) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.require_resident_key = require_resident_key
        self.require_user_verification = require_user_verification
        self.challenge_ttl_seconds = challenge_ttl_seconds

    # Plugin hooks
    def get_custom_columns(self) -> dict[str, dict[str, Any]]:
        """
        Injects three columns into the ``user`` table:

        - ``passkey_credential_id`` – Base64url-encoded credential ID.
        - ``passkey_public_key``    – Base64url-encoded COSE public key bytes.
        - ``passkey_sign_count``    – Monotonic counter for replay protection.
        """
        return {
            "user": {
                _COL_CREDENTIAL_ID: str,
                _COL_PUBLIC_KEY: str,
                _COL_SIGN_COUNT: int,
            }
        }

    # Internal helpers
    def _encode_challenge(self, challenge_bytes: bytes, user_id: str | int) -> str:
        """
        Wraps a raw WebAuthn challenge in a short-lived signed JWT so it can be
        round-tripped through the client without server-side state.
        """
        payload = {
            "type": _CHALLENGE_TYPE,
            "challenge": challenge_bytes.hex(),  # hex is URL-safe and easy to decode
            "user_id": str(user_id),
            "exp": datetime.now(timezone.utc)
            + timedelta(seconds=self.challenge_ttl_seconds),
        }
        return jwt.encode(payload, self.auth.config.secret_key, algorithm="HS256")

    def _decode_challenge(self, token: str) -> tuple[bytes, str]:
        """
        Decodes and validates a challenge JWT.

        Returns
        -------
        (challenge_bytes, user_id_str)

        Raises
        ------
        PasskeyVerificationError
            If the token is expired, has an invalid signature, or carries the
            wrong ``type`` claim.
        """
        try:
            payload = jwt.decode(
                token, self.auth.config.secret_key, algorithms=["HS256"]
            )
        except ExpiredSignatureError:
            raise PasskeyVerificationError("Challenge expired. Please try again.")
        except InvalidTokenError:
            raise PasskeyVerificationError("Invalid challenge token.")

        if payload.get("type") != _CHALLENGE_TYPE:
            raise PasskeyVerificationError("Invalid challenge token type.")

        challenge_bytes = bytes.fromhex(payload["challenge"])
        user_id: str = payload["user_id"]
        return challenge_bytes, user_id

    # Routes
    def get_routes(self) -> list[QulfRoute]:
        """Returns the four WebAuthn ceremony endpoints."""

        # Registration
        async def register_begin(request: QulfRequest) -> QulfResponse:
            """
            **POST /passkey/register/begin**

            Requires an active session. Returns WebAuthn
            ``PublicKeyCredentialCreationOptions`` as JSON, plus a short-lived
            challenge token the client must echo back in
            ``/passkey/register/complete``.
            """
            session_data = await self.auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return QulfResponse(status_code=401, body={"detail": "Unauthorized"})

            _, user = session_data

            authenticator_selection = AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED
                if self.require_resident_key
                else ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.REQUIRED
                if self.require_user_verification
                else UserVerificationRequirement.PREFERRED,
            )

            options = webauthn.generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_name=user.email,
                user_display_name=user.name or user.email,
                authenticator_selection=authenticator_selection,
            )

            challenge_token = self._encode_challenge(options.challenge, user.id)
            options_dict: dict[str, Any] = json.loads(options_to_json(options))

            return QulfResponse(
                status_code=200,
                body={
                    "publicKey": options_dict,
                    "challenge_token": challenge_token,
                },
            )

        async def register_complete(request: QulfRequest) -> QulfResponse:
            """
            **POST /passkey/register/complete**

            Requires an active session. Expects:

            - ``challenge_token`` – the token returned by ``/passkey/register/begin``.
            - ``credential``      – the ``PublicKeyCredential`` JSON from the browser.

            Verifies the attestation and persists the credential against the user.
            """
            session_data = await self.auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return QulfResponse(status_code=401, body={"detail": "Unauthorized"})

            _, user = session_data

            challenge_token = request.body.get("challenge_token")
            credential = request.body.get("credential")

            if not challenge_token:
                return QulfResponse(
                    status_code=400, body={"detail": "challenge_token is required"}
                )
            if credential is None:
                return QulfResponse(
                    status_code=400, body={"detail": "credential is required"}
                )

            try:
                expected_challenge, _uid = self._decode_challenge(challenge_token)
            except PasskeyVerificationError as exc:
                return QulfResponse(status_code=400, body={"detail": str(exc)})

            try:
                verified = webauthn.verify_registration_response(
                    credential=credential,
                    expected_challenge=expected_challenge,
                    expected_rp_id=self.rp_id,
                    expected_origin=self.origin,
                )
            except InvalidRegistrationResponse as exc:
                return QulfResponse(
                    status_code=400,
                    body={"detail": f"Registration verification failed: {exc}"},
                )

            # Persist the credential on the user record
            await self.auth.db.update_user(
                user.id,
                {
                    _COL_CREDENTIAL_ID: verified.credential_id.hex(),
                    _COL_PUBLIC_KEY: verified.credential_public_key.hex(),
                    _COL_SIGN_COUNT: verified.sign_count,
                },
            )

            return QulfResponse(
                status_code=201,
                body={"message": "Passkey registered successfully."},
            )

        # Authentication
        async def login_begin(request: QulfRequest) -> QulfResponse:
            """
            **POST /passkey/login/begin**

            Accepts ``email`` in the request body. Returns
            ``PublicKeyCredentialRequestOptions`` as JSON plus a challenge token.
            """
            email = request.body.get("email")
            if not email:
                return QulfResponse(
                    status_code=400, body={"detail": "email is required"}
                )

            user = await self.auth.db.get_user_by_email(email)
            if not user:
                return QulfResponse(status_code=404, body={"detail": "User not found"})

            # Retrieve the stored credential ID for the allow_credentials hint
            credential_id_hex: str | None = None
            if user.model_extra:
                credential_id_hex = user.model_extra.get(_COL_CREDENTIAL_ID)

            if not credential_id_hex:
                return QulfResponse(
                    status_code=400,
                    body={"detail": "No passkey registered for this account."},
                )

            from webauthn.helpers.structs import PublicKeyCredentialDescriptor

            allow_credentials = [
                PublicKeyCredentialDescriptor(id=bytes.fromhex(credential_id_hex))
            ]

            options = webauthn.generate_authentication_options(
                rp_id=self.rp_id,
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.REQUIRED
                if self.require_user_verification
                else UserVerificationRequirement.PREFERRED,
            )

            challenge_token = self._encode_challenge(options.challenge, user.id)
            options_dict = json.loads(options_to_json(options))

            return QulfResponse(
                status_code=200,
                body={
                    "publicKey": options_dict,
                    "challenge_token": challenge_token,
                },
            )

        async def login_complete(request: QulfRequest) -> QulfResponse:
            """
            **POST /passkey/login/complete**

            Expects:

            - ``challenge_token`` – token returned by ``/passkey/login/begin``.
            - ``credential``      – the ``PublicKeyCredential`` JSON from the browser.

            Verifies the assertion signature. On success, creates and returns
            a full authenticated session (cookie-based).
            """
            challenge_token = request.body.get("challenge_token")
            credential = request.body.get("credential")

            if not challenge_token:
                return QulfResponse(
                    status_code=400, body={"detail": "challenge_token is required"}
                )
            if credential is None:
                return QulfResponse(
                    status_code=400, body={"detail": "credential is required"}
                )

            try:
                expected_challenge, user_id = self._decode_challenge(challenge_token)
            except PasskeyVerificationError as exc:
                return QulfResponse(status_code=400, body={"detail": str(exc)})

            user = await self.auth.db.get_user_by_id(user_id)
            if not user:
                return QulfResponse(status_code=404, body={"detail": "User not found"})

            public_key_hex: str | None = None
            sign_count: int = 0

            if user.model_extra:
                public_key_hex = user.model_extra.get(_COL_PUBLIC_KEY)
                sign_count = int(user.model_extra.get(_COL_SIGN_COUNT) or 0)

            if not public_key_hex:
                return QulfResponse(
                    status_code=400,
                    body={"detail": "No passkey registered for this account."},
                )

            try:
                verified = webauthn.verify_authentication_response(
                    credential=credential,
                    expected_challenge=expected_challenge,
                    expected_rp_id=self.rp_id,
                    expected_origin=self.origin,
                    credential_public_key=bytes.fromhex(public_key_hex),
                    credential_current_sign_count=sign_count,
                )
            except InvalidAuthenticationResponse as exc:
                raise PasskeyVerificationError(str(exc)) from exc

            # Update the sign count to prevent replay attacks
            await self.auth.db.update_user(
                user.id,
                {_COL_SIGN_COUNT: verified.new_sign_count},
            )

            try:
                session = await self.auth.create_session(
                    user, request.ip_address, request.user_agent
                )
            except QulfException as exc:
                return QulfResponse(status_code=400, body={"detail": str(exc)})

            cookie = CookieOptions(
                key=self.auth.config.cookies.name,
                value=session.token,
                httponly=self.auth.config.cookies.http_only,
                secure=self.auth.config.cookies.secure,
                samesite=self.auth.config.cookies.same_site,
            )

            return QulfResponse(
                status_code=200,
                set_cookies=[cookie],
                body={"message": "Signed in successfully.", "user": user.model_dump()},
            )

        return [
            QulfRoute(
                path="/passkey/register/begin",
                methods=["POST"],
                handler=register_begin,
            ),
            QulfRoute(
                path="/passkey/register/complete",
                methods=["POST"],
                handler=register_complete,
            ),
            QulfRoute(
                path="/passkey/login/begin",
                methods=["POST"],
                handler=login_begin,
            ),
            QulfRoute(
                path="/passkey/login/complete",
                methods=["POST"],
                handler=login_complete,
            ),
        ]
