"""
PasskeyPlugin - WebAuthn / FIDO2 passwordless authentication.

Credentials are stored in a dedicated ``passkeys`` table via four new
DatabaseAdapter methods (``create_passkey``, ``get_passkeys_by_user``,
``get_passkey_by_credential_id``, ``update_passkey_sign_count``).

This allows multiple authenticators per user (Touch ID, Face ID,
Windows Hello, hardware security keys).

Routes
------
POST   /passkey/register/begin    – Returns registration options.
POST   /passkey/register/complete – Verifies attestation & stores key.
POST   /passkey/login/begin       – Accepts ``email``; returns options.
POST   /passkey/login/complete    – Verifies assertion & creates session.
GET    /passkey/list              – Returns all passkeys for user.
DELETE /passkey/{credential_id}   – Removes a specific passkey.
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
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from qulf.exceptions import PasskeyVerificationError, QulfException
from qulf.plugins.base import QulfPlugin
from qulf.routing import CookieOptions, QulfRequest, QulfResponse, QulfRoute
from qulf.types import PasskeyCredentialCreate

# JWT claim type used to distinguish passkey challenges from other short-lived tokens
_CHALLENGE_TYPE = "passkey_challenge"


class PasskeyPlugin(QulfPlugin):
    """
    **Passwordless authentication via WebAuthn / Passkeys (FIDO2).**

    Allows users to register and authenticate using platform authenticators
    such as FaceID, TouchID, or Windows Hello.

    Multiple passkeys can be registered per user — one per authenticator
    device (e.g. a laptop's Touch ID *and* a hardware security key).

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
        """Returns the six WebAuthn ceremony endpoints."""

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

            # Build the exclude list from already-registered credentials so the
            # browser can warn the user if they try to re-register a key.
            existing = await self.auth.db.get_passkeys_by_user(user.id)
            exclude_credentials = [
                PublicKeyCredentialDescriptor(id=bytes.fromhex(pk.credential_id))
                for pk in existing
            ]

            options = webauthn.generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_name=user.email,
                user_display_name=user.name or user.email,
                authenticator_selection=authenticator_selection,
                exclude_credentials=exclude_credentials,
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

            - ``challenge_token`` – token returned by ``/passkey/register/begin``.
            - ``credential``      – the ``PublicKeyCredential`` JSON from the browser.
            - ``name``            – optional label (default: ``"Passkey"``).

            Verifies the attestation and persists the new credential in the
            ``passkeys`` table. A user may complete this flow multiple times
            to register additional authenticators.
            """
            session_data = await self.auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return QulfResponse(status_code=401, body={"detail": "Unauthorized"})

            _, user = session_data

            challenge_token = request.body.get("challenge_token")
            credential = request.body.get("credential")
            passkey_name: str = request.body.get("name") or "Passkey"

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

            # Persist the new credential in the dedicated passkeys table.
            await self.auth.db.create_passkey(
                PasskeyCredentialCreate(
                    user_id=user.id,
                    credential_id=verified.credential_id.hex(),
                    public_key=verified.credential_public_key.hex(),
                    sign_count=verified.sign_count,
                    name=passkey_name,
                )
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

            The ``allow_credentials`` list contains **all** passkeys registered
            for the user so the browser can use any of them.
            """
            email = request.body.get("email")
            if not email:
                return QulfResponse(
                    status_code=400, body={"detail": "email is required"}
                )

            user = await self.auth.db.get_user_by_email(email)
            if not user:
                return QulfResponse(status_code=404, body={"detail": "User not found"})

            # Load all passkeys for this user.
            passkeys = await self.auth.db.get_passkeys_by_user(user.id)
            if not passkeys:
                return QulfResponse(
                    status_code=400,
                    body={"detail": "No passkey registered for this account."},
                )

            allow_credentials = [
                PublicKeyCredentialDescriptor(id=bytes.fromhex(pk.credential_id))
                for pk in passkeys
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

            The browser includes the credential ID it used inside ``credential``.
            We use that ID to look up the specific passkey row (and its public key
            + current sign count), then verify the assertion signature. On success,
            creates and returns a full authenticated session (cookie-based).
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

            # Resolve which passkey the browser actually used from the credential ID.
            raw_id: str | None = None
            if isinstance(credential, dict):
                raw_id = credential.get("rawId") or credential.get("id")

            if not raw_id:
                return QulfResponse(
                    status_code=400,
                    body={"detail": "No passkey registered for this account."},
                )

            # credential IDs may arrive as base64url; normalise to hex via the
            # raw bytes path that py_webauthn uses internally.
            try:
                cred_id_bytes = bytes.fromhex(raw_id)
                credential_id_hex = raw_id
            except ValueError:
                # Likely base64url – decode it
                import base64

                cred_id_bytes = base64.urlsafe_b64decode(raw_id + "==")
                credential_id_hex = cred_id_bytes.hex()

            passkey = await self.auth.db.get_passkey_by_credential_id(credential_id_hex)
            if not passkey:
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
                    credential_public_key=bytes.fromhex(passkey.public_key),
                    credential_current_sign_count=passkey.sign_count,
                )
            except InvalidAuthenticationResponse as exc:
                raise PasskeyVerificationError(str(exc)) from exc

            # Update the sign count to prevent replay attacks.
            await self.auth.db.update_passkey_sign_count(
                passkey.credential_id, verified.new_sign_count
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

        # Management endpoints

        async def list_passkeys(request: QulfRequest) -> QulfResponse:
            """
            **GET /passkey/list**

            Requires an active session. Returns all passkeys registered for the
            authenticated user, without the raw public-key bytes.
            """
            session_data = await self.auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return QulfResponse(status_code=401, body={"detail": "Unauthorized"})

            _, user = session_data
            passkeys = await self.auth.db.get_passkeys_by_user(user.id)

            return QulfResponse(
                status_code=200,
                body={
                    "passkeys": [
                        {
                            "id": pk.id,
                            "credential_id": pk.credential_id,
                            "name": pk.name,
                            "created_at": pk.created_at.isoformat()
                            if pk.created_at
                            else None,
                        }
                        for pk in passkeys
                    ]
                },
            )

        async def delete_passkey(request: QulfRequest) -> QulfResponse:
            """
            **DELETE /passkey/{credential_id}**

            Requires an active session. Removes the specified passkey from the
            authenticated user's account. Returns 404 if the credential does not
            exist or belongs to a different user.
            """
            session_data = await self.auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return QulfResponse(status_code=401, body={"detail": "Unauthorized"})

            _, user = session_data
            credential_id: str = request.path_params.get("credential_id", "")

            if not credential_id:
                return QulfResponse(
                    status_code=400, body={"detail": "credential_id is required"}
                )

            # Verify ownership before deleting.
            passkey = await self.auth.db.get_passkey_by_credential_id(credential_id)
            if not passkey or str(passkey.user_id) != str(user.id):
                return QulfResponse(
                    status_code=404, body={"detail": "Passkey not found"}
                )

            await self.auth.db.delete_passkey(credential_id)

            return QulfResponse(
                status_code=200,
                body={"message": "Passkey deleted successfully."},
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
            QulfRoute(
                path="/passkey/list",
                methods=["GET"],
                handler=list_passkeys,
            ),
            QulfRoute(
                path="/passkey/{credential_id}",
                methods=["DELETE"],
                handler=delete_passkey,
            ),
        ]
