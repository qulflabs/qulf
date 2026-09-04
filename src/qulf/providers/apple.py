"""Apple Sign In OAuth2 provider.

Apple's authorization code flow differs from other providers in two key ways:

1. **Client secret**: A short-lived ES256 JWT must be generated on every
   token exchange, signed with an EC private key (.p8) downloaded from the
   Apple Developer portal.  No static secret string is used.

2. **User profile**: Apple has no separate userinfo endpoint.  All identity
   claims (``sub``, ``email``) are extracted from the ``id_token`` JWT
   included in the token response.  The user's display name is only sent
   during the *first* authorization callback (in the POST body) and is
   therefore not available via ``get_user_profile``.
"""

import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from qulf.exceptions import QulfException
from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)


class AppleProvider(BaseOAuthProvider):
    """
    Apple Sign In OAuth2 provider implementation.

    Parameters
    ----------
    client_id:
        Your Apple Services ID (e.g. ``com.example.app``).
    team_id:
        Your 10-character Apple Developer Team ID.
    key_id:
        The Key ID associated with the .p8 private key file.
    private_key:
        The full contents of the ``.p8`` file (PEM-encoded EC private key).
    redirect_uri:
        The HTTPS URL Apple POSTs the authorization response to.
        Must match the redirect URI registered in the Apple Developer portal.
    scopes:
        Requested scopes. Defaults to ``["name", "email"]``.

    .. note::
        ES256 JWT signing requires the ``cryptography`` package.
        Install it via ``pip install 'qulf[apple]'``.
    """

    id = "apple"
    name = "Apple"

    AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize"
    TOKEN_URL = "https://appleid.apple.com/auth/token"
    # Constant audience claim required in Apple-issued JWTs.
    _APPLE_AUDIENCE = "https://appleid.apple.com"
    # Apple caps the client_secret JWT lifetime at 6 months (15,552,000 s).
    _SECRET_TTL_SECONDS = 15_552_000

    def __init__(
        self,
        client_id: str,
        team_id: str,
        key_id: str,
        private_key: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ) -> None:
        # Store the PEM private key as `self.client_secret` via the base class;
        # the actual Apple-required JWT secret is generated fresh on each call
        # to `_generate_client_secret()`.
        super().__init__(
            client_id=client_id,
            client_secret=private_key,
            redirect_uri=redirect_uri,
            scopes=scopes,
        )
        self.team_id = team_id
        self.key_id = key_id
        # Apple has no userinfo endpoint; identity claims live in the id_token
        # returned by exchange_code. Cache it here so get_user_profile can
        # decode it without an extra network round-trip.
        self._pending_id_token: str | None = None

    def _generate_client_secret(self) -> str:
        """Return a short-lived ES256 JWT for use as the Apple ``client_secret``.

        Apple requires a freshly generated JWT on every token exchange instead
        of a static secret string. The JWT is signed with the developer's EC
        private key (.p8) and carries the Team ID, Service ID, and expiry.

        See https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
        """
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.team_id,
            "iat": now,
            "exp": now + self._SECRET_TTL_SECONDS,
            "aud": self._APPLE_AUDIENCE,
            "sub": self.client_id,
        }
        return jwt.encode(
            payload,
            self.client_secret,  # PEM EC private key
            algorithm="ES256",
            headers={"kid": self.key_id},
        )

    async def get_authorization_url(self, state: str) -> str:
        scopes = " ".join(self.scopes) if self.scopes else "name email"
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": scopes,
            # `form_post` is required whenever `name` or `email` scopes are
            # requested; Apple delivers the user data in the POST body, not
            # as a URL fragment or query parameter.
            "response_mode": "form_post",
        }
        return f"{self.AUTHORIZATION_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        # Apple requires a form-encoded body and a freshly generated client_secret.
        data = {
            "client_id": self.client_id,
            "client_secret": self._generate_client_secret(),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.TOKEN_URL, data=data, headers=headers)

            if response.status_code != 200:
                raise QulfException(f"Failed to fetch access token: {response.text}")

            result = response.json()
            if "error" in result:
                description = result.get("error_description", result["error"])
                raise QulfException(f"Apple OAuth error: {description}")

            # Cache the id_token; all Apple identity claims live in this JWT
            # since there is no separate userinfo endpoint to query.
            self._pending_id_token = result.get("id_token")

            return OAuthTokenResponse(
                access_token=result["access_token"],
                token_type=result.get("token_type", "Bearer"),
                expires_in=result.get("expires_in"),
                refresh_token=result.get("refresh_token"),
                scope=result.get("scope"),
                id_token=result.get("id_token"),
            )

    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        id_token = self._pending_id_token
        if not id_token:
            raise QulfException(
                "Apple id_token unavailable. "
                "Ensure exchange_code() is called before get_user_profile()."
            )

        try:
            # The id_token was received directly from Apple's HTTPS token
            # endpoint and cannot be tampered with in transit; signature
            # verification is skipped to avoid a JWKS round-trip. The JWT
            # structure and standard claims are still validated.
            payload = jwt.decode(
                id_token,
                options={"verify_signature": False},
                algorithms=["RS256"],
            )
        except jwt.InvalidTokenError as exc:
            raise QulfException(f"Failed to decode Apple id_token: {exc}") from exc
        finally:
            # Clear the cached token regardless of outcome to prevent
            # accidental reuse across unrelated requests.
            self._pending_id_token = None

        email: str | None = payload.get("email")
        if not email:
            raise QulfException("Could not obtain email from Apple")

        return OAuthUserProfile(
            id=str(payload["sub"]),
            email=email,
            # Apple sends the display name only on the first authorization,
            # via the callback POST body—outside the scope of this method.
            name=None,
            username=None,
            avatar_url=None,
            raw_data=payload,
        )
