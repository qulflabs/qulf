"""Generic OpenID Connect (OIDC) OAuth2 provider.

Supports standard OpenID Connect discovery via ``/.well-known/openid-configuration``
or explicit authorization, token, and userinfo endpoint overrides.
"""

from typing import Any
from urllib.parse import urlencode

import httpx

from qulf.exceptions import QulfException
from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)


class OIDCProvider(BaseOAuthProvider):
    """
    Generic OpenID Connect (OIDC) OAuth2 provider implementation.

    Parameters
    ----------
    client_id:
        OAuth2 Client ID issued by the Identity Provider.
    client_secret:
        OAuth2 Client Secret issued by the Identity Provider.
    redirect_uri:
        Redirect URI registered with the Identity Provider.
    issuer:
        Issuer base URL (e.g. ``https://auth.example.com``). If provided,
        endpoints are automatically discovered via
        ``/.well-known/openid-configuration``.
    authorization_url:
        Explicit authorization URL. Overrides discovery if provided.
    token_url:
        Explicit token URL. Overrides discovery if provided.
    userinfo_url:
        Explicit userinfo URL. Overrides discovery if provided.
    scopes:
        Requested scopes. Defaults to ``["openid", "profile", "email"]``.
    id:
        Custom provider identifier string (e.g. ``"auth0"`` or ``"okta"``).
        Defaults to ``"oidc"``.
    name:
        Custom provider human-readable name (e.g. ``"Auth0"``).
        Defaults to ``"OIDC"``.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        issuer: str | None = None,
        authorization_url: str | None = None,
        token_url: str | None = None,
        userinfo_url: str | None = None,
        scopes: list[str] | None = None,
        id: str = "oidc",
        name: str = "OIDC",
    ) -> None:
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or ["openid", "profile", "email"],
        )
        if not issuer and not (authorization_url and token_url):
            raise QulfException(
                "OIDCProvider requires either an 'issuer' URL for discovery "
                "or explicit 'authorization_url' and 'token_url'."
            )

        self.issuer = issuer.rstrip("/") if issuer else None
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url
        self.id = id
        self.name = name
        self._discovered: bool = False

    async def discover_configuration(self) -> None:
        """Fetch OIDC discovery metadata from ``/.well-known/openid-configuration``."""
        if self._discovered or not self.issuer:
            return

        discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            response = await client.get(discovery_url)
            if response.status_code != 200:
                raise QulfException(
                    "Failed to fetch OIDC discovery document from "
                    f"{discovery_url}: {response.text}"
                )

            data = response.json()
            if not self.authorization_url:
                self.authorization_url = data.get("authorization_endpoint")
            if not self.token_url:
                self.token_url = data.get("token_endpoint")
            if not self.userinfo_url:
                self.userinfo_url = data.get("userinfo_endpoint")

            self._discovered = True

        if not self.authorization_url or not self.token_url:
            raise QulfException(
                "OIDC discovery document missing required "
                "'authorization_endpoint' or 'token_endpoint'."
            )

    async def get_authorization_url(self, state: str) -> str:
        await self.discover_configuration()
        if not self.authorization_url:
            raise QulfException("OIDC authorization_url is not configured.")

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.scopes),
        }
        return f"{self.authorization_url}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        await self.discover_configuration()
        if not self.token_url:
            raise QulfException("OIDC token_url is not configured.")

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data, headers=headers)

            if response.status_code != 200:
                raise QulfException(f"Failed to fetch access token: {response.text}")

            result = response.json()
            if "error" in result:
                description = result.get("error_description", result["error"])
                raise QulfException(f"OIDC OAuth error: {description}")

            return OAuthTokenResponse(
                access_token=result["access_token"],
                token_type=result.get("token_type", "Bearer"),
                expires_in=result.get("expires_in"),
                refresh_token=result.get("refresh_token"),
                scope=result.get("scope"),
                id_token=result.get("id_token"),
            )

    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        await self.discover_configuration()
        if not self.userinfo_url:
            raise QulfException("OIDC userinfo_url is not configured.")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(self.userinfo_url, headers=headers)

            if response.status_code != 200:
                raise QulfException(f"Failed to fetch user profile: {response.text}")

            user_data: dict[str, Any] = response.json()

        user_id = user_data.get("sub") or user_data.get("id")
        if not user_id:
            raise QulfException("Could not obtain sub from OIDC provider")

        email: str | None = user_data.get("email")
        if not email:
            raise QulfException("Could not obtain email from OIDC provider")

        given = user_data.get("given_name", "")
        family = user_data.get("family_name", "")
        full_name = f"{given} {family}".strip() if (given or family) else None
        name: str | None = (
            user_data.get("name") or user_data.get("nickname") or full_name
        )
        username: str | None = (
            user_data.get("preferred_username")
            or user_data.get("nickname")
            or (email.split("@")[0] if email else None)
        )

        return OAuthUserProfile(
            id=str(user_id),
            email=email,
            name=name,
            username=username,
            avatar_url=user_data.get("picture"),
            raw_data=user_data,
        )
