from urllib.parse import urlencode

import httpx

from qulf.exceptions import QulfException
from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)

_CDN_BASE = "https://cdn.discordapp.com"


class DiscordProvider(BaseOAuthProvider):
    """
    Discord OAuth2 provider implementation.

    Uses Discord's Authorization Code Grant flow to authenticate users.
    Requires the ``identify`` and ``email`` scopes to retrieve the user's
    profile and verified email address.

    See: https://discord.com/developers/docs/topics/oauth2
    """

    id = "discord"
    name = "Discord"

    AUTHORIZATION_URL = "https://discord.com/oauth2/authorize"
    TOKEN_URL = "https://discord.com/api/oauth2/token"
    USERINFO_URL = "https://discord.com/api/users/@me"

    async def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.scopes) if self.scopes else "identify email",
            # Prompt the user to re-authorize even if they have a prior grant,
            # keeping behavior consistent with other providers.
            "prompt": "consent",
        }
        return f"{self.AUTHORIZATION_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        # Discord requires form-encoded body, not JSON.
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
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
                raise QulfException(f"Discord OAuth error: {description}")

            return OAuthTokenResponse(
                access_token=result["access_token"],
                token_type=result.get("token_type", "Bearer"),
                expires_in=result.get("expires_in"),
                refresh_token=result.get("refresh_token"),
                scope=result.get("scope"),
            )

    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(self.USERINFO_URL, headers=headers)

            if response.status_code != 200:
                raise QulfException(f"Failed to fetch user profile: {response.text}")

            user_data = response.json()
            email: str | None = user_data.get("email")

            if not email:
                raise QulfException("Could not obtain email from Discord")

            # Build the CDN avatar URL if the user has a custom avatar hash.
            avatar_url: str | None = None
            avatar_hash: str | None = user_data.get("avatar")
            if avatar_hash:
                avatar_url = f"{_CDN_BASE}/avatars/{user_data['id']}/{avatar_hash}.png"

            # Discord uses `global_name` as the display name (added in API v10),
            # falling back to the legacy `username` discriminator field.
            display_name: str | None = user_data.get("global_name") or user_data.get(
                "username"
            )

            return OAuthUserProfile(
                id=str(user_data["id"]),
                email=email,
                name=display_name,
                username=user_data.get("username"),
                avatar_url=avatar_url,
                raw_data=user_data,
            )
