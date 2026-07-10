from urllib.parse import urlencode

import httpx

from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)
from qulf.exceptions import QulfException


class GoogleProvider(BaseOAuthProvider):
    """
    Google OAuth2 provider implementation.
    """

    id = "google"
    name = "Google"

    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

    async def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.scopes) if self.scopes else "openid email profile",
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{self.AUTHORIZATION_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        headers = {"Accept": "application/json"}

        async with httpx.AsyncClient() as client:
            response = await client.post(self.TOKEN_URL, data=data, headers=headers)

            if response.status_code != 200:
                raise QulfException(f"Failed to fetch access token: {response.text}")

            result = response.json()
            if "error" in result:
                raise QulfException(f"Google OAuth error: {result.get('error_description', result['error'])}")

            return OAuthTokenResponse(
                access_token=result["access_token"],
                token_type=result.get("token_type", "Bearer"),
                expires_in=result.get("expires_in"),
                refresh_token=result.get("refresh_token"),
                scope=result.get("scope"),
                id_token=result.get("id_token"),
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
            email = user_data.get("email")

            if not email:
                raise QulfException("Could not obtain email from Google")

            return OAuthUserProfile(
                id=str(user_data.get("sub", user_data.get("id"))),
                email=email,
                name=user_data.get("name"),
                username=user_data.get("email").split("@")[0] if user_data.get("email") else None,
                avatar_url=user_data.get("picture"),
                raw_data=user_data,
            )
