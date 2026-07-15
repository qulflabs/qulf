from urllib.parse import urlencode

import httpx

from qulf.exceptions import QulfException
from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)


class GitHubProvider(BaseOAuthProvider):
    """
    GitHub OAuth2 provider implementation.
    """

    id = "github"
    name = "GitHub"

    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USERINFO_URL = "https://api.github.com/user"
    USERINFO_EMAILS_URL = "https://api.github.com/user/emails"

    async def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": state,
            "scope": " ".join(self.scopes) if self.scopes else "read:user user:email",
        }
        return f"{self.AUTHORIZATION_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        headers = {"Accept": "application/json"}

        async with httpx.AsyncClient() as client:
            response = await client.post(self.TOKEN_URL, data=data, headers=headers)

            if response.status_code != 200:
                raise QulfException(f"Failed to fetch access token: {response.text}")

            result = response.json()
            if "error" in result:
                raise QulfException(
                    f"GitHub OAuth error: {result['error_description']}"
                )

            return OAuthTokenResponse(
                access_token=result["access_token"],
                token_type=result.get("token_type", "bearer"),
                expires_in=result.get("expires_in"),
                refresh_token=result.get("refresh_token"),
                scope=result.get("scope"),
            )

    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient() as client:
            # Fetch user profile
            response = await client.get(self.USERINFO_URL, headers=headers)
            if response.status_code != 200:
                raise QulfException(f"Failed to fetch user profile: {response.text}")

            user_data = response.json()

            # Fetch user emails if necessary
            email = user_data.get("email")
            if not email:
                emails_response = await client.get(
                    self.USERINFO_EMAILS_URL, headers=headers
                )
                if emails_response.status_code == 200:
                    emails = emails_response.json()
                    primary_email = next(
                        (e["email"] for e in emails if e["primary"]), None
                    )
                    verified_email = next(
                        (e["email"] for e in emails if e["verified"]), None
                    )
                    email = (
                        primary_email
                        or verified_email
                        or (emails[0]["email"] if emails else None)
                    )

            if not email:
                raise QulfException("Could not obtain email from GitHub")

            return OAuthUserProfile(
                id=str(user_data["id"]),
                email=email,
                name=user_data.get("name"),
                username=user_data.get("login"),
                avatar_url=user_data.get("avatar_url"),
                raw_data=user_data,
            )
