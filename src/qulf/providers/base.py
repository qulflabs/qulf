from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, EmailStr


class OAuthUserProfile(BaseModel):
    """
    Standardized user profile information returned by an OAuth provider.
    """

    id: str
    email: EmailStr
    name: str | None = None
    username: str | None = None
    avatar_url: str | None = None
    raw_data: dict[str, Any] | None = None


class OAuthTokenResponse(BaseModel):
    """
    Standardized token response from an OAuth provider after code exchange.
    """

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    id_token: str | None = None


class BaseOAuthProvider(ABC):
    """
    The abstract contract that all Qulf OAuth providers must implement.
    """

    id: str
    name: str

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or []

    @abstractmethod
    async def get_authorization_url(self, state: str) -> str:
        """
        Generates the authorization URL to redirect the user to.

        Args:
            state: A random string used to prevent CSRF attacks.

        Returns:
            The complete authorization URL as a string.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        """
        Exchanges the authorization code for an access token.

        Args:
            code: The authorization code returned by the provider.

        Returns:
            An OAuthTokenResponse containing the access token and other details.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        """
        Fetches the user's profile from the provider using the access token.

        Args:
            access_token: The access token obtained from exchange_code.

        Returns:
            An OAuthUserProfile containing standard user information.
        """
        pass  # pragma: no cover
