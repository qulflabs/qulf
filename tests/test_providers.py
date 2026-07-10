import pytest
from pydantic import ValidationError

from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)


class MockOAuthProvider(BaseOAuthProvider):
    async def get_authorization_url(self, state: str) -> str:
        return f"https://mock.example.com/auth?state={state}"

    async def exchange_code(self, code: str) -> OAuthTokenResponse:
        return OAuthTokenResponse(
            access_token="mock_access_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="mock_refresh_token",
            scope="read",
            id_token="mock_id_token",
        )

    async def get_user_profile(self, access_token: str) -> OAuthUserProfile:
        return OAuthUserProfile(
            id="123",
            email="test@example.com",
            name="Test User",
            username="testuser",
            avatar_url="https://example.com/avatar.png",
        )


def test_base_oauth_provider_cannot_be_instantiated() -> None:

    with pytest.raises(TypeError):
        BaseOAuthProvider(  # type: ignore[abstract]
            client_id="id", client_secret="secret", redirect_uri="http://localhost"
        )


def test_mock_oauth_provider_instantiation() -> None:
    provider = MockOAuthProvider(
        client_id="id",
        client_secret="secret",
        redirect_uri="http://localhost",
        scopes=["read", "write"],
    )

    assert provider.client_id == "id"
    assert provider.client_secret == "secret"
    assert provider.redirect_uri == "http://localhost"
    assert provider.scopes == ["read", "write"]


def test_oauth_user_profile_validation() -> None:
    # Valid profile
    profile = OAuthUserProfile(id="123", email="test@example.com")
    assert profile.id == "123"
    assert profile.email == "test@example.com"
    assert profile.name is None

    # Invalid email
    with pytest.raises(ValidationError):
        OAuthUserProfile(id="123", email="not_an_email")


def test_oauth_token_response_validation() -> None:
    # Valid response
    token = OAuthTokenResponse(access_token="abc", token_type="Bearer")
    assert token.access_token == "abc"
    assert token.token_type == "Bearer"
    assert token.expires_in is None

    # Missing required field
    with pytest.raises(ValidationError):
        OAuthTokenResponse(access_token="abc")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_github_provider_authorization_url() -> None:
    from qulf.providers.github import GitHubProvider
    provider = GitHubProvider(client_id="gh_id", client_secret="gh_secret", redirect_uri="http://localhost")
    url = await provider.get_authorization_url("state123")
    assert "https://github.com/login/oauth/authorize" in url
    assert "client_id=gh_id" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost" in url
    assert "state=state123" in url
    assert "scope=read%3Auser+user%3Aemail" in url


@pytest.mark.asyncio
async def test_google_provider_authorization_url() -> None:
    from qulf.providers.google import GoogleProvider
    provider = GoogleProvider(client_id="go_id", client_secret="go_secret", redirect_uri="http://localhost")
    url = await provider.get_authorization_url("state123")
    assert "https://accounts.google.com/o/oauth2/v2/auth" in url
    assert "client_id=go_id" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost" in url
    assert "state=state123" in url
    assert "response_type=code" in url
    assert "scope=openid+email+profile" in url
    assert "access_type=offline" in url
