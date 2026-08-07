import pytest
import respx
from httpx import Response
from pydantic import ValidationError

from qulf.exceptions import QulfException
from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)
from qulf.providers.github import GitHubProvider
from qulf.providers.google import GoogleProvider


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


class TestOAuthBaseAndModels:
    def test_base_oauth_provider_cannot_be_instantiated(self) -> None:
        with pytest.raises(TypeError):
            BaseOAuthProvider(  # type: ignore[abstract]
                client_id="id", client_secret="secret", redirect_uri="http://localhost"
            )

    def test_mock_oauth_provider_instantiation(self) -> None:
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

    def test_oauth_user_profile_validation(self) -> None:
        profile = OAuthUserProfile(id="123", email="test@example.com")
        assert profile.id == "123"
        assert profile.email == "test@example.com"
        assert profile.name is None

        with pytest.raises(ValidationError):
            OAuthUserProfile(id="123", email="not_an_email")

    def test_oauth_token_response_validation(self) -> None:
        token = OAuthTokenResponse(access_token="abc", token_type="Bearer")
        assert token.access_token == "abc"
        assert token.token_type == "Bearer"
        assert token.expires_in is None

        with pytest.raises(ValidationError):
            OAuthTokenResponse(access_token="abc")


@pytest.mark.asyncio
class TestGitHubProvider:
    @pytest.fixture
    def provider(self) -> GitHubProvider:
        return GitHubProvider(
            client_id="gh_id",
            client_secret="gh_secret",
            redirect_uri="http://localhost",
        )

    async def test_github_provider_authorization_url(
        self, provider: GitHubProvider
    ) -> None:
        url = await provider.get_authorization_url("state123")
        assert "https://github.com/login/oauth/authorize" in url
        assert "client_id=gh_id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost" in url
        assert "state=state123" in url
        assert "scope=read%3Auser+user%3Aemail" in url

    @respx.mock
    async def test_github_exchange_code(self, provider: GitHubProvider) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(
                200, json={"access_token": "abc", "token_type": "bearer"}
            )
        )
        token = await provider.exchange_code("code")
        assert token.access_token == "abc"

        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(400, text="Bad Request")
        )
        with pytest.raises(QulfException, match="Failed to fetch access token"):
            await provider.exchange_code("code")

        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(
                200, json={"error": "bad", "error_description": "invalid code"}
            )
        )
        with pytest.raises(QulfException, match="invalid code"):
            await provider.exchange_code("code")

    @respx.mock
    async def test_github_get_user_profile(self, provider: GitHubProvider) -> None:
        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(
                200, json={"id": 1, "email": "main@gh.com", "login": "ghuser"}
            )
        )
        profile = await provider.get_user_profile("token")
        assert profile.email == "main@gh.com"

        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(200, json={"id": 1, "login": "ghuser"})
        )
        respx.get(provider.USERINFO_EMAILS_URL).mock(
            return_value=Response(
                200, json=[{"email": "sec@gh.com", "primary": True, "verified": True}]
            )
        )
        profile2 = await provider.get_user_profile("token")
        assert profile2.email == "sec@gh.com"

        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(401, text="Unauthorized")
        )
        with pytest.raises(QulfException, match="Failed to fetch user profile"):
            await provider.get_user_profile("token")

        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(200, json={"id": 1, "login": "ghuser"})
        )
        respx.get(provider.USERINFO_EMAILS_URL).mock(
            return_value=Response(200, json=[])
        )
        with pytest.raises(QulfException, match="Could not obtain email from GitHub"):
            await provider.get_user_profile("token")


@pytest.mark.asyncio
class TestGoogleProvider:
    @pytest.fixture
    def provider(self) -> GoogleProvider:
        return GoogleProvider(
            client_id="go_id",
            client_secret="go_secret",
            redirect_uri="http://localhost",
        )

    async def test_google_provider_authorization_url(
        self, provider: GoogleProvider
    ) -> None:
        url = await provider.get_authorization_url("state123")
        assert "https://accounts.google.com/o/oauth2/v2/auth" in url
        assert "client_id=go_id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost" in url
        assert "state=state123" in url
        assert "response_type=code" in url
        assert "scope=openid+email+profile" in url
        assert "access_type=offline" in url

    @respx.mock
    async def test_google_exchange_code(self, provider: GoogleProvider) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(200, json={"access_token": "abc"})
        )
        token = await provider.exchange_code("code")
        assert token.access_token == "abc"

        respx.post(provider.TOKEN_URL).mock(return_value=Response(400, text="Bad"))
        with pytest.raises(QulfException):
            await provider.exchange_code("code")

        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(200, json={"error": "invalid"})
        )
        with pytest.raises(QulfException):
            await provider.exchange_code("code")

    @respx.mock
    async def test_google_get_user_profile(self, provider: GoogleProvider) -> None:
        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(
                200, json={"sub": "1", "email": "go@go.com", "name": "Go"}
            )
        )
        profile = await provider.get_user_profile("token")
        assert profile.email == "go@go.com"

        respx.get(provider.USERINFO_URL).mock(return_value=Response(400, text="Bad"))
        with pytest.raises(QulfException):
            await provider.get_user_profile("token")

        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(200, json={"sub": "1"})
        )
        with pytest.raises(QulfException, match="Could not obtain email from Google"):
            await provider.get_user_profile("token")
