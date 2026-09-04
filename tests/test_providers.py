import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import Response
from pydantic import ValidationError

from qulf.exceptions import QulfException
from qulf.providers.apple import AppleProvider
from qulf.providers.base import (
    BaseOAuthProvider,
    OAuthTokenResponse,
    OAuthUserProfile,
)
from qulf.providers.discord import DiscordProvider
from qulf.providers.github import GitHubProvider
from qulf.providers.google import GoogleProvider
from qulf.providers.oidc import OIDCProvider


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
            OAuthTokenResponse.model_validate({"access_token": "abc"})


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


@pytest.mark.asyncio
class TestDiscordProvider:
    @pytest.fixture
    def provider(self) -> DiscordProvider:
        return DiscordProvider(
            client_id="dc_id",
            client_secret="dc_secret",
            redirect_uri="http://localhost/callback",
        )

    async def test_discord_authorization_url_default_scopes(
        self, provider: DiscordProvider
    ) -> None:
        url = await provider.get_authorization_url("state_abc")
        assert "https://discord.com/oauth2/authorize" in url
        assert "client_id=dc_id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback" in url
        assert "state=state_abc" in url
        assert "response_type=code" in url
        assert "scope=identify+email" in url
        assert "prompt=consent" in url

    async def test_discord_authorization_url_custom_scopes(self) -> None:
        provider = DiscordProvider(
            client_id="dc_id",
            client_secret="dc_secret",
            redirect_uri="http://localhost/callback",
            scopes=["identify", "email", "guilds"],
        )
        url = await provider.get_authorization_url("s")
        assert "scope=identify+email+guilds" in url

    @respx.mock
    async def test_discord_exchange_code_success(
        self, provider: DiscordProvider
    ) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "dc_token",
                    "token_type": "Bearer",
                    "expires_in": 604800,
                    "refresh_token": "dc_refresh",
                    "scope": "identify email",
                },
            )
        )
        token = await provider.exchange_code("code123")
        assert token.access_token == "dc_token"
        assert token.token_type == "Bearer"
        assert token.expires_in == 604800
        assert token.refresh_token == "dc_refresh"
        assert token.scope == "identify email"

    @respx.mock
    async def test_discord_exchange_code_http_error(
        self, provider: DiscordProvider
    ) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(401, text="Unauthorized")
        )
        with pytest.raises(QulfException, match="Failed to fetch access token"):
            await provider.exchange_code("bad_code")

    @respx.mock
    async def test_discord_exchange_code_json_error(
        self, provider: DiscordProvider
    ) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(
                200,
                json={"error": "invalid_grant", "error_description": "Invalid code"},
            )
        )
        with pytest.raises(QulfException, match="Invalid code"):
            await provider.exchange_code("bad_code")

    @respx.mock
    async def test_discord_exchange_code_json_error_no_description(
        self, provider: DiscordProvider
    ) -> None:
        # Falls back to the raw error key when no description is present.
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(200, json={"error": "invalid_client"})
        )
        with pytest.raises(QulfException, match="invalid_client"):
            await provider.exchange_code("bad_code")

    @respx.mock
    async def test_discord_get_user_profile_with_avatar(
        self, provider: DiscordProvider
    ) -> None:
        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(
                200,
                json={
                    "id": "123456789",
                    "email": "user@discord.com",
                    "username": "cool_user",
                    "global_name": "Cool User",
                    "avatar": "abc123hash",
                    "verified": True,
                },
            )
        )
        profile = await provider.get_user_profile("dc_token")
        assert profile.id == "123456789"
        assert profile.email == "user@discord.com"
        assert profile.name == "Cool User"
        assert profile.username == "cool_user"
        assert (
            profile.avatar_url
            == "https://cdn.discordapp.com/avatars/123456789/abc123hash.png"
        )

    @respx.mock
    async def test_discord_get_user_profile_no_avatar(
        self, provider: DiscordProvider
    ) -> None:
        # Users without a custom avatar have avatar=None; avatar_url should be None.
        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(
                200,
                json={
                    "id": "987",
                    "email": "noavatar@discord.com",
                    "username": "plain_user",
                    "global_name": None,
                    "avatar": None,
                    "verified": True,
                },
            )
        )
        profile = await provider.get_user_profile("dc_token")
        assert profile.avatar_url is None
        # Falls back to username when global_name is None.
        assert profile.name == "plain_user"

    @respx.mock
    async def test_discord_get_user_profile_legacy_username_display_name(
        self, provider: DiscordProvider
    ) -> None:
        # Older Discord accounts may not have global_name; fall back to username.
        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(
                200,
                json={
                    "id": "111",
                    "email": "legacy@discord.com",
                    "username": "legacy_user#1234",
                    "verified": True,
                },
            )
        )
        profile = await provider.get_user_profile("dc_token")
        assert profile.name == "legacy_user#1234"

    @respx.mock
    async def test_discord_get_user_profile_http_error(
        self, provider: DiscordProvider
    ) -> None:
        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(401, text="401: Unauthorized")
        )
        with pytest.raises(QulfException, match="Failed to fetch user profile"):
            await provider.get_user_profile("bad_token")

    @respx.mock
    async def test_discord_get_user_profile_missing_email(
        self, provider: DiscordProvider
    ) -> None:
        # Happens when the token was issued without the `email` scope.
        respx.get(provider.USERINFO_URL).mock(
            return_value=Response(
                200,
                json={"id": "222", "username": "noemail_user", "verified": True},
            )
        )
        with pytest.raises(QulfException, match="Could not obtain email from Discord"):
            await provider.get_user_profile("dc_token")


@pytest.mark.asyncio
class TestAppleProvider:
    @pytest.fixture
    def ec_private_key(self) -> str:
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode("utf-8")

    @pytest.fixture
    def provider(self, ec_private_key: str) -> AppleProvider:
        return AppleProvider(
            client_id="com.example.app",
            team_id="TEAM123456",
            key_id="KEY1234567",
            private_key=ec_private_key,
            redirect_uri="https://example.com/callback",
        )

    async def test_apple_authorization_url_default_scopes(
        self, provider: AppleProvider
    ) -> None:
        url = await provider.get_authorization_url("state123")
        assert "https://appleid.apple.com/auth/authorize" in url
        assert "client_id=com.example.app" in url
        assert "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback" in url
        assert "state=state123" in url
        assert "response_type=code" in url
        assert "scope=name+email" in url
        assert "response_mode=form_post" in url

    async def test_apple_authorization_url_custom_scopes(
        self, ec_private_key: str
    ) -> None:
        provider = AppleProvider(
            client_id="com.example.app",
            team_id="TEAM123456",
            key_id="KEY1234567",
            private_key=ec_private_key,
            redirect_uri="https://example.com/callback",
            scopes=["email"],
        )
        url = await provider.get_authorization_url("state123")
        assert "scope=email" in url

    @respx.mock
    async def test_apple_exchange_code_success(self, provider: AppleProvider) -> None:
        mock_id_token = jwt.encode(
            {"sub": "apple_user_123", "email": "user@example.com"},
            "secret_key_32_bytes_long_1234567890",
            algorithm="HS256",
        )
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "apple_access_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "apple_refresh_token",
                    "id_token": mock_id_token,
                },
            )
        )
        token = await provider.exchange_code("code123")
        assert token.access_token == "apple_access_token"
        assert token.id_token == mock_id_token
        assert provider._pending_id_token == mock_id_token

    @respx.mock
    async def test_apple_exchange_code_http_error(
        self, provider: AppleProvider
    ) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(400, text="Bad Request")
        )
        with pytest.raises(QulfException, match="Failed to fetch access token"):
            await provider.exchange_code("bad_code")

    @respx.mock
    async def test_apple_exchange_code_json_error(
        self, provider: AppleProvider
    ) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(
                200,
                json={"error": "invalid_grant", "error_description": "Invalid code"},
            )
        )
        with pytest.raises(QulfException, match="Apple OAuth error: Invalid code"):
            await provider.exchange_code("bad_code")

    @respx.mock
    async def test_apple_exchange_code_json_error_no_description(
        self, provider: AppleProvider
    ) -> None:
        respx.post(provider.TOKEN_URL).mock(
            return_value=Response(200, json={"error": "invalid_client"})
        )
        with pytest.raises(QulfException, match="Apple OAuth error: invalid_client"):
            await provider.exchange_code("bad_code")

    async def test_apple_get_user_profile_success(
        self, provider: AppleProvider
    ) -> None:
        mock_id_token = jwt.encode(
            {"sub": "apple_user_123", "email": "user@example.com"},
            "secret_key_32_bytes_long_1234567890",
            algorithm="HS256",
        )
        provider._pending_id_token = mock_id_token

        profile = await provider.get_user_profile("apple_access_token")
        assert profile.id == "apple_user_123"
        assert profile.email == "user@example.com"
        assert profile.name is None
        assert profile.username is None
        assert profile.avatar_url is None
        assert profile.raw_data == {
            "sub": "apple_user_123",
            "email": "user@example.com",
        }
        assert provider._pending_id_token is None

    async def test_apple_get_user_profile_missing_pending_id_token(
        self, provider: AppleProvider
    ) -> None:
        with pytest.raises(QulfException, match="Apple id_token unavailable"):
            await provider.get_user_profile("apple_access_token")

    async def test_apple_get_user_profile_invalid_id_token(
        self, provider: AppleProvider
    ) -> None:
        invalid_token: str | None = "invalid.token.str"
        provider._pending_id_token = invalid_token
        with pytest.raises(QulfException, match="Failed to decode Apple id_token"):
            await provider.get_user_profile("apple_access_token")
        assert provider._pending_id_token is None

    async def test_apple_get_user_profile_missing_email(
        self, provider: AppleProvider
    ) -> None:
        mock_id_token: str | None = jwt.encode(
            {"sub": "apple_user_123"},
            "secret_key_32_bytes_long_1234567890",
            algorithm="HS256",
        )
        provider._pending_id_token = mock_id_token
        with pytest.raises(QulfException, match="Could not obtain email from Apple"):
            await provider.get_user_profile("apple_access_token")
        assert provider._pending_id_token is None


@pytest.mark.asyncio
class TestOIDCProvider:
    async def test_oidc_init_validation(self) -> None:
        with pytest.raises(
            QulfException, match="OIDCProvider requires either an 'issuer'"
        ):
            OIDCProvider(
                client_id="id",
                client_secret="secret",
                redirect_uri="http://localhost/cb",
            )

        with pytest.raises(
            QulfException, match="OIDCProvider requires either an 'issuer'"
        ):
            OIDCProvider(
                client_id="id",
                client_secret="secret",
                redirect_uri="http://localhost/cb",
                authorization_url="http://auth.com",
            )

        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="http://auth.com/authorize",
            token_url="http://auth.com/token",
            id="custom_id",
            name="Custom Provider",
        )
        assert provider.id == "custom_id"
        assert provider.name == "Custom Provider"
        assert provider.scopes == ["openid", "profile", "email"]

    async def test_oidc_missing_authorization_url(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="http://auth.com/authorize",
            token_url="http://auth.com/token",
        )
        provider.authorization_url = None
        with pytest.raises(
            QulfException, match="OIDC authorization_url is not configured"
        ):
            await provider.get_authorization_url("state")

    async def test_oidc_missing_token_url(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="http://auth.com/authorize",
            token_url="http://auth.com/token",
        )
        provider.token_url = None
        with pytest.raises(QulfException, match="OIDC token_url is not configured"):
            await provider.exchange_code("code")

    @respx.mock
    async def test_oidc_discovery_success(self) -> None:
        issuer = "https://auth.example.com"
        respx.get(f"{issuer}/.well-known/openid-configuration").mock(
            return_value=Response(
                200,
                json={
                    "authorization_endpoint": f"{issuer}/oauth/authorize",
                    "token_endpoint": f"{issuer}/oauth/token",
                    "userinfo_endpoint": f"{issuer}/oauth/userinfo",
                },
            )
        )
        provider = OIDCProvider(
            client_id="oidc_id",
            client_secret="oidc_secret",
            redirect_uri="http://localhost/cb",
            issuer=issuer,
        )
        url = await provider.get_authorization_url("state123")
        assert f"{issuer}/oauth/authorize" in url
        assert "client_id=oidc_id" in url
        assert "state=state123" in url
        assert provider._discovered is True
        assert provider.token_url == f"{issuer}/oauth/token"
        assert provider.userinfo_url == f"{issuer}/oauth/userinfo"

    @respx.mock
    async def test_oidc_discovery_http_error(self) -> None:
        issuer = "https://bad.example.com"
        respx.get(f"{issuer}/.well-known/openid-configuration").mock(
            return_value=Response(500, text="Internal Server Error")
        )
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            issuer=issuer,
        )
        with pytest.raises(
            QulfException, match="Failed to fetch OIDC discovery document"
        ):
            await provider.get_authorization_url("state")

    @respx.mock
    async def test_oidc_discovery_missing_endpoints(self) -> None:
        issuer = "https://missing.example.com"
        respx.get(f"{issuer}/.well-known/openid-configuration").mock(
            return_value=Response(200, json={})
        )
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            issuer=issuer,
        )
        with pytest.raises(
            QulfException, match="OIDC discovery document missing required"
        ):
            await provider.get_authorization_url("state")

    @respx.mock
    async def test_oidc_exchange_code_success(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
        )
        respx.post(provider.token_url).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "acc_123",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "ref_123",
                    "id_token": "id_123",
                },
            )
        )
        token = await provider.exchange_code("code123")
        assert token.access_token == "acc_123"
        assert token.id_token == "id_123"

    @respx.mock
    async def test_oidc_exchange_code_http_error(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
        )
        respx.post(provider.token_url).mock(
            return_value=Response(400, text="Bad Request")
        )
        with pytest.raises(QulfException, match="Failed to fetch access token"):
            await provider.exchange_code("code")

    @respx.mock
    async def test_oidc_exchange_code_json_error(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
        )
        respx.post(provider.token_url).mock(
            return_value=Response(
                200, json={"error": "invalid_grant", "error_description": "Bad code"}
            )
        )
        with pytest.raises(QulfException, match="OIDC OAuth error: Bad code"):
            await provider.exchange_code("code")

    @respx.mock
    async def test_oidc_get_user_profile_success(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
            userinfo_url="https://auth.com/userinfo",
        )
        respx.get("https://auth.com/userinfo").mock(
            return_value=Response(
                200,
                json={
                    "sub": "oidc_user_789",
                    "email": "oidc@example.com",
                    "name": "OIDC User",
                    "preferred_username": "oidc_user",
                    "picture": "https://example.com/avatar.png",
                },
            )
        )
        profile = await provider.get_user_profile("token_123")
        assert profile.id == "oidc_user_789"
        assert profile.email == "oidc@example.com"
        assert profile.name == "OIDC User"
        assert profile.username == "oidc_user"
        assert profile.avatar_url == "https://example.com/avatar.png"

    @respx.mock
    async def test_oidc_get_user_profile_name_fallbacks(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
            userinfo_url="https://auth.com/userinfo",
        )
        respx.get("https://auth.com/userinfo").mock(
            return_value=Response(
                200,
                json={
                    "sub": "oidc_user_789",
                    "email": "user.name@example.com",
                    "given_name": "Jane",
                    "family_name": "Doe",
                },
            )
        )
        profile = await provider.get_user_profile("token_123")
        assert profile.name == "Jane Doe"
        assert profile.username == "user.name"

    async def test_oidc_get_user_profile_missing_userinfo_url(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
        )
        with pytest.raises(QulfException, match="OIDC userinfo_url is not configured"):
            await provider.get_user_profile("token")

    @respx.mock
    async def test_oidc_get_user_profile_http_error(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
            userinfo_url="https://auth.com/userinfo",
        )
        respx.get("https://auth.com/userinfo").mock(
            return_value=Response(401, text="Unauthorized")
        )
        with pytest.raises(QulfException, match="Failed to fetch user profile"):
            await provider.get_user_profile("token")

    @respx.mock
    async def test_oidc_get_user_profile_missing_sub(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
            userinfo_url="https://auth.com/userinfo",
        )
        respx.get("https://auth.com/userinfo").mock(
            return_value=Response(200, json={"email": "nosub@example.com"})
        )
        with pytest.raises(
            QulfException, match="Could not obtain sub from OIDC provider"
        ):
            await provider.get_user_profile("token")

    @respx.mock
    async def test_oidc_get_user_profile_missing_email(self) -> None:
        provider = OIDCProvider(
            client_id="id",
            client_secret="secret",
            redirect_uri="http://localhost/cb",
            authorization_url="https://auth.com/authorize",
            token_url="https://auth.com/token",
            userinfo_url="https://auth.com/userinfo",
        )
        respx.get("https://auth.com/userinfo").mock(
            return_value=Response(200, json={"sub": "123"})
        )
        with pytest.raises(
            QulfException, match="Could not obtain email from OIDC provider"
        ):
            await provider.get_user_profile("token")
