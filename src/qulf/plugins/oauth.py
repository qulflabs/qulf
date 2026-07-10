# src/qulf/plugins/oauth.py
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from qulf.crypto import generate_session_token, hash_password
from qulf.exceptions import QulfException
from qulf.plugins.base import QulfPlugin
from qulf.routing import CookieOptions, QulfRequest, QulfResponse, QulfRoute
from qulf.types import AccountCreate, UserCreate


class OAuthPlugin(QulfPlugin):
    name = "oauth"

    def __init__(self):
        self.auth = None

    def setup(self, auth: Any) -> None:
        self.auth = auth

    def get_routes(self) -> list[QulfRoute]:
        if not self.auth:
            return []

        async def login(request: QulfRequest) -> QulfResponse:
            provider_id = request.path_params.get("provider")

            provider = next(
                (p for p in self.auth.config.oauth_providers if p.id == provider_id),
                None,
            )
            if not provider:
                return QulfResponse(
                    status_code=404,
                    body={"detail": f"Provider {provider_id} not configured"},
                )

            state = secrets.token_urlsafe(32)
            auth_url = await provider.get_authorization_url(state=state)

            state_cookie = CookieOptions(
                key=f"qulf_oauth_state_{provider_id}",
                value=state,
                httponly=True,
                secure=self.auth.config.cookies.secure,
                samesite="lax",
            )

            return QulfResponse(
                status_code=302,
                headers={"Location": auth_url},
                set_cookies=[state_cookie],
            )

        async def callback(request: QulfRequest) -> QulfResponse:
            provider_id = request.path_params.get("provider")
            provider = next(
                (p for p in self.auth.config.oauth_providers if p.id == provider_id),
                None,
            )
            if not provider:
                return QulfResponse(
                    status_code=404, body={"detail": "Provider not configured"}
                )

            code = request.query_params.get("code")
            state = request.query_params.get("state")

            if not code or not state:
                return QulfResponse(
                    status_code=400, body={"detail": "Missing code or state"}
                )

            # Verify CSRF State
            cookie_state = request.cookies.get(f"qulf_oauth_state_{provider_id}")
            if not cookie_state or cookie_state != state:
                return QulfResponse(
                    status_code=400,
                    body={"detail": "State mismatch. CSRF attempt blocked."},
                )

            try:
                token_res = await provider.exchange_code(code)
                profile = await provider.get_user_profile(token_res.access_token)
            except QulfException as e:
                return QulfResponse(status_code=400, body={"detail": str(e)})

            # ACCOUNT LINKING
            account = await self.auth.db.get_account_by_provider(
                provider_id=provider.id, account_id=profile.id
            )

            if account:
                user = await self.auth.db.get_user_by_id(account.user_id)
                if not user:
                    return QulfResponse(
                        status_code=500,
                        body={
                            "detail": """Database integrity error:
                             Account has no linked User"""
                        },
                    )
            else:
                user = await self.auth.db.get_user_by_email(profile.email)
                if not user:
                    random_pass = secrets.token_urlsafe(32)

                    safe_username = (
                        profile.username
                        or f"{profile.email.split('@')[0]}_{secrets.token_hex(4)}"
                    )

                    user_data = UserCreate(
                        email=profile.email,
                        name=profile.name or safe_username,
                        username=safe_username,
                        password=random_pass,
                        password_confirmation=random_pass,
                    )
                    user = await self.auth.db.create_user(
                        user_data, hash_password(random_pass)
                    )

                # 4. Link the new OAuth Account to the User
                expires_at = None
                if token_res.expires_in:
                    expires_at = datetime.now(timezone.utc) + timedelta(
                        seconds=token_res.expires_in
                    )

                account_data = AccountCreate(
                    user_id=user.id,
                    account_id=profile.id,
                    provider_id=provider.id,
                    access_token=token_res.access_token,
                    refresh_token=token_res.refresh_token,
                    expires_at=expires_at,
                    scope=token_res.scope,
                    id_token=token_res.id_token,
                )
                await self.auth.db.create_account(account_data)


            # Create Session
            session_token = generate_session_token()
            expires_at = datetime.now(timezone.utc) + timedelta(
                days=self.auth.config.sessions.expires_in_days
            )

            session = await self.auth.db.create_session(
                user_id=user.id,
                token=session_token,
                expires_at=expires_at,
                ip_address=request.ip_address,
                user_agent=request.user_agent,
            )

            session_cookie = CookieOptions(
                key=self.auth.config.cookies.name,
                value=session.token,
                httponly=self.auth.config.cookies.http_only,
                secure=self.auth.config.cookies.secure,
                samesite=self.auth.config.cookies.same_site,
            )

            return QulfResponse(
                status_code=200,
                set_cookies=[session_cookie],
                delete_cookies=[f"qulf_oauth_state_{provider_id}"],
                body={"message": "OAuth login successful", "user": user.model_dump()},
            )

        return [
            QulfRoute(path="/oauth/{provider}/login", methods=["GET"], handler=login),
            QulfRoute(
                path="/oauth/{provider}/callback", methods=["GET"], handler=callback
            ),
        ]
