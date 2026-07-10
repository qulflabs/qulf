import secrets
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from qulf.crypto import generate_session_token, hash_password
from qulf.exceptions import (
    ConfigurationError,
    InvalidTokenError,
    QulfException,
    SessionExpiredError,
)
from qulf.plugins.base import QulfPlugin
from qulf.routing import CookieOptions, QulfRequest, QulfResponse, QulfRoute
from qulf.types import Session, User, UserCreate


class MagicLinkPlugin(QulfPlugin):
    """
    **A stateless passwordless authentication plugin.**

    Generates time-bound, cryptographically signed JSON Web Tokens (JWT)
    dispatched to the user's email, allowing credential-free sign-in's.
    """

    name = "magic_link"

    def __init__(
        self,
        send_email_func: Callable[[str, str], Awaitable[None]],
        expires_in_minutes: int = 15,
    ):
        self.send_email_func = send_email_func
        self.expires_in_minutes = expires_in_minutes
        self.auth = None

    def setup(self, auth: Any) -> None:
        self.auth = auth

    async def generate_and_send(self, email: str) -> None:
        """
        **Generates a stateless JWT token and passes it
        to the user-supplied dispatch handler.**
        """
        if not self.auth:
            raise ConfigurationError(
                "MagicLinkPlugin has not been initialized by Qulf."
            )
        payload = {
            "email": email,
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=self.expires_in_minutes),
        }
        token = jwt.encode(payload, self.auth.config.secret_key, algorithm="HS256")

        await self.send_email_func(email, token)

    async def verify_and_sign_in(
        self, token: str, ip_address: str | None = None, user_agent: str | None = None
    ) -> tuple[Session, User]:
        """
        **Verifies the magic link token.**

        Creates the user profile if it doesn't exist yet
        it initiates a standard session.
        """
        if not self.auth:
            raise ConfigurationError(
                "MagicLinkPlugin has not been initialized by Qulf."
            )

        try:
            payload = jwt.decode(
                token, self.auth.config.secret_key, algorithms=["HS256"]
            )
            email = payload["email"]
        except jwt.ExpiredSignatureError:
            raise SessionExpiredError("Magic link expired")
        except jwt.InvalidTokenError:
            raise InvalidTokenError("Invalid magic link")

        user = await self.auth.db.get_user_by_email(email)
        if not user:
            # If a user joins using a magic link, we automatically onboard them.
            # We generate a cryptographically strong, secure random password so the
            # account satisfies the DB structure requirements and remains secure
            # until they choose to associate a standard credential with their profile.
            random_pass = secrets.token_urlsafe(32)
            user_data = UserCreate(
                email=email,
                name=email.split("@")[0],
                username=email.split("@")[0],
                password=random_pass,
                password_confirmation=random_pass,
            )
            user = await self.auth.db.create_user(user_data, hash_password(random_pass))

        session_token = generate_session_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self.auth.config.sessions.expires_in_days
        )

        session = await self.auth.db.create_session(
            user_id=user.id,
            token=session_token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return session, user

    def get_routes(self) -> list[QulfRoute]:
        """Expose framework-agnostic routes for the Magic Link flow."""

        if not self.auth:
            return []

        async def send_magic_link(request: QulfRequest) -> QulfResponse:
            email = request.body.get("email")
            if not email:
                return QulfResponse(
                    status_code=400, body={"detail": "Email is required"}
                )

            await self.generate_and_send(email)
            return QulfResponse(status_code=200, body={"message": "Magic link sent"})

        async def verify_magic_link(request: QulfRequest) -> QulfResponse:
            token = request.body.get("token")
            if not token:
                return QulfResponse(
                    status_code=400, body={"detail": "Token is required"}
                )

            try:
                session, user = await self.verify_and_sign_in(
                    token, request.ip_address, request.user_agent
                )
            except QulfException as e:
                return QulfResponse(status_code=400, body={"detail": str(e)})

            cookie = CookieOptions(
                key=self.auth.config.cookies.name,
                value=session.token,
                httponly=self.auth.config.cookies.http_only,
                secure=self.auth.config.cookies.secure,
                samesite=self.auth.config.cookies.same_site,
            )

            return QulfResponse(
                status_code=200,
                set_cookies=[cookie],
                body={"message": "Signed in successfully", "user": user.model_dump()},
            )

        return [
            QulfRoute(
                path="/magic-link/send", methods=["POST"], handler=send_magic_link
            ),
            QulfRoute(
                path="/magic-link/verify", methods=["POST"], handler=verify_magic_link
            ),
        ]
