from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from jwt import ExpiredSignatureError, InvalidTokenError

from qulf import QulfRequest, QulfResponse, QulfRoute
from qulf.exceptions import QulfException, Requires2FAError
from qulf.plugins import QulfPlugin
from qulf.routing import CookieOptions
from qulf.types import Session, User


class TOTPPlugin(QulfPlugin):
    name = "totp"

    def get_custom_columns(self):
        return {"user": {"two_factor_enabled": bool, "two_factor_secret": str}}

    async def after_sign_in(self, user: User, session: Session) -> None:
        if (
            not self.auth
            or not user.model_extra
            or not user.model_extra.get("two_factor_enabled")
        ):
            return

        await self.auth.db.delete_session(session.token)

        # 3. Create a temporary JWT payload
        payload = {
            "sub": user.id,
            "type": "2fa_pending",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
        temp_token = jwt.encode(payload, self.auth.config.secret_key)

        # 4. Raise the error to stop the HTTP response and pass the token to the frontend
        raise Requires2FAError(temp_token)

    def get_routes(self) -> list[QulfRoute]:
        if not self.auth:
            return []

        async def totp_setup(request: QulfRequest) -> QulfResponse:
            session_data = await self.auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return QulfResponse(status_code=401, body={"detail": "Unauthorized"})

            session, user = session_data

            secret = pyotp.random_base32()

            await self.auth.db.update_user(user.id, {"two_factor_secret": secret})

            uri = pyotp.TOTP(secret).provisioning_uri(
                name=user.email, issuer_name=self.auth.config.project_name
            )
            return QulfResponse(status_code=200, body={"uri": uri})

        async def totp_enable(request: QulfRequest) -> QulfResponse:
            session_data = await self.auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return QulfResponse(status_code=401, body={"detail": "Unauthorized"})

            session, user = session_data

            code = request.body.get("code")
            if not code:
                return QulfResponse(
                    status_code=400, body={"detail": "2FA code missing."}
                )

            if not session:
                return QulfResponse(
                    status_code=400, body={"detail": "Invalid or expired session."}
                )

            secret = None

            if user.model_extra:
                secret = user.model_extra.get("two_factor_secret")

            if not secret:
                return QulfResponse(status_code=400, body={"detail": "2FA not set up."})

            is_valid = pyotp.TOTP(secret).verify(code)
            if not is_valid:
                return QulfResponse(
                    status_code=401, body={"detail": "Invalid 2FA code."}
                )

            await self.auth.db.update_user(user.id, {"two_factor_enabled": True})

            return QulfResponse(
                status_code=200, body={"message": "2FA enabled successfully!"}
            )

        async def totp_verify_login(request: QulfRequest) -> QulfResponse:
            temp_token = request.body.get("temp_token")
            code = request.body.get("code")

            if not code:
                return QulfResponse(
                    status_code=400, body={"detail": "2FA code missing."}
                )

            if not temp_token:
                return QulfResponse(
                    status_code=400, body={"detail": "Temporary Auth token missing."}
                )

            payload = None

            try:
                payload = jwt.decode(
                    temp_token, self.auth.config.secret_key, algorithms=["HS256"]
                )
            except (ExpiredSignatureError, InvalidTokenError):
                return QulfResponse(
                    status_code=401, body={"detail": "Invalid or expired token"}
                )

            user = await self.auth.db.get_user_by_id(payload["sub"])

            secret = None

            if not user:
                return QulfResponse(status_code=400, body={"detail": "User not found"})

            if not user.model_extra:
                # Not supposed to reach, added just to tell the compiler
                # the users `two_factor_secret` exists.
                return QulfResponse(status_code=401, body={"detail": "User not found"})

            secret = user.model_extra.get("two_factor_secret")

            if not secret:
                return QulfResponse(
                    status_code=401, body={"detail": "2FA is not set up for this user."}
                )

            is_valid = pyotp.TOTP(secret).verify(code)
            if not is_valid:
                return QulfResponse(
                    status_code=401, body={"detail": "Invalid 2FA code."}
                )

            try:
                session = await self.auth.create_session(
                    user, request.ip_address, request.user_agent
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
            QulfRoute(path="/2fa/setup", methods=["POST"], handler=totp_setup),
            QulfRoute(path="/2fa/enable", methods=["POST"], handler=totp_enable),
            QulfRoute(
                path="/2fa/verify_login", methods=["POST"], handler=totp_verify_login
            ),
        ]
