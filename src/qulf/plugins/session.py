from pydantic import BaseModel

from qulf.plugins.base import QulfPlugin
from qulf.routing import QulfRequest, QulfResponse, QulfRoute


class RevokeSessionRequest(BaseModel):
    token: str


class SessionManagementPlugin(QulfPlugin):
    name = "session_management"

    def get_routes(self) -> list[QulfRoute]:
        if not self.auth:
            return []

        async def list_sessions(request: QulfRequest) -> QulfResponse:
            """GET /session/list"""
            token = request.cookies.get(self.auth.config.cookies.name)
            if not token:
                return QulfResponse(
                    status_code=401, body={"detail": "Session token missing."}
                )

            result = await self.auth.validate_session(token)
            if not result:
                return QulfResponse(
                    status_code=401, body={"detail": "Invalid or expired session."}
                )

            session, user = result

            # Fetch sessions
            sessions = await self.auth.get_user_sessions(user.id)

            # Sanitize the sessions using 
            # Pydantic V2 model_dump to strip the secret token
            sanitized_sessions = [s.model_dump(exclude={"token"}) for s in sessions]

            return QulfResponse(status_code=200, body={"sessions": sanitized_sessions})

        async def revoke_session(request: QulfRequest) -> QulfResponse:
            """POST /session/revoke"""
            token = request.cookies.get(self.auth.config.cookies.name)
            if not token:
                return QulfResponse(
                    status_code=401, body={"detail": "Session token missing."}
                )

            result = await self.auth.validate_session(token)
            if not result:
                return QulfResponse(
                    status_code=401, body={"detail": "Invalid or expired session."}
                )

            session, user = result

            try:
                # Assuming request.json holds the parsed dict body.
                body = RevokeSessionRequest.model_validate(request.body)
            except Exception as e:
                return QulfResponse(
                    status_code=400, body={"detail": f"Invalid request body: {str(e)}"}
                )

            revoked = await self.auth.revoke_session(user.id, body.token)

            if not revoked:
                return QulfResponse(
                    status_code=404,
                    body={"detail": "Session not found or already revoked."},
                )

            return QulfResponse(
                status_code=200,
                body={"detail": "Session successfully revoked.", "revoked": True},
            )

        async def revoke_all_sessions(request: QulfRequest) -> QulfResponse:
            """POST /session/revoke-all"""
            token = request.cookies.get(self.auth.config.cookies.name)
            if not token:
                return QulfResponse(
                    status_code=401, body={"detail": "Session token missing."}
                )

            result = await self.auth.validate_session(token)
            if not result:
                return QulfResponse(
                    status_code=401, body={"detail": "Invalid or expired session."}
                )

            session, user = result

            # we pass the current `session.token`
            # to the except_token to not revoke the current session
            revoked_tokens = await self.auth.revoke_all_user_sessions(
                user.id, except_token=session.token
            )

            return QulfResponse(
                status_code=200,
                body={
                    "detail": "Other sessions successfully revoked.",
                    "revoked_count": len(revoked_tokens),
                },
            )

        return [
            QulfRoute(path="/session/list", methods=["GET"], handler=list_sessions),
            QulfRoute(path="/session/revoke", methods=["POST"], handler=revoke_session),
            QulfRoute(
                path="/session/revoke-all",
                methods=["POST"],
                handler=revoke_all_sessions,
            ),
        ]
