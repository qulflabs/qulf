from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.base import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    SignInRequest,
    VerifyEmailRequest,
)
from qulf.routing import QulfRequest, QulfResponse
from qulf.types import User, UserCreate

Handler = Callable[[QulfRequest], Awaitable[QulfResponse]]

Endpoint = Callable[[Request, Response], Coroutine[Any, Any, dict[str, Any] | None]]


def serve_qulf(auth: Qulf) -> APIRouter:
    """
    Constructs and returns a FastAPI APIRouter
    serving standard authentication endpoints.

    Includes plugin routers dynamically to
    group all auth routes under a single namespace.
    """
    router = APIRouter()

    async def _get_authenticated_user_id(request: Request) -> str:
        """Helper to extract user_id from the session cookie."""
        token = request.cookies.get(auth.config.cookies.name)
        if not token:
            raise HTTPException(status_code=401, detail="Unauthorized")

        try:
            validated_session = await auth.validate_session(token)
            if validated_session:
                session, user = validated_session
                return str(user.id)
            raise HTTPException(status_code=401, detail="Unauthorized")
        except QulfException as e:
            raise HTTPException(status_code=401, detail=str(e))

    @router.post("/sign-up", response_model=User)
    async def sign_up(user_data: UserCreate) -> User:
        try:
            return await auth.sign_up(user_data)
        except QulfException as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/sign-in")
    async def sign_in(
        payload: SignInRequest, request: Request, response: Response
    ) -> dict[str, str]:
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        try:
            session = await auth.sign_in(
                payload.email, payload.password, ip, user_agent
            )
        except QulfException as e:
            raise HTTPException(status_code=400, detail=str(e))

        response.set_cookie(
            key=auth.config.cookies.name,
            value=session.token,
            httponly=auth.config.cookies.http_only,
            secure=auth.config.cookies.secure,
            samesite=auth.config.cookies.same_site,
        )
        return {"message": "Signed in successfully"}

    @router.post("/sign-out")
    async def sign_out(request: Request, response: Response) -> dict[str, Any]:
        token = request.cookies.get(auth.config.cookies.name)
        if token:
            await auth.sign_out(token)

        response.delete_cookie(key=auth.config.cookies.name, path="/")
        return {"message": "Signed out"}

    @router.post("/forgot-password")
    async def forgot_password(payload: ForgotPasswordRequest) -> dict[str, str]:
        try:
            await auth.generate_password_reset_token(payload.email)
            return {"message": "Reset link generated"}
        except QulfException as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/reset-password")
    async def reset_password(payload: ResetPasswordRequest) -> dict[str, str]:
        try:
            await auth.reset_password(payload.token, payload.new_password)
            return {"message": "Password reset successfully"}
        except QulfException as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/verify-email")
    async def verify_email(payload: VerifyEmailRequest) -> dict[str, str]:
        try:
            await auth.verify_email(payload.token)
            return {"message": "Email verified successfully"}
        except QulfException as e:
            raise HTTPException(status_code=400, detail=str(e))

    # AUTHENTICATED ROUTES
    @router.post("/change-password")
    async def change_password(
        payload: ChangePasswordRequest, request: Request
    ) -> dict[str, str]:
        user_id = await _get_authenticated_user_id(request)
        try:
            await auth.change_password(
                user_id, payload.old_password, payload.new_password
            )
            return {"message": "Password changed successfully"}
        except QulfException as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.delete("/account")
    async def delete_account(request: Request, response: Response) -> dict[str, str]:
        user_id = await _get_authenticated_user_id(request)
        try:
            await auth.delete_account(user_id)
        except QulfException as e:
            raise HTTPException(status_code=400, detail=str(e))
        await auth.revoke_all_user_sessions(user_id)

        response.delete_cookie(key=auth.config.cookies.name, path="/")
        return {"message": "Account deleted successfully"}

    # AUTHENTICATED ROUTES
    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():

            def make_endpoint(handler: Handler) -> Endpoint:
                async def dynamic_endpoint(
                    request: Request, response: Response
                ) -> dict[str, Any] | None:
                    body = {}
                    if request.method in ["POST", "PUT", "PATCH"]:
                        try:
                            body = await request.json()
                        except Exception:
                            pass

                    qulf_request = QulfRequest(
                        body=body,
                        query_params=dict(request.query_params),
                        path_params=request.path_params,
                        cookies=request.cookies,
                        ip_address=request.client.host if request.client else None,
                        user_agent=request.headers.get("user-agent"),
                    )

                    qulf_response = await handler(qulf_request)

                    response.status_code = qulf_response.status_code

                    for key, value in qulf_response.headers.items():
                        response.headers[key] = value

                    for cookie in qulf_response.set_cookies:
                        response.set_cookie(
                            key=cookie.key,
                            value=cookie.value,
                            httponly=cookie.httponly,
                            secure=cookie.secure,
                            samesite=cookie.samesite,
                        )

                    for cookie_name in qulf_response.delete_cookies:
                        response.delete_cookie(key=cookie_name)

                    return qulf_response.body

                return dynamic_endpoint

            methods = [method.value for method in qulf_route.methods]
            router.add_api_route(
                path=qulf_route.path,
                endpoint=make_endpoint(qulf_route.handler),
                methods=methods,
            )

    return router
