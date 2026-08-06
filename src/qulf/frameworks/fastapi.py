from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, Response, status

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
from qulf.types import Session, User, UserCreate

Handler = Callable[[QulfRequest], Awaitable[QulfResponse]]

Endpoint = Callable[[Request, Response], Coroutine[Any, Any, dict[str, Any] | None]]


def get_current_session(
    auth: Qulf,
) -> Callable[[Request], Coroutine[Any, Any, Session]]:
    async def _dependency(request: Request) -> Session:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )
        session, _ = session_data
        return session

    return _dependency


def get_current_user(auth: Qulf) -> Callable[[Request], Coroutine[Any, Any, User]]:
    async def _dependency(request: Request) -> User:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )
        _, user = session_data
        return user

    return _dependency


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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )

        try:
            validated_session = await auth.validate_session(token)
            if validated_session:
                _, user = validated_session
                return str(user.id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )
        except QulfException as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    @router.post("/sign-up", response_model=User)
    async def sign_up(user_data: UserCreate) -> User:
        try:
            return await auth.sign_up(user_data)
        except QulfException as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

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
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        response.set_cookie(
            key=auth.config.cookies.name,
            value=session.token,
            httponly=auth.config.cookies.http_only,
            secure=auth.config.cookies.secure,
            samesite=auth.config.cookies.same_site,
        )
        return {"message": "Signed in successfully"}

    @router.get("/session")
    async def get_session(request: Request) -> Any:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )

        session, user = session_data
        return {"session": session.model_dump(), "user": user.model_dump()}

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
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    @router.post("/reset-password")
    async def reset_password(payload: ResetPasswordRequest) -> dict[str, str]:
        try:
            await auth.reset_password(payload.token, payload.new_password)
            return {"message": "Password reset successfully"}
        except QulfException as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    @router.post("/verify-email")
    async def verify_email(payload: VerifyEmailRequest) -> dict[str, str]:
        try:
            await auth.verify_email(payload.token)
            return {"message": "Email verified successfully"}
        except QulfException as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

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
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    @router.delete("/delete-account")
    async def delete_account(request: Request, response: Response) -> dict[str, str]:
        user_id = await _get_authenticated_user_id(request)
        try:
            await auth.delete_account(user_id)
        except QulfException as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        await auth.revoke_all_user_sessions(user_id)

        response.delete_cookie(key=auth.config.cookies.name, path="/")
        return {"message": "Account deleted successfully"}

    # PLUGIN ROUTES
    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():

            def make_endpoint(handler: Handler, route_config: Any) -> Endpoint:
                async def dynamic_endpoint(
                    request: Request, response: Response
                ) -> dict[str, Any] | None:

                    # RBAC ENFORCEMENT
                    if route_config.require_roles or route_config.require_permissions:
                        session_data = await auth.get_session_from_cookies(
                            request.cookies
                        )
                        if not session_data:
                            raise HTTPException(
                                status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Authentication required",
                            )

                        _, user = session_data

                        for role in route_config.require_roles:
                            if not await auth.has_role(user, role):
                                raise HTTPException(
                                    status_code=status.HTTP_403_FORBIDDEN,
                                    detail=f"Missing required role: '{role}'",
                                )

                        for perm in route_config.require_permissions:
                            if not await auth.has_permission(user, perm):
                                raise HTTPException(
                                    status_code=status.HTTP_403_FORBIDDEN,
                                    detail=f"Missing required permission: '{perm}'",
                                )

                    # parsing
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
                endpoint=make_endpoint(qulf_route.handler, qulf_route),
                methods=methods,
            )

    return router


class RequiresRole:
    """FastAPI Dependency to protect native framework routes by Role."""

    def __init__(
        self, auth: Qulf, roles: str | list[str], mode: Literal["any", "all"] = "all"
    ):
        self.auth = auth
        self.roles = [roles] if isinstance(roles, str) else roles
        self.mode = mode

    async def __call__(self, request: Request) -> User:
        session_data = await self.auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

        _, user = session_data

        if self.mode == "all":
            for role in self.roles:
                if not await self.auth.has_role(user, role):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing required role: '{role}'",
                    )

        elif self.mode == "any":
            has_any = False
            for role in self.roles:
                if await self.auth.has_role(user, role):
                    has_any = True
                    break
            if not has_any:
                raise HTTPException(
                    status_code=403,
                    detail=f"Requires at least one role from: {self.roles}",
                )

        return user


class RequiresPermission:
    """FastAPI Dependency to protect native framework routes by Permission."""

    def __init__(
        self,
        auth: Qulf,
        permissions: str | list[str],
        mode: Literal["any", "all"] = "all",
    ):
        self.auth = auth
        self.permissions = (
            [permissions] if isinstance(permissions, str) else permissions
        )
        self.mode = mode

    async def __call__(self, request: Request) -> User:
        session_data = await self.auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise HTTPException(status_code=401, detail="Authentication required")

        _, user = session_data

        if self.mode == "all":
            for perm in self.permissions:
                if not await self.auth.has_permission(user, perm):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing required permission: '{perm}'",
                    )

        elif self.mode == "any":
            has_any = False
            for perm in self.permissions:
                if await self.auth.has_permission(user, perm):
                    has_any = True
                    break
            if not has_any:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires at least one permission from: {self.permissions}",
                )

        return user
