from collections.abc import Callable, Coroutine
from typing import Any, Literal, cast

from litestar import Request, Response, Router, delete, get, post, route
from litestar.datastructures import Cookie
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.types import Method

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    SignInRequest,
    VerifyEmailRequest,
)
from qulf.routing import QulfRequest
from qulf.types import Session, User, UserCreate


def get_current_session(
    auth: Qulf,
) -> Callable[[Request[Any, Any, Any]], Coroutine[Any, Any, Session]]:
    async def _dependency(request: Request[Any, Any, Any]) -> Session:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise NotAuthorizedException("Unauthorized")
        session, _ = session_data
        return session

    return _dependency


def get_current_user(
    auth: Qulf,
) -> Callable[[Request[Any, Any, Any]], Coroutine[Any, Any, User]]:
    async def _dependency(request: Request[Any, Any, Any]) -> User:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise NotAuthorizedException("Unauthorized")
        _, user = session_data
        return user

    return _dependency


def serve_qulf(auth: Qulf) -> Router:
    """
    Constructs and returns a Litestar Router
    serving standard authentication endpoints.
    """

    async def _get_authenticated_user_id(request: Request[Any, Any, Any]) -> str:
        token = request.cookies.get(auth.config.cookies.name)
        if not token:
            raise QulfException("Unauthorized")

        validated_session = await auth.validate_session(token)
        if validated_session:
            _, user = validated_session
            return str(user.id)
        raise QulfException("Unauthorized")

    @post("/sign-up")
    async def sign_up(data: UserCreate) -> User | Response[dict[str, str]]:
        try:
            return await auth.sign_up(data)
        except QulfException as e:
            return Response({"detail": str(e)}, status_code=400)

    @post("/sign-in")
    async def sign_in(
        data: SignInRequest, request: Request[Any, Any, Any]
    ) -> Response[dict[str, str]]:
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        try:
            session = await auth.sign_in(data.email, data.password, ip, user_agent)
        except QulfException as e:
            return Response({"detail": str(e)}, status_code=400)
        cookie = Cookie(
            key=auth.config.cookies.name,
            value=session.token,
            httponly=auth.config.cookies.http_only,
            secure=auth.config.cookies.secure,
            samesite=auth.config.cookies.same_site,
        )
        return Response(
            {"message": "Signed in successfully"}, cookies=[cookie], status_code=200
        )

    @get("/session")
    async def get_session(request: Request[Any, Any, Any]) -> dict[str, Any]:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise NotAuthorizedException("Unauthorized")

        session, user = session_data
        return {"session": session.model_dump(), "user": user.model_dump()}

    @post("/sign-out")
    async def sign_out(request: Request[Any, Any, Any]) -> Response[dict[str, str]]:
        token = request.cookies.get(auth.config.cookies.name)
        if token:
            await auth.sign_out(token)
        cookie = Cookie(
            key=auth.config.cookies.name,
            value="",
            httponly=auth.config.cookies.http_only,
            secure=auth.config.cookies.secure,
            samesite=auth.config.cookies.same_site,
            max_age=0,
        )

        return Response(
            {"message": "Signed out successfully"}, cookies=[cookie], status_code=200
        )

    @post("/forgot-password")
    async def forgot_password(data: ForgotPasswordRequest) -> Response[Any]:
        try:
            await auth.generate_password_reset_token(data.email)
            return Response({"message": "Reset link generated"})
        except QulfException as e:
            return Response({"detail": str(e)}, status_code=400)

    @post("/reset-password")
    async def reset_password(data: ResetPasswordRequest) -> Response[Any]:
        try:
            await auth.reset_password(data.token, data.new_password)
            return Response({"message": "Password reset successfully"})
        except QulfException as e:
            return Response({"detail": str(e)}, status_code=400)

    @post("/verify-email")
    async def verify_email(data: VerifyEmailRequest) -> Response[Any]:
        try:
            await auth.verify_email(data.token)
            return Response({"message": "Email verified successfully"})
        except QulfException as e:
            return Response({"detail": str(e)}, status_code=400)

    # AUTHENTICATED ROUTES
    @post("/change-password")
    async def change_password(
        data: ChangePasswordRequest, request: Request[Any, Any, Any]
    ) -> Response[Any]:
        try:
            user_id = await _get_authenticated_user_id(request)
            await auth.change_password(user_id, data.old_password, data.new_password)
            return Response({"message": "Password changed successfully"})
        except QulfException as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return Response({"detail": str(e)}, status_code=status_code)

    @delete("/delete-account", status_code=200)
    async def delete_account(request: Request[Any, Any, Any]) -> Response[Any]:
        try:
            user_id = await _get_authenticated_user_id(request)
            await auth.delete_account(user_id)
            await auth.revoke_all_user_sessions(user_id)
        except QulfException as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return Response({"detail": str(e)}, status_code=status_code)

        delete_cookie = Cookie(
            key=auth.config.cookies.name,
            value="",
            max_age=0,
        )
        return Response(
            {"message": "Account deleted successfully"}, cookies=[delete_cookie]
        )

    plugin_routes = []

    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():
            litestar_methods = cast(list[Method], [m.value for m in qulf_route.methods])

            def make_handler(route_def: Any) -> Any:
                @route(path=route_def.path, http_method=litestar_methods)
                async def dynamic_endpoint(
                    request: Request[Any, Any, Any],
                ) -> Response[Any]:
                    if route_def.require_roles or route_def.require_permissions:
                        from litestar.exceptions import (
                            NotAuthorizedException,
                            PermissionDeniedException,
                        )

                        session_data = await auth.get_session_from_cookies(
                            request.cookies
                        )
                        if not session_data:
                            raise NotAuthorizedException("Authentication required")

                        _, user = session_data

                        for role in route_def.require_roles:
                            if not await auth.has_role(user, role):
                                raise PermissionDeniedException(
                                    f"Missing required role: '{role}'"
                                )

                        for perm in route_def.require_permissions:
                            if not await auth.has_permission(user, perm):
                                raise PermissionDeniedException(
                                    f"Missing required permission: '{perm}'"
                                )
                    body = {}
                    if request.method in ["POST", "PUT", "PATCH"]:
                        try:
                            body = await request.json()
                        except Exception:
                            pass

                    # Litestar Request -> QulfRequest
                    qulf_request = QulfRequest(
                        body=body,
                        query_params=dict(request.query_params),
                        path_params=request.path_params,
                        cookies=request.cookies,
                        ip_address=request.client.host if request.client else None,
                        user_agent=request.headers.get("user-agent"),
                    )

                    qulf_response = await route_def.handler(qulf_request)

                    # QulfResponse -> Litestar Cookies
                    response_cookies: list[Cookie] = []

                    for c in qulf_response.set_cookies:
                        response_cookies.append(
                            Cookie(
                                key=c.key,
                                value=c.value,
                                httponly=c.httponly,
                                secure=c.secure,
                                samesite=c.samesite,
                            )
                        )

                    for cookie_name in qulf_response.delete_cookies:
                        response_cookies.append(
                            Cookie(key=cookie_name, value="", max_age=0)
                        )

                    return Response(
                        content=qulf_response.body
                        if qulf_response.body is not None
                        else {},
                        status_code=qulf_response.status_code,
                        headers=qulf_response.headers,
                        cookies=response_cookies,
                    )

                return dynamic_endpoint

            plugin_routes.append(make_handler(qulf_route))

    return Router(
        path="/",
        route_handlers=[
            sign_up,
            sign_in,
            get_session,
            sign_out,
            forgot_password,
            reset_password,
            verify_email,
            change_password,
            delete_account,
        ]
        + plugin_routes,
    )


class RequiresRole:
    """
    Litestar Dependency to protect native framework routes by Role via `Provide()`.
    """

    def __init__(
        self, auth: Qulf, roles: str | list[str], mode: Literal["any", "all"] = "all"
    ):
        self.auth = auth
        self.roles = [roles] if isinstance(roles, str) else roles
        self.mode = mode

    async def __call__(self, request: Request[Any, Any, Any]) -> User:
        session_data = await self.auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise NotAuthorizedException("Authentication required")

        _, user = session_data

        if self.mode == "all":
            for role in self.roles:
                if not await self.auth.has_role(user, role):
                    raise PermissionDeniedException(f"Missing required role: '{role}'")
        elif self.mode == "any":
            has_any = False
            for role in self.roles:
                if await self.auth.has_role(user, role):
                    has_any = True
                    break
            if not has_any:
                raise PermissionDeniedException(
                    f"Requires at least one role from: {self.roles}"
                )

        return user


class RequiresPermission:
    """
    Litestar Dependency to protect native framework routes
    by Permission via `Provide()`.
    """

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

    async def __call__(self, request: Request[Any, Any, Any]) -> User:
        session_data = await self.auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise NotAuthorizedException("Authentication required")

        _, user = session_data

        if self.mode == "all":
            for perm in self.permissions:
                if not await self.auth.has_permission(user, perm):
                    raise PermissionDeniedException(
                        f"Missing required permission: '{perm}'"
                    )
        elif self.mode == "any":
            has_any = False
            for perm in self.permissions:
                if await self.auth.has_permission(user, perm):
                    has_any = True
                    break
            if not has_any:
                raise PermissionDeniedException(
                    f"Requires at least one permission from: {self.permissions}"
                )

        return user
