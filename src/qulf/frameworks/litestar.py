from typing import Any, cast

from litestar import Request, Response, Router, post, route
from litestar.datastructures import Cookie
from litestar.types import Method

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.base import SignInRequest
from qulf.routing import QulfRequest
from qulf.types import User, UserCreate


def serve_qulf(auth: Qulf) -> Router:
    """
    Constructs and returns a Litestar Router
    serving standard authentication endpoints.
    """

    @post("/sign-up")
    async def sign_up(data: UserCreate) -> User | Response[dict[str, str]]:
        # Notice how Litestar magically parses `data` into UserCreate!
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

    # Plugin Routing
    plugin_routes = []

    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():
            litestar_methods = cast(list[Method], [m.value for m in qulf_route.methods])

            def make_handler(route_def: Any) -> Any:
                @route(path=route_def.path, http_method=litestar_methods)
                async def dynamic_endpoint(
                    request: Request[Any, Any, Any],
                ) -> Response[Any]:
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

                    # Await handler
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

                    # Return Litestar Response
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

    return Router(path="/", route_handlers=[sign_up, sign_in, sign_out] + plugin_routes)
