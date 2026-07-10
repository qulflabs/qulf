from fastapi import APIRouter, HTTPException, Request, Response

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.base import SignInRequest
from qulf.routing import QulfRequest
from qulf.types import User, UserCreate


def serve_qulf(auth: Qulf) -> APIRouter:
    """
    Constructs and returns a FastAPI APIRouter
    serving standard authentication endpoints.

    Includes plugin routers dynamically to
    group all auth routes under a single namespace.
    """
    router = APIRouter()

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
    async def sign_out(request: Request, response: Response) -> dict[str, str]:
        token = request.cookies.get(auth.config.cookies.name)
        if token:
            await auth.sign_out(token)

        response.delete_cookie(key=auth.config.cookies.name, path="/")
        return {"message": "Signed out"}

    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():

            def make_endpoint(handler):
                async def dynamic_endpoint(request: Request, response: Response):
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

            router.add_api_route(
                path=qulf_route.path,
                endpoint=make_endpoint(qulf_route.handler),
                methods=qulf_route.methods,
            )

    return router
