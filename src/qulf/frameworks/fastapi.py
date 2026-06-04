from fastapi import APIRouter, HTTPException, Request, Response

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.base import SignInRequest
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
        plugin_router = plugin.get_fastapi_router(auth)
        if plugin_router:
            router.include_router(plugin_router)

    return router
