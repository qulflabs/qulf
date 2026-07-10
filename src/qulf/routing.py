from collections.abc import Awaitable, Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class QulfRequest(BaseModel):
    """
    **An agnostic HTTP response.**
    """

    body: dict[str, Any] = {}
    query_params: dict[str, str] = {}
    ip_address: str | None = None
    user_agent: str | None = None


class CookieOptions(BaseModel):
    key: str
    value: str
    httponly: bool = True
    secure: bool = True
    samesite: Literal["lax", "none", "strict"] = "lax"


class QulfResponse(BaseModel):
    """
    **An agnostic HTTP response.**
    """

    status_code: int = 200
    body: dict[str, Any] = {}
    set_cookies: list[CookieOptions] = []
    delete_cookies: list[str] = []


class QulfRoute(BaseModel):
    """
    **A generic route definition that framework adapters will translate.**
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    path: str
    methods: list[str]
    # The handler must be an async function that takes a
    # QulfRequest and returns a QulfResponse
    handler: Callable[[QulfRequest], Awaitable[QulfResponse]]
