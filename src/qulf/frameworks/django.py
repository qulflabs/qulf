import json
from typing import Any, Literal, cast

from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from pydantic import ValidationError

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.frameworks.base import SignInRequest
from qulf.routing import QulfRequest
from qulf.types import UserCreate


def _get_client_ip(request: HttpRequest) -> str | None:
    """
    Safely extract the IP address using hasattr for forward/backward compatibility.
    """
    if hasattr(request, "headers"):
        if forwarded := request.headers.get("X-Forwarded-For"):
            return forwarded.split(",")[0].strip()

    if hasattr(request, "META"):
        value: Any = request.META.get("HTTP_X_FORWARDED_FOR")

        if isinstance(value, str):
            if forwarded := value:
                return forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    return None


def _get_user_agent(request: HttpRequest) -> str | None:
    """Safely extract the User-Agent using hasattr."""
    if hasattr(request, "headers"):
        return request.headers.get("User-Agent")
    if hasattr(request, "META"):
        return request.META.get("HTTP_USER_AGENT")
    return None


def serve_qulf(auth: Qulf) -> list[Any]:
    """
    Constructs and returns a list of Django URL patterns
    serving standard authentication endpoints.
    """

    async def sign_up(request: HttpRequest) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"detail": "Method not allowed"}, status=405)

        try:
            body = json.loads(request.body)
            user_data = UserCreate(**body)
            user = await auth.sign_up(user_data)
            return JsonResponse(user.model_dump())
        except (ValueError, ValidationError, QulfException) as e:
            return JsonResponse({"detail": str(e)}, status=400)

    async def sign_in(request: HttpRequest) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"detail": "Method not allowed"}, status=405)

        ip = _get_client_ip(request)
        user_agent = _get_user_agent(request)

        try:
            body = json.loads(request.body)
            payload = SignInRequest(**body)
            session = await auth.sign_in(
                payload.email, payload.password, ip, user_agent
            )
        except (ValueError, ValidationError, QulfException) as e:
            return JsonResponse({"detail": str(e)}, status=400)

        response = JsonResponse({"message": "Signed in successfully"})
        print("Same site:", auth.config.cookies.same_site)
        response.set_cookie(
            key=auth.config.cookies.name,
            value=session.token,
            httponly=auth.config.cookies.http_only,
            secure=auth.config.cookies.secure,
            samesite=cast(
                Literal["Lax", "None", "Strict"],
                auth.config.cookies.same_site.capitalize(),
            )
            if auth.config.cookies.same_site
            else "Lax",
        )
        return response

    async def sign_out(request: HttpRequest) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"detail": "Method not allowed"}, status=405)

        token = request.COOKIES.get(auth.config.cookies.name)
        if token:
            await auth.sign_out(token)

        response = JsonResponse({"message": "Signed out"})
        response.delete_cookie(key=auth.config.cookies.name, path="/")
        return response

    urlpatterns = [
        path("sign-up", csrf_exempt(sign_up), name="sign-up"),
        path("sign-in", csrf_exempt(sign_in), name="sign-in"),
        path("sign-out", csrf_exempt(sign_out), name="sign-out"),
    ]

    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():

            def make_view(handler: Any) -> Any:
                async def dynamic_view(
                    request: HttpRequest, *args: Any, **kwargs: Any
                ) -> JsonResponse:
                    body = {}
                    if request.method in ["POST", "PUT", "PATCH"]:
                        try:
                            body = json.loads(request.body)
                        except Exception:
                            pass

                    qulf_request = QulfRequest(
                        body=body,
                        query_params=request.GET.dict(),
                        path_params=kwargs,
                        cookies=request.COOKIES,
                        ip_address=_get_client_ip(request),
                        user_agent=_get_user_agent(request),
                    )

                    qulf_response = await handler(qulf_request)

                    response_body = (
                        qulf_response.body if qulf_response.body is not None else {}
                    )
                    response = JsonResponse(
                        response_body, status=qulf_response.status_code
                    )

                    for key, value in qulf_response.headers.items():
                        response[key] = value

                    for cookie in qulf_response.set_cookies:
                        response.set_cookie(
                            key=cookie.key,
                            value=cookie.value,
                            httponly=cookie.httponly,
                            secure=cookie.secure,
                            # Django expects "Lax", "Strict", "None"
                            # with capitalized first letters
                            samesite=cookie.samesite.capitalize()
                            if cookie.samesite
                            else "Lax",
                        )

                    for cookie_name in qulf_response.delete_cookies:
                        response.delete_cookie(key=cookie_name)

                    return response

                return dynamic_view

            # Remove leading slash for Django pathing
            route_path = qulf_route.path.lstrip("/")
            urlpatterns.append(
                path(route_path, csrf_exempt(make_view(qulf_route.handler)))
            )

    return urlpatterns
