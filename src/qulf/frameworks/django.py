import json
from functools import wraps
from typing import Any, Literal, cast

from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from pydantic import ValidationError

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

    async def _get_authenticated_user_id(request: HttpRequest) -> str:
        """Helper to extract user_id from the session cookie."""
        token = request.COOKIES.get(auth.config.cookies.name)
        if not token:
            raise QulfException("Unauthorized")

        validated_session = await auth.validate_session(token)
        if validated_session:
            session, user = validated_session
            return str(user.id)
        raise QulfException("Unauthorized")

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

    async def forgot_password(request: HttpRequest) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"detail": "Method not allowed"}, status=405)
        try:
            body = json.loads(request.body)
            ForgotPasswordRequest.model_validate(body)
            await auth.generate_password_reset_token(body["email"])
            return JsonResponse({"message": "Reset link generated successfully"})
        except (ValueError, ValidationError, QulfException) as e:
            return JsonResponse({"detail": str(e)}, status=400)

    async def reset_password(request: HttpRequest) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"detail": "Method not allowed"}, status=405)
        try:
            body = json.loads(request.body)
            validated_body = ResetPasswordRequest.model_validate(body)
            await auth.reset_password(validated_body.token, validated_body.new_password)
            return JsonResponse({"message": "Password reset successfully"})
        except (ValueError, ValidationError, QulfException) as e:
            return JsonResponse({"detail": str(e)}, status=400)

    async def verify_email(request: HttpRequest) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"detail": "Method not allowed"}, status=405)
        try:
            body = json.loads(request.body)
            validated_body = VerifyEmailRequest.model_validate(body)
            await auth.verify_email(validated_body.token)
            return JsonResponse({"message": "Email verified successfully"})
        except (ValueError, ValidationError, QulfException) as e:
            return JsonResponse({"detail": str(e)}, status=400)

    # --- AUTHENTICATED ROUTES ---

    async def change_password(request: HttpRequest) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"detail": "Method not allowed"}, status=405)
        try:
            user_id = await _get_authenticated_user_id(request)
            body = json.loads(request.body)
            validated_body = ChangePasswordRequest.model_validate(body)
            await auth.change_password(
                user_id, validated_body.old_password, validated_body.new_password
            )
            return JsonResponse({"message": "Password changed"})
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return JsonResponse({"detail": str(e)}, status=status_code)

    async def delete_account(request: HttpRequest) -> JsonResponse:
        if request.method != "DELETE":
            return JsonResponse({"detail": "Method not allowed"}, status=405)
        try:
            user_id = await _get_authenticated_user_id(request)
            await auth.delete_account(user_id)
            await auth.revoke_all_user_sessions(user_id)

            response = JsonResponse({"message": "Account deleted successfully"})
            response.delete_cookie(key=auth.config.cookies.name, path="/")
            return response
        except QulfException as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return JsonResponse({"detail": str(e)}, status=status_code)

    urlpatterns = [
        path("sign-up", csrf_exempt(sign_up), name="sign-up"),
        path("sign-in", csrf_exempt(sign_in), name="sign-in"),
        path("sign-out", csrf_exempt(sign_out), name="sign-out"),
        path("forgot-password", csrf_exempt(forgot_password), name="forgot-password"),
        path("reset-password", csrf_exempt(reset_password), name="reset-password"),
        path("verify-email", csrf_exempt(verify_email), name="verify-email"),
        path("change-password", csrf_exempt(change_password), name="change-password"),
        path("delete-account", csrf_exempt(delete_account), name="delete-account"),
    ]

    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():

            def make_view(handler: Any) -> Any:
                async def dynamic_view(
                    request: HttpRequest, *args: Any, **kwargs: Any
                ) -> JsonResponse:
                    if qulf_route.require_roles or qulf_route.require_permissions:
                        session_data = await auth.get_session_from_cookies(
                            request.COOKIES
                        )
                        if not session_data:
                            return JsonResponse(
                                {"detail": "Authentication required"}, status=401
                            )

                        _, user = session_data

                        for role in qulf_route.require_roles:
                            if not await auth.has_role(user, role):
                                return JsonResponse(
                                    {"detail": f"Missing required role: '{role}'"},
                                    status=403,
                                )

                        for perm in qulf_route.require_permissions:
                            if not await auth.has_permission(user, perm):
                                return JsonResponse(
                                    {
                                        "detail": "Missing required permission: "
                                        f"'{perm}'"
                                    },
                                    status=403,
                                )
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


def requires_role(
    auth: Qulf, roles: str | list[str], mode: Literal["any", "all"] = "all"
) -> Any:
    """Django async decorator to protect views by Role."""
    roles_list = [roles] if isinstance(roles, str) else roles

    def decorator(view_func: Any) -> Any:
        @wraps(view_func)
        async def _wrapped_view(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            session_data = await auth.get_session_from_cookies(request.COOKIES)
            if not session_data:
                return JsonResponse({"detail": "Authentication required"}, status=401)

            _, user = session_data

            if mode == "all":
                for role in roles_list:
                    if not await auth.has_role(user, role):
                        return JsonResponse(
                            {"detail": f"Missing required role: '{role}'"}, status=403
                        )
            elif mode == "any":
                has_any = False
                for role in roles_list:
                    if await auth.has_role(user, role):
                        has_any = True
                        break
                if not has_any:
                    return JsonResponse(
                        {"detail": f"Requires at least one role from: {roles_list}"},
                        status=403,
                    )

            request.qulf_user = user  # type: ignore
            return await view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator


def requires_permission(
    auth: Qulf, permissions: str | list[str], mode: Literal["any", "all"] = "all"
) -> Any:
    """Django async decorator to protect views by Permission."""
    perms_list = [permissions] if isinstance(permissions, str) else permissions

    def decorator(view_func: Any) -> Any:
        @wraps(view_func)
        async def _wrapped_view(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            session_data = await auth.get_session_from_cookies(request.COOKIES)
            if not session_data:
                return JsonResponse({"detail": "Authentication required"}, status=401)

            _, user = session_data

            if mode == "all":
                for perm in perms_list:
                    if not await auth.has_permission(user, perm):
                        return JsonResponse(
                            {"detail": f"Missing required permission: '{perm}'"},
                            status=403,
                        )
            elif mode == "any":
                has_any = False
                for perm in perms_list:
                    if await auth.has_permission(user, perm):
                        has_any = True
                        break
                if not has_any:
                    return JsonResponse(
                        {
                            "detail": "Requires at least one permission from: "
                            f"{perms_list}"
                        },
                        status=403,
                    )

            request.qulf_user = user  # type: ignore
            return await view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator
