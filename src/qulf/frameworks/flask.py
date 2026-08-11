import inspect
from collections.abc import Callable, Coroutine
from functools import wraps
from typing import Any, Literal

from flask import Blueprint, g, jsonify, make_response, request
from pydantic import ValidationError

from qulf.core import Qulf
from qulf.exceptions import QulfException, Requires2FAError
from qulf.frameworks.base import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    SignInRequest,
    VerifyEmailRequest,
)
from qulf.routing import QulfRequest
from qulf.types import Session, User, UserCreate


def get_current_session(auth: Qulf) -> Callable[[], Coroutine[Any, Any, Session]]:
    async def _get() -> Session:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise QulfException("Unauthorized")
        session, _ = session_data
        return session

    return _get


def get_current_user(auth: Qulf) -> Callable[[], Coroutine[Any, Any, User]]:
    async def _get() -> User:
        session_data = await auth.get_session_from_cookies(request.cookies)
        if not session_data:
            raise QulfException("Unauthorized")
        _, user = session_data
        return user

    return _get


def serve_qulf(auth: Qulf) -> Blueprint:
    bp = Blueprint("qulf", __name__)

    async def _get_authenticated_user_id() -> str:
        token = request.cookies.get(auth.config.cookies.name)
        if not token:
            raise QulfException("Unauthorized")
        validated_session = await auth.validate_session(token)
        if validated_session:
            _, user = validated_session
            return str(user.id)
        raise QulfException("Unauthorized")

    @bp.route("/sign-up", methods=["POST"])
    async def sign_up() -> Any:
        try:
            body = request.get_json(force=True) or {}
            user_data = UserCreate(**body)
            user = await auth.sign_up(user_data)
            return jsonify(user.model_dump())
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    @bp.route("/sign-in", methods=["POST"])
    async def sign_in() -> Any:
        try:
            body = SignInRequest.model_validate(request.get_json(force=True))
            ip_address = request.remote_addr
            user_agent = request.headers.get("User-Agent")
            session = await auth.sign_in(
                body.email, body.password, ip_address, user_agent
            )
            response = make_response(jsonify({"message": "Signed in successfully"}))
            response.set_cookie(
                key=auth.config.cookies.name,
                value=session.token,
                httponly=auth.config.cookies.http_only,
                samesite=auth.config.cookies.same_site,
                secure=auth.config.cookies.secure,
            )
            return response
        except Requires2FAError as e:
            return jsonify({"detail": "2FA required", "temp_token": e.temp_token}), 401
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    @bp.route("/session", methods=["GET"])
    async def get_session() -> Any:
        try:
            session_data = await auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return jsonify({"detail": "Unauthorized"}), 401

            session, user = session_data
            return jsonify({"session": session.model_dump(), "user": user.model_dump()})
        except QulfException as e:
            return jsonify({"detail": str(e)}), 401

    @bp.route("/sign-out", methods=["POST"])
    async def sign_out() -> Any:
        try:
            token = request.cookies.get(auth.config.cookies.name)
            if not token:
                raise QulfException("Unauthorized")
            await auth.sign_out(token)
            response = make_response(jsonify({"message": "Signed out successfully"}))
            response.set_cookie(
                key=auth.config.cookies.name,
                value="",
                httponly=auth.config.cookies.http_only,
                samesite=auth.config.cookies.same_site,
                secure=auth.config.cookies.secure,
                max_age=0,
            )
            return response
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    @bp.route("/forgot-password", methods=["POST"])
    async def forgot_password() -> Any:
        try:
            body = request.get_json(force=True)
            validated = ForgotPasswordRequest.model_validate(body)
            await auth.generate_password_reset_token(validated.email)
            return jsonify({"message": "Reset link generated"})
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    @bp.route("/reset-password", methods=["POST"])
    async def reset_password() -> Any:
        try:
            body = request.get_json(force=True)
            validated = ResetPasswordRequest.model_validate(body)
            await auth.reset_password(validated.token, validated.new_password)
            return make_response(jsonify({"message": "Password reset successfully"}))
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    @bp.route("/verify-email", methods=["POST"])
    async def verify_email() -> Any:
        try:
            body = request.get_json(force=True)
            validated = VerifyEmailRequest.model_validate(body)
            await auth.verify_email(validated.token)
            return make_response(jsonify({"message": "Email verified successfully"}))
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    @bp.route("/change-password", methods=["POST"])
    async def change_password() -> Any:
        try:
            user_id = await _get_authenticated_user_id()
            body = request.get_json(force=True)
            validated = ChangePasswordRequest.model_validate(body)
            await auth.change_password(
                user_id, validated.old_password, validated.new_password
            )
            return make_response(jsonify({"message": "Password changed successfully"}))
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    @bp.route("/delete-account", methods=["DELETE"])
    async def delete_account() -> Any:
        try:
            user_id = await _get_authenticated_user_id()
            await auth.delete_account(user_id)
            await auth.revoke_all_user_sessions(user_id)
            return make_response(jsonify({"message": "Account deleted successfully"}))
        except (ValueError, ValidationError, QulfException) as e:
            status_code = 401 if str(e) == "Unauthorized" else 400
            return jsonify({"detail": str(e)}), status_code

    for plugin in auth.plugins.values():
        for qulf_route in plugin.get_routes():

            def make_view(route_def: Any) -> Any:
                async def dynamic_view(*args: Any, **kwargs: Any) -> Any:
                    # RBAC ENFORCEMENT
                    if route_def.require_roles or route_def.require_permissions:
                        session_data = await auth.get_session_from_cookies(
                            request.cookies
                        )
                        if not session_data:
                            return jsonify({"detail": "Authentication required"}), 401

                        _, user = session_data

                        for role in route_def.require_roles:
                            if not await auth.has_role(user, role):
                                return (
                                    jsonify({"detail": "Unauthorized"}),
                                    403,
                                )

                        for perm in route_def.require_permissions:
                            if not await auth.has_permission(user, perm):
                                return (
                                    jsonify({"detail": "Unauthorized"}),
                                    403,
                                )

                    # Parsing
                    body: dict[Any, Any] = {}
                    if request.method in ["POST", "PUT", "PATCH"]:
                        try:
                            body = request.get_json(force=True, silent=True) or {}
                        except Exception:
                            # delegate validation to the Plugin layer
                            # and prevent unhandled 500 Server Errors.
                            pass

                    qulf_request = QulfRequest(
                        body=body,
                        query_params=request.args.to_dict(),
                        path_params=kwargs,
                        cookies=request.cookies,
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get("User-Agent"),
                    )

                    qulf_response = await route_def.handler(qulf_request)

                    flask_response = make_response(
                        jsonify(qulf_response.body)
                        if qulf_response.body is not None
                        else jsonify({})
                    )
                    flask_response.status_code = qulf_response.status_code

                    for key, value in qulf_response.headers.items():
                        flask_response.headers[key] = value

                    for cookie in qulf_response.set_cookies:
                        flask_response.set_cookie(
                            key=cookie.key,
                            value=cookie.value,
                            httponly=cookie.httponly,
                            secure=cookie.secure,
                            samesite=cookie.samesite.capitalize()
                            if cookie.samesite
                            else "Lax",
                        )

                    for cookie_name in qulf_response.delete_cookies:
                        flask_response.delete_cookie(cookie_name)

                    return flask_response

                return dynamic_view

            # Translate Qulf's bracket routing {provider} to Flask's <provider>
            flask_path = qulf_route.path.replace("{", "<").replace("}", ">")
            methods = [m.value for m in qulf_route.methods]

            # Generate a unique endpoint name for Flask to prevent overwriting
            safe_endpoint = (
                f"plugin_{plugin.name}_{qulf_route.path}".replace("/", "_")
                .replace("{", "")
                .replace("}", "")
            )

            bp.add_url_rule(
                flask_path,
                endpoint=safe_endpoint,
                view_func=make_view(qulf_route),
                methods=methods,
            )

    return bp


def requires_role(
    auth: Qulf, roles: str | list[str], mode: Literal["any", "all"] = "all"
) -> Any:
    roles_list = [roles] if isinstance(roles, str) else roles

    def decorator(view_func: Any) -> Any:
        @wraps(view_func)
        async def _wrapped_view(*args: Any, **kwargs: Any) -> Any:
            session_data = await auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return jsonify({"detail": "Authentication required"}), 401

            _, user = session_data

            if mode == "all":
                for perm in roles_list:
                    if not await auth.has_role(user, perm):
                        return jsonify({"detail": "Unauthorized"}), 403

            elif mode == "any":
                has_any = False
                for perm in roles_list:
                    if await auth.has_role(user, perm):
                        has_any = True
                        break
                if not has_any:
                    return jsonify({"detail": "Unauthorized"}), 403
            g.qulf_user = user
            if inspect.iscoroutinefunction(view_func):
                return await view_func(*args, **kwargs)
            return view_func(*args, **kwargs)

        return _wrapped_view

    return decorator


def requires_permission(
    auth: Qulf, permissions: str | list[str], mode: Literal["any", "all"] = "all"
) -> Any:
    permissions_list = [permissions] if isinstance(permissions, str) else permissions

    def decorator(view_func: Any) -> Any:
        @wraps(view_func)
        async def _wrapped_view(*args: Any, **kwargs: Any) -> Any:
            session_data = await auth.get_session_from_cookies(request.cookies)
            if not session_data:
                return jsonify({"detail": "Authentication required"}), 401

            _, user = session_data

            if mode == "all":
                for perm in permissions_list:
                    if not await auth.has_permission(user, perm):
                        return jsonify({"detail": "Unauthorized"}), 403

            elif mode == "any":
                has_any = False
                for perm in permissions_list:
                    if await auth.has_permission(user, perm):
                        has_any = True
                        break
                if not has_any:
                    return jsonify({"detail": "Unauthorized"}), 403
            g.qulf_user = user
            if inspect.iscoroutinefunction(view_func):
                return await view_func(*args, **kwargs)
            return view_func(*args, **kwargs)

        return _wrapped_view

    return decorator
