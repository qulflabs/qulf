from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar, cast

import jwt

from qulf.adapters.base import DatabaseAdapter, SchemaAdapter
from qulf.config import QulfConfig
from qulf.crypto import (
    generate_session_token,
    hash_password,
    verify_password,
)
from qulf.exceptions import (
    InvalidCredentialsError,
    QulfException,
    UserAccountDeactivatedError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from qulf.plugins import QulfPlugin
from qulf.types import Session, User, UserCreate

TPlugin = TypeVar("TPlugin", bound=QulfPlugin)


class Qulf:
    """
    The central orchestrator of the Qulf authentication engine.

    Coordinates the database adapter, core operations (sign up, sign in,
    session validation), and mounts modular plugins.
    """

    def __init__(
        self,
        db: DatabaseAdapter,
        config: QulfConfig | None = None,
        plugins: list[QulfPlugin] | None = None,
    ) -> None:
        self.db = db
        self.config = config or QulfConfig()
        self.plugins: dict[str, QulfPlugin] = {}

        aggregated_columns: dict[str, dict[str, Any]] = {}

        if plugins:
            for plugin in plugins:
                plugin.setup(self)
                self.plugins[plugin.name] = plugin

                # Check for a backend/orm specific method first
                specific_method_name = f"get_{self.db.name}_columns"
                specific_method = getattr(plugin, specific_method_name, None)

                if specific_method:
                    cols = specific_method()
                else:
                    cols = plugin.get_custom_columns()

                for table_name, columns in cols.items():
                    if table_name not in aggregated_columns:
                        aggregated_columns[table_name] = {}
                    aggregated_columns[table_name].update(columns)

        if hasattr(self.db, "inject_custom_columns"):
            schema_db = cast(SchemaAdapter, self.db)
            schema_db.inject_custom_columns(aggregated_columns)

    def get_plugin(
        self, plugin_class: type[TPlugin], name: str | None = None
    ) -> TPlugin | None:
        """
        Safely retrieves a registered plugin by its class type.
        If multiple instances of the same plugin exist, `name` can be provided
        to target a specific instance natively.
        """
        # specific name is requested, do an O(1) lookup
        if name:
            plugin = self.plugins.get(name)
            # Verify the type
            if isinstance(plugin, plugin_class):
                return plugin
            return None

        # O(N) scan to find the first matching instance
        for plugin in self.plugins.values():
            if isinstance(plugin, plugin_class):
                return plugin

        return None

    async def sign_up(self, user_data: UserCreate) -> User:
        """
        Creates a new user profile inside the database.

        Raises UserAlreadyExistsError if the email address is already registered.
        """
        # EXECUTE BEFORE Hooks
        for plugin in self.plugins.values():
            user_data = await plugin.before_user_create(user_data)

        user_exists = await self.db.get_user_by_email(user_data.email)
        if user_exists:
            raise UserAlreadyExistsError("Email already associated with an account.")
        hashed_password = hash_password(user_data.password)
        user = await self.db.create_user(user_data, hashed_password)

        # EXECUTE AFTER Hooks
        for plugin in self.plugins.values():
            await plugin.after_user_create(user)

        return user

    async def sign_in(
        self,
        email: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Session:
        """
        Validates user credentials and issues a secure and persistent session token.

        Accepts optional network and client
        identifiers for security logging and auditing.
        """
        # EXECUTE BEFORE Hook
        for plugin in self.plugins.values():
            await plugin.before_sign_in(email, ip_address)

        user = await self.db.get_user_by_email_with_password(email)
        if not user:
            raise UserNotFoundError("User not found.")

        if user.deleted_at is not None:
            raise UserAccountDeactivatedError("Account deactivated.")

        verify = verify_password(password, user.hashed_password)
        if not verify:
            raise InvalidCredentialsError("Password incorrect")

        session = await self.create_session(user, ip_address, user_agent)

        # EXECUTE AFTER Hook
        for plugin in self.plugins.values():
            await plugin.after_sign_in(user, session)

        return session

    async def create_session(
        self, user: User, ip_address: str | None = None, user_agent: str | None = None
    ) -> Session:
        """Centralized method to create a session based on the configured strategy."""
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self.config.sessions.expires_in_days
        )

        if self.config.sessions.strategy == "jwt":
            payload = {
                "sub": str(user.id),
                "email": user.email,
                "name": user.name or "",
                "username": user.username,
                "created_at": user.created_at.timestamp(),
                "exp": expires_at,
            }
            session_token = jwt.encode(
                payload, self.config.secret_key, algorithm="HS256"
            )
        else:
            session_token = generate_session_token()

        session = await self.db.create_session(
            user_id=user.id,
            token=session_token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return session

    async def validate_session(self, token: str) -> tuple[Session, User] | None:
        """
        Validates a session token. If strategy is 'jwt', it validates statelessly.
        """

        # STATELESS JWT VALIDATION
        if self.config.sessions.strategy == "jwt":
            try:
                payload = jwt.decode(
                    token, self.config.secret_key, algorithms=["HS256"]
                )

                user = User(
                    id=payload["sub"],
                    email=payload["email"],
                    name=payload["name"],
                    username=payload["username"],
                    created_at=datetime.fromtimestamp(
                        payload["created_at"], tz=timezone.utc
                    ),
                )
                session = Session(
                    id="jwt",
                    user_id=user.id,
                    token=token,
                    created_at=datetime.fromtimestamp(
                        payload["created_at"], tz=timezone.utc
                    ),
                    expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                )
                return (session, user)
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                return None

        # STATEFUL DATABASE VALIDATION
        db_session = await self.db.get_session(token=token)
        if not db_session:
            return None

        # Fix naive datetimes from SQLite
        expires_at = db_session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await self.db.delete_session(token=token)
            return None

        db_user = await self.db.get_user_by_id(db_session.user_id)
        if not db_user:
            return None

        return (db_session, db_user)

    async def get_session_from_cookies(
        self, cookies: dict[str, str]
    ) -> tuple[Session, User] | None:
        """
        Extracts the session token from a dictionary of cookies and validates it.
        Returns the (Session, User) tuple if valid, or None if missing/invalid.
        """
        token = cookies.get(self.config.cookies.name)
        if not token:
            return None
        return await self.validate_session(token)

    async def sign_out(self, token: str) -> None:
        """
        Terminates the session by deleting the token from storage.
        """
        await self.db.delete_session(token=token)

    async def get_user_sessions(self, user_id: str | int) -> list[Session]:
        """Fetch all active sessions for a given user."""
        return await self.db.get_user_sessions(user_id=user_id)

    async def revoke_session(self, user_id: str | int, token: str) -> bool:
        """Revoke a specific session for a user."""
        return await self.db.delete_user_session(user_id=user_id, token=token)

    async def revoke_all_user_sessions(
        self, user_id: str | int, except_token: str | None = None
    ) -> list[str]:
        """Revoke all sessions for a user, optionally keeping the current one alive."""
        return await self.db.delete_all_user_sessions(
            user_id=user_id, except_token=except_token
        )

    async def generate_password_reset_token(self, email: str) -> str:
        """Generates a secure JWT for password resets."""
        user = await self.db.get_user_by_email(email)
        if not user:
            raise QulfException("If the email exists, a reset link will be sent.")

        if user.deleted_at is not None:
            raise UserAccountDeactivatedError("Account deactivated.")

        minutes = self.config.password_reset.token_expires_in
        payload = {
            "sub": str(user.id),
            "action": "reset_password",
            "exp": datetime.now(timezone.utc) + minutes,
        }
        session_token = jwt.encode(payload, self.config.secret_key, algorithm="HS256")
        if self.config.email_hooks.send_password_reset:
            await self.config.email_hooks.send_password_reset(email, session_token)
        return session_token

    async def reset_password(self, token: str, new_password: str) -> User:
        """Verifies the token and updates the user's password."""
        try:
            payload = jwt.decode(token, self.config.secret_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise QulfException("Token expired")
        except jwt.InvalidTokenError:
            raise QulfException("Invalid token")

        action: str = payload["action"]
        user_id: str = payload["sub"]
        if action == "reset_password":
            hashed_password = hash_password(password=new_password)
            update_data: dict[str, Any] = {"hashed_password": hashed_password}
            if self.config.password_reset.auto_verify_email:
                update_data["email_verified_at"] = datetime.now(timezone.utc)
            user = await self.db.update_user(user_id, update_data)
            if not user or user.deleted_at is not None:
                raise QulfException("User not found or account deactivated")
            return user
        raise QulfException("Invalid action")

    async def generate_email_verification_token(self, email: str) -> str:
        """Generates a secure, JWT for email verification."""
        user = await self.db.get_user_by_email(email)
        if not user or user.deleted_at is not None:
            raise QulfException("User not found or account deactivated")

        days = self.config.email_verification.token_expires_in
        payload = {
            "sub": str(user.id),
            "action": "verify_email",
            "exp": datetime.now(timezone.utc) + days,
        }
        email_verification_token = jwt.encode(
            payload, self.config.secret_key, algorithm="HS256"
        )
        if self.config.email_hooks.send_verification:
            await self.config.email_hooks.send_verification(
                email, email_verification_token
            )
        return email_verification_token

    async def verify_email(self, token: str) -> User:
        """Verifies the token and marks the user's email as verified."""
        try:
            payload = jwt.decode(token, self.config.secret_key, algorithms=["HS256"])
            if not payload["action"] == "verify_email":
                raise QulfException("Invalid action")
            user_id = payload["sub"]
            user = await self.db.get_user_by_id(user_id)
            if not user or user.deleted_at is not None:
                raise QulfException("User not found or account deactivated")
            verified_email_user = await self.db.update_user(
                user_id, {"email_verified_at": datetime.now(timezone.utc)}
            )
            return verified_email_user
        except jwt.ExpiredSignatureError:
            raise QulfException("Token expired")
        except jwt.InvalidTokenError:
            raise QulfException("Invalid token")

    async def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> User:
        """Allows an authenticated user to change their password."""
        user = await self.db.get_user_by_id_with_password(user_id)
        if not user or user.deleted_at is not None:
            raise QulfException("User not found or account deactivated")
        verified = verify_password(old_password, user.hashed_password)
        if not verified:
            raise QulfException("Invalid current password.")
        hashed_password = hash_password(new_password)
        updated_user = await self.db.update_user(
            user_id, {"hashed_password": hashed_password}
        )
        return updated_user

    async def delete_account(self, user_id: str) -> bool | None:
        """
        Deletes the user account based on the global DeletionStrategy.
        Respects the AccountDeletionConfig.enabled flag.
        """
        if not self.config.account_deletion.enabled:
            raise QulfException("Account deletion is disabled")
        user = await self.db.get_user_by_id(user_id)
        if not user or user.deleted_at is not None:
            raise QulfException("User not found or account deactivated")
        strategy = self.config.deletion.get_strategy("user")
        return await self.db.delete_user(str(user.id), strategy)

    # RBAC methods
    async def has_role(self, user: User, role_name: str) -> bool:
        """Check if a user has a specific role (with per-request caching)."""
        if user.roles is None:
            user.roles = await self.db.get_user_roles(user.id)

        return any(r.name == role_name for r in user.roles)

    async def has_permission(self, user: User, permission_name: str) -> bool:
        """
        Check if a user has a specific permission
        via their roles (with per-request caching).
        """
        if user.permissions is None:
            user.permissions = await self.db.get_user_permissions(user.id)

        return any(p.name == permission_name for p in user.permissions)

    async def require_role(self, user: User, role_name: str) -> None:
        """Enforce role requirement. Raises AuthorizationError if missing."""
        if not await self.has_role(user, role_name):
            from qulf.exceptions import AuthorizationError

            raise AuthorizationError(f"User lacks required role: '{role_name}'")

    async def require_permission(self, user: User, permission_name: str) -> None:
        """Enforce permission requirement. Raises AuthorizationError if missing."""
        if not await self.has_permission(user, permission_name):
            from qulf.exceptions import AuthorizationError

            raise AuthorizationError(
                f"User lacks required permission: '{permission_name}'"
            )
