from datetime import datetime, timedelta, timezone

import jwt

from qulf.adapters.base import DatabaseAdapter
from qulf.config import QulfConfig
from qulf.crypto import generate_session_token, hash_password, verify_password
from qulf.exceptions import (
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from qulf.plugins.base import QulfPlugin
from qulf.types import Session, User, UserCreate


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
    ):
        self.db = db
        self.config = config or QulfConfig()
        self.plugins: dict[str, QulfPlugin] = {}

        aggregated_columns: dict[str, dict[str, type]] = {}

        if plugins:
            for plugin in plugins:
                plugin.setup(self)
                self.plugins[plugin.name] = plugin

                cols = plugin.get_custom_columns()

                # Dynamically iterate over ANY table the plugin requests
                for table_name, columns in cols.items():
                    if table_name not in aggregated_columns:
                        aggregated_columns[table_name] = {}

                    aggregated_columns[table_name].update(columns)

        # Pass the dictionary to the database adapter
        if hasattr(self.db, "inject_custom_columns"):
            self.db.inject_custom_columns(aggregated_columns)

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

        user = await self.db.get_user_by_email(email)
        if not user:
            raise UserNotFoundError("User not found.")
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
        """Validates a session token. If strategy is 'jwt', it validates statelessly."""

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
        session = await self.db.get_session(token=token)
        if not session:
            return None

        # Fix naive datetimes from SQLite
        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await self.db.delete_session(token=token)
            return None

        user = await self.db.get_user_by_id(session.user_id)
        if not user:
            return None

        return (session, user)
    
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
