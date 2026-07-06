from datetime import datetime, timedelta, timezone

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
        if plugins:
            for plugin in plugins:
                plugin.setup(self)
                self.plugins[plugin.name] = plugin

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

        session_token = generate_session_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self.config.sessions.expires_in_days
        )
        session = await self.db.create_session(
            user_id=user.id,
            token=session_token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # EXECUTE BEFORE Hook
        for plugin in self.plugins.values():
            await plugin.after_sign_in(user, session)

        return session

    async def validate_session(
        self, token: str
    ) -> tuple[Session, User] | tuple[None, None]:
        """
        Checks if a given session token is valid and active.

        Returns a tuple of the active (Session, User) or (None, None) if the session
        does not exist or has expired.
        """
        session = await self.db.get_session(token=token)
        if not session:
            return (None, None)

        expires_at = session.expires_at
        # SQLite and other relational databases loaded through standard SQLAlchemy
        # adapters retrieve datetimes as offset-naive objects. so we cast
        # naive datetimes to UTC to allow comparisons against timezone-aware datetimes.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await self.db.delete_session(token=token)
            return (None, None)

        user = await self.db.get_user_by_id(session.user_id)
        if not user:
            # The session is orphaned if the associated user account has been deleted.
            return (None, None)
        return (session, user)

    async def sign_out(self, token: str) -> None:
        """
        Terminates the session by deleting the token from storage.
        """
        await self.db.delete_session(token=token)
