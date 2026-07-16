from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from qulf.types import (
    Account,
    AccountCreate,
    Session,
    User,
    UserCreate,
    UserWithPassword,
)


class DatabaseAdapter(ABC):
    """
    The abstract contract that all Qulf storage backends must implement.

    All database methods are explicitly asynchronous because modern Python
    web frameworks require non-blocking database queries to maintain high
    concurrent throughput during connection processing.
    """

    @abstractmethod
    async def get_user_by_email(self, email: str) -> UserWithPassword | None:
        """
        Retrieves a user profile including the sensitive hashed password.

        This method is utilized during the sign-in phase to compare password.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_by_id(self, user_id: int | str) -> User | None:
        pass  # pragma: no cover

    @abstractmethod
    async def create_user(self, user_data: UserCreate, hashed_password: str) -> User:
        pass  # pragma: no cover

    @abstractmethod
    async def update_user(
        self, user_id: str | int, update_data: dict[str, Any]
    ) -> User:
        pass  # pragma: no cover

    @abstractmethod
    async def create_session(
        self,
        user_id: int | str,
        token: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Session:
        """
        Inserts a new session record into the database.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_session(self, token: str) -> Session | None:
        """
        Retrieves a session by its token.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def delete_session(self, token: str) -> bool:
        """
        Removes a session token from the database.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_sessions(self, user_id: str | int) -> list[Session]:
        """Fetch all active sessions for a specific user."""
        pass

    @abstractmethod
    async def delete_user_session(
        self, user_id: str | int, token: str | None = None
    ) -> bool:
        """
        Delete a session with the provided `token` for a user.

        return bool
        """
        pass

    @abstractmethod
    async def delete_all_user_sessions(
        self, user_id: str | int, except_token: str | None = None
    ) -> list[str]:
        """
        Delete all sessions for a user.
        If except_token is provided, do NOT delete the session with that token.

        return a list of ID's of the deleted instances
        """
        pass

    @abstractmethod
    async def create_account(self, account_data: AccountCreate) -> Account:
        """
        Inserts a new OAuth account record and links it to a user.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_account_by_provider(
        self, provider_id: str, account_id: str
    ) -> Account | None:
        """
        Retrieves an OAuth account using the provider's name and the provider's user ID.
        """
        pass  # pragma: no cover

    def inject_custom_columns(self, custom_columns: dict[str, dict[str, type]]) -> None:
        """
        Dynamically injects plugin-requested columns into the database schema.
        Expected format: {"user": {"two_factor_secret": str}, "session": {...}}
        """
        pass  # pragma: no cover
