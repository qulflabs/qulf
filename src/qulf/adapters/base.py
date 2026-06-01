from abc import ABC, abstractmethod
from datetime import datetime

from qulf.types import Session, User, UserCreate, UserWithPassword


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
    async def delete_session(self, token: str) -> None:
        """
        Removes a session token from the database.
        """
        pass  # pragma: no cover
