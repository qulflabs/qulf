from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from qulf.config import DeletionStrategy
from qulf.types import (
    Account,
    AccountCreate,
    PasskeyCredential,
    PasskeyCredentialCreate,
    Permission,
    Role,
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

    def inject_custom_columns(self, custom_columns: dict[str, dict[str, type]]) -> None:
        """
        Dynamically injects plugin-requested columns into the database schema.
        Expected format: {"user": {"two_factor_secret": str}, "session": {...}}
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_by_email_with_password(
        self, email: str
    ) -> UserWithPassword | None:
        """
        Retrieves a user profile including the sensitive hashed password.

        This method is utilized during the sign-in phase to compare password.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_by_email(self, email: str) -> User | None:
        """
        Retrieves a user profile including the sensitive hashed password.

        This method is utilized during the sign-in phase to compare password.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_by_id_with_password(
        self, user_id: int | str
    ) -> UserWithPassword | None:
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
    async def delete_user(
        self, user_id: str, strategy: DeletionStrategy
    ) -> bool | None:
        """
        Deletes a user.
        If strategy == DeletionStrategy.SOFT, set `deleted_at` to the current UTC time.
        If strategy == DeletionStrategy.HARD, completely remove the row.
        """
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
        pass  # pragma: no cover

    @abstractmethod
    async def delete_user_session(
        self, user_id: str | int, token: str | None = None
    ) -> bool:
        """
        Delete a session with the provided `token` for a user.

        return bool
        """
        pass  # pragma: no cover

    @abstractmethod
    async def delete_all_user_sessions(
        self, user_id: str | int, except_token: str | None = None
    ) -> list[str]:
        """
        Delete all sessions for a user.
        If except_token is provided, do NOT delete the session with that token.

        return a list of ID's of the deleted instances
        """
        pass  # pragma: no cover

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

    @abstractmethod
    async def create_role(self, name: str, description: str | None = None) -> Role:
        pass  # pragma: no cover

    @abstractmethod
    async def get_role_by_name(self, name: str) -> Role | None:
        pass  # pragma: no cover

    @abstractmethod
    async def create_permission(
        self, name: str, description: str | None = None
    ) -> Permission:
        pass  # pragma: no cover

    @abstractmethod
    async def get_permission_by_name(self, name: str) -> Permission | None:
        pass  # pragma: no cover

    @abstractmethod
    async def assign_role_to_user(self, user_id: str | int, role_name: str) -> None:
        pass  # pragma: no cover

    @abstractmethod
    async def remove_role_from_user(self, user_id: str | int, role_name: str) -> None:
        pass  # pragma: no cover

    @abstractmethod
    async def grant_permission_to_role(
        self, role_name: str, permission_name: str
    ) -> None:
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_roles(self, user_id: str | int) -> list[Role]:
        """Fetch all roles directly assigned to the user."""
        pass  # pragma: no cover

    @abstractmethod
    async def get_user_permissions(self, user_id: str | int) -> list[Permission]:
        """Fetch all unique permissions the user has through their assigned roles."""
        pass  # pragma: no cover

    # Passkey (WebAuthn) operations

    @abstractmethod
    async def create_passkey(self, data: PasskeyCredentialCreate) -> PasskeyCredential:
        """
        Inserts a new passkey credential row linked to the given user.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_passkeys_by_user(
        self, user_id: str | int
    ) -> list[PasskeyCredential]:
        """
        Returns all passkey credentials registered for a user.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def get_passkey_by_credential_id(
        self, credential_id: str
    ) -> PasskeyCredential | None:
        """
        Looks up a single passkey row by its hex-encoded credential ID.
        Returns ``None`` if no matching credential exists.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def update_passkey_sign_count(
        self, credential_id: str, new_sign_count: int
    ) -> None:
        """
        Updates the monotonic sign counter for a credential after successful
        authentication, preventing replay attacks.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def delete_passkey(self, credential_id: str) -> bool:
        """
        Removes a passkey credential by its hex-encoded credential ID.
        Returns ``True`` if a row was deleted, ``False`` if not found.
        """
        pass  # pragma: no cover
