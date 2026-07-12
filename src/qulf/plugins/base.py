from typing import TYPE_CHECKING, Any

from qulf.routing import QulfRoute
from qulf.types import Session, User, UserCreate

if TYPE_CHECKING:
    from qulf.core import Qulf


class QulfPlugin:
    """
    **Base class for all Qulf Plugins.**

    Exposes setup and routing hooks to let developer plugins register custom logic
    and custom framework endpoints seamlessly.
    """

    name: str

    auth: "Qulf | None" = None

    def setup(self, auth: "Qulf") -> None:
        """
        **Called when the plugin is initialized within the Qulf engine.**

        Gives the plugin access to the primary configuration
        and the shared database adapter,
        allowing the plugin to query database records safely.
        """
        self.auth = auth

    def get_routes(self) -> list[QulfRoute]:
        """
        **Returns a list of generic routes to be mounted by the framework.**
        """
        return []  # pragma: no cover

    async def before_user_create(self, user_data: UserCreate) -> UserCreate:
        """
        **Hook called before a new user is created.**

        Allows plugins to mutate user_data, validate fields, or enforce
        cross-system constraints before the user record is persisted to the database.

        - Args:
            `user_data`: Dictionary containing user fields

        - Returns:
            `UserCreate`

        *Example:*
            if not user_data.email.endswith("@example.com"):
                raise QulfException("Only example.com emails allowed")
            return user_data
        """
        return user_data  # pragma: no cover

    async def after_user_create(self, user: User) -> None:
        """
        **Hook called after a new user is created.**

        - Args:
            `user`: User object
        """
        pass  # pragma: no cover

    async def before_sign_in(self, email: str, ip_address: str | None = None) -> None:
        """
        **Hook called before a user is signed in.**

        - Args:
            `email`: Email of the user
            `ip_address`: IP address of the user
        """
        pass  # pragma: no cover

    async def after_sign_in(self, user: User, session: Session) -> None:
        """
        **Hook called after a user is signed in.**

        - Args:
            `user`: User object
            `ip_address`: IP address of the user
        """
        pass  # pragma: no cover

    def get_custom_columns(self) -> dict[str, dict[str, Any]]:
        """
        Allows plugins to inject columns into the core tables.
        """
        return {}  # pragma: no cover
