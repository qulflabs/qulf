from qulf.types import Session
from qulf.types import User, UserCreate
from typing import Any


class QulfPlugin:
    """
    **Base class for all Qulf Plugins.**

    Exposes setup and routing hooks to let developer plugins register custom logic
    and custom framework endpoints seamlessly.
    """

    name: str

    def setup(self, auth: Any) -> None:
        """
        **Called when the plugin is initialized within the Qulf engine.**

        Passing the `auth` instance gives the plugin access to the primary configuration
        and the shared database adapter,
        allowing the plugin to query database records safely.
        """
        pass  # pragma: no cover

    def get_fastapi_router(self, auth: Any) -> Any | None:
        """
        **Optional hook returning a FastAPI APIRouter to inject plugin-specific endpoints.**

        Defaults to returning `None` because some plugins may act as pure internal
        middleware or operational hooks
        without needing any public API endpoints.
        """
        return None

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
