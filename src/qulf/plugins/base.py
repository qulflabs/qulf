from typing import Any


class QulfPlugin:
    """
    Base class for all Qulf Plugins.

    Exposes setup and routing hooks to let developer plugins register custom logic
    and custom framework endpoints seamlessly.
    """

    name: str

    def setup(self, auth: Any) -> None:
        """
        Called when the plugin is initialized within the Qulf engine.

        Passing the `auth` instance gives the plugin access to the primary configuration
        and the shared database adapter,
        allowing the plugin to query database records safely.
        """
        pass  # pragma: no cover

    def get_fastapi_router(self, auth: Any) -> Any | None:
        """
        Optional hook returning a FastAPI APIRouter to inject plugin-specific endpoints.

        Defaults to returning `None` because some plugins may act as pure internal
        middleware or operational hooks
        without needing any public API endpoints.
        """
        return None
