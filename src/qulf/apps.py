try:
    from django.apps import AppConfig
except ImportError:
    # Dummy class so the file doesn't crash for non-Django users if scanned
    class AppConfig:  # type: ignore
        pass  # pragma: no cover


class QulfConfig(AppConfig):
    name = "qulf"
    label = "qulf"
    verbose_name = "Qulf Auth Ecosystem"

    def ready(self) -> None:
        """Force Django to load our database adapter models."""
        try:
            import qulf.adapters.django  # noqa: F401
        except ImportError:
            pass  # pragma: no cover
