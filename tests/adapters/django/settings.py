SECRET_KEY = "qulf-test-secret"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

INSTALLED_APPS = ["qulf"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
