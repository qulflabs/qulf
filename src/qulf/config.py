from datetime import timedelta
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CookieConfig(BaseModel):
    name: str = "qulf_session"
    secure: bool = False
    same_site: Literal["lax", "none", "strict"] = "lax"
    http_only: bool = True


class SessionConfig(BaseModel):
    expires_in_days: int = 7
    update_age_days: int = 1
    strategy: Literal["jwt", "database"] = "database"


class DeletionStrategy(str, Enum):
    SOFT = "soft"
    HARD = "hard"


class DeletionConfig(BaseModel):
    """
    Controls how Qulf handles deletions across tables.
    By default, we soft-delete everything except sessions.
    """

    default: DeletionStrategy = Field(
        default=DeletionStrategy.SOFT,
        description="Global default strategy for deletions.",
    )

    table_overrides: dict[str, DeletionStrategy] = Field(
        # default is soft-delete users/accounts, hard-delete sessions
        default_factory=lambda: {"session": DeletionStrategy.HARD},
        description="Table-overrides (e.g., {'session': DeletionStrategy.HARD})",
    )

    def get_strategy(self, table_name: str) -> DeletionStrategy:
        """Helper to quickly resolve the active strategy for a given table."""
        return self.table_overrides.get(table_name, self.default)


class PasswordResetConfig(BaseModel):
    token_expires_in: timedelta = Field(default=timedelta(minutes=15))
    auto_verify_email: bool = Field(
        default=True,
        description="Automatically mark email as verified "
        "if a password reset token is successfully used.",
    )


class EmailVerificationConfig(BaseModel):
    token_expires_in: timedelta = Field(default=timedelta(hours=24))
    require_for_sign_in: bool = Field(
        default=False,
        description="If True, reject sign_in attempts if User.email_verified is False.",
    )


class EmailUpdateConfig(BaseModel):
    require_verification: bool = Field(
        default=True,
        description="If True, changing an email generates "
        "a token instead of updating the DB immediately.",
    )


class AccountDeletionConfig(BaseModel):
    enabled: bool = Field(
        default=True,
        description="If False, the DELETE /account "
        "endpoint will return a 403 Forbidden.",
    )


class QulfConfig(BaseSettings):
    """Main Configuration for Qulf"""

    project_name: str = "Qulf"
    base_url: str = "http://localhost:8000"
    # Requires a 32+ character string for security!
    secret_key: str = Field(
        ...,
        min_length=32,
        description="""
        Secret used to sign JWTs and other cryptographic tokens.
        """,
    )

    cookies: CookieConfig = CookieConfig()
    sessions: SessionConfig = SessionConfig()
    deletion: DeletionConfig = Field(default_factory=DeletionConfig)
    password_reset: PasswordResetConfig = Field(default_factory=PasswordResetConfig)
    email_verification: EmailVerificationConfig = Field(
        default_factory=EmailVerificationConfig
    )
    email_update: EmailUpdateConfig = Field(default_factory=EmailUpdateConfig)
    account_deletion: AccountDeletionConfig = Field(
        default_factory=AccountDeletionConfig
    )
    oauth_providers: list[Any] = []

    model_config = SettingsConfigDict(
        env_prefix="QULF_", env_nested_delimiter="__", env_file=".env", extra="ignore"
    )
