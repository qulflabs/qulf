# src/qulf/config.py
from typing import Literal

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
    strategy: str = "database"


class QulfConfig(BaseSettings):
    """Main Configuration for Qulf"""

    # Requires a 32+ character string for security!
    secret_key: str = Field(..., min_length=32)
    base_url: str = "http://localhost:8000"

    cookies: CookieConfig = CookieConfig()
    sessions: SessionConfig = SessionConfig()

    model_config = SettingsConfigDict(
        env_prefix="QULF_", env_nested_delimiter="__", env_file=".env", extra="ignore"
    )
