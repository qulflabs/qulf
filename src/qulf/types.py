from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, model_validator


class CoreModel(BaseModel):
    """
    Common base schema for all Qulf entities containing tracking properties.
    """

    model_config = ConfigDict(extra="allow")

    id: int | str
    created_at: datetime
    updated_at: datetime | None = None


class User(CoreModel):
    """
    Standard, safe public representation of a user account.

    Contains user descriptors and profile tracking parameters, but strictly
    excludes the password hash to protect credentials from exposure.
    """

    name: str
    email: EmailStr
    username: str
    email_verified_at: datetime | None = None
    last_login: datetime | None = None
    deleted_at: datetime | None = None


class UserCreate(BaseModel):
    """
    Validation schema for creating a user account.

    Enforces password matching and standard syntax before creation proceeds.
    """

    name: str
    email: EmailStr
    username: str
    password: str
    password_confirmation: str

    @model_validator(mode="after")
    def check_passwords_match(self) -> "UserCreate":
        if self.password != self.password_confirmation:
            raise ValueError("Passwords do not match")
        return self


class UserUpdate(BaseModel):
    """
    Validation schema for updating a user account.

    Enforces password matching and standard syntax before creation proceeds.
    """

    id: int | str
    name: str
    email: EmailStr
    email_verified_at: datetime | None = None
    username: str


class UserWithPassword(User):
    """
    Internal user model containing the Argon2 password hash.

    Used only inside the crypto validation and storage layer.
    """

    hashed_password: str


class Session(CoreModel):
    """
    Session model representing an active user token context.
    """

    user_id: int | str
    expires_at: datetime
    token: str
    ip_address: str | None = None
    user_agent: str | None = None
    deleted_at: datetime | None = None


class AccountCreate(BaseModel):
    """
    Validation schema for linking an OAuth account.
    """

    user_id: int | str
    account_id: str
    provider_id: str
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None
    scope: str | None = None
    id_token: str | None = None


class Account(CoreModel, AccountCreate):
    """
    Standard representation of an OAuth account linked to a user.
    """

    deleted_at: datetime | None = None
