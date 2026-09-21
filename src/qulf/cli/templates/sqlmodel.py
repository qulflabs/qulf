"""
Qulf Database Models (SQLModel ORM)
Generated on: {timestamp}
"""

from datetime import datetime, timezone
from typing import Any, ClassVar

from sqlmodel import Field, SQLModel

from qulf.adapters.sqlmodel import AccountMixin, SessionMixin, UserMixin


class User(UserMixin, table=True):
    """Default User table schema."""

    __tablename__: ClassVar[Any] = "users"
    __table_args__ = {{"extend_existing": True}}

    id: int | None = Field(default=None, primary_key=True)


class Session(SessionMixin, table=True):
    """Default Session table schema."""

    __tablename__: ClassVar[Any] = "sessions"
    __table_args__ = {{"extend_existing": True}}

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")


class Account(AccountMixin, table=True):
    """Default Account table schema."""

    __tablename__: ClassVar[Any] = "accounts"
    __table_args__ = {{"extend_existing": True}}

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")


# RBAC Link Models (Many-to-Many)
class UserRoleLink(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "user_roles"
    __table_args__ = {{"extend_existing": True}}
    user_id: int = Field(foreign_key="users.id", primary_key=True)
    role_id: int = Field(foreign_key="roles.id", primary_key=True)


class RolePermissionLink(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "role_permissions"
    __table_args__ = {{"extend_existing": True}}
    role_id: int = Field(foreign_key="roles.id", primary_key=True)
    permission_id: int = Field(foreign_key="permissions.id", primary_key=True)


# RBAC Default Models
class Role(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "roles"
    __table_args__ = {{"extend_existing": True}}
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = None


class Permission(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "permissions"
    __table_args__ = {{"extend_existing": True}}
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = None


class Passkey(SQLModel, table=True):
    """
    Default Passkey credential table (``passkeys``).

    Each row represents one WebAuthn credential for a user. A user may have
    multiple rows — one per authenticator device (Touch ID, Face ID, etc.).
    """

    __tablename__: ClassVar[Any] = "passkeys"
    __table_args__ = {{"extend_existing": True}}

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    credential_id: str = Field(unique=True, index=True)
    public_key: str
    sign_count: int = 0
    name: str = "Passkey"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = None