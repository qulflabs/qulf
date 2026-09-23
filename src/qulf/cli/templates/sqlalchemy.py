"""
Qulf Database Models (SQLAlchemy ORM)
Generated on: {timestamp}
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
)
from sqlalchemy.orm import Mapped, mapped_column

from qulf.adapters.sqlalchemy import (
    AccountMixin,
    PermissionMixin,
    QulfBase,
    RoleMixin,
    SessionMixin,
    UserMixin,
)


class DefaultUser(QulfBase, UserMixin):
    """Default User table schema ('user') used if no custom model is supplied."""

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)


class DefaultSession(QulfBase, SessionMixin):
    """Default Session table schema ('session')
    used if no custom model is supplied."""

    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))


class DefaultAccount(QulfBase, AccountMixin):
    """
    Default Account table schema ('account') used if no custom model is supplied.
    """

    __tablename__ = "accounts"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))


# Mapping table users <-> roles
user_roles = Table(
    "user_roles",
    QulfBase.metadata,
    Column(
        "user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    ),
)

# Mapping table roles <-> permissions
role_permissions = Table(
    "role_permissions",
    QulfBase.metadata,
    Column(
        "role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "permission_id",
        Integer,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class DefaultRole(QulfBase, RoleMixin):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)


class DefaultPermission(QulfBase, PermissionMixin):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)


class DefaultPasskey(QulfBase):
    """
    Default Passkey credential table (``passkeys``).

    Each row represents one WebAuthn credential for a user. A user may have
    multiple rows — one per authenticator device (Touch ID, Face ID, etc.).
    """

    __tablename__ = "passkeys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    credential_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    public_key: Mapped[str] = mapped_column(String)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String, default="Passkey")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
