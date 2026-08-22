DJANGO_TEMPLATE = """\
\"\"\"
Qulf Database Models (Django ORM)
Generated on: {timestamp}
\"\"\"
import uuid
from django.db import models
from qulf.adapters.django import (
    AccountMixin,
    PermissionMixin,
    RoleMixin,
    SessionMixin,
    UserMixin,
)

def generate_uuid() -> str:
    return str(uuid.uuid4())

class User(UserMixin):
    id: Any = models.BigAutoField(primary_key=True)
        
    # --- QULF PLUGIN COLUMNS ---
{plugin_columns}
    # ---------------------------

    class Meta:
        db_table = "qulf_users"

class Session(SessionMixin):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sessions")

    class Meta:
        db_table = "qulf_sessions"

class Account(AccountMixin):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="accounts")

    class Meta:
        db_table = "qulf_accounts"

class Role(RoleMixin):
    id = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "qulf_roles"

class Permission(PermissionMixin):
    id = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "qulf_permissions"

class UserRole(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_roles")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="role_users")

    class Meta:
        db_table = "qulf_user_roles"

class RolePermission(models.Model):
    id = models.BigAutoField(primary_key=True)
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name="role_permissions"
        )
    permission = models.ForeignKey(
        Permission, on_delete=models.CASCADE, related_name="permission_roles"
        )

    class Meta:
        db_table = "qulf_role_permissions"
"""

SQLALCHEMY_TEMPLATE = """\
\"\"\"
Qulf Database Models (SQLAlchemy)
Generated on: {timestamp}
\"\"\"
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from qulf.adapters.sqlalchemy import (
    AccountMixin,
    PermissionMixin,
    RoleMixin,
    SessionMixin,
    UserMixin,
)

class Base(DeclarativeBase):
    pass

class User(Base, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # --- QULF PLUGIN COLUMNS ---
{plugin_columns}
    # ---------------------------

class Session(Base, SessionMixin):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

class Account(Base, AccountMixin):
    __tablename__ = "accounts"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

class Role(Base, RoleMixin):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

class Permission(Base, PermissionMixin):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
"""
