"""
Qulf Database Models (Django ORM)
Generated on: {timestamp}
"""

from typing import Any

from django.db import models

from qulf.adapters.django import (
    AccountMixin,
    PermissionMixin,
    RoleMixin,
    SessionMixin,
    UserMixin,
)


class User(UserMixin):
    id: Any = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "users"


class Session(SessionMixin):
    id: Any = models.BigAutoField(primary_key=True)
    user: Any = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="sessions"
    )

    class Meta:
        db_table = "sessions"


class Account(AccountMixin):
    id: Any = models.BigAutoField(primary_key=True)
    user: Any = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="accounts"
    )

    class Meta:
        db_table = "accounts"


class Role(RoleMixin):
    id: Any = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "roles"


class Permission(PermissionMixin):
    id: Any = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "permissions"


class UserRole(models.Model):
    id: Any = models.BigAutoField(primary_key=True)
    user: Any = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="user_roles"
    )
    role: Any = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name="role_users"
    )

    class Meta:
        db_table = "user_roles"


class RolePermission(models.Model):
    id: Any = models.BigAutoField(primary_key=True)
    role: Any = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name="role_permissions"
    )
    permission: Any = models.ForeignKey(
        Permission, on_delete=models.CASCADE, related_name="permission_roles"
    )

    class Meta:
        db_table = "role_permissions"


class PasskeyMixin(models.Model):
    """
    Abstract Django model mixin for WebAuthn passkey credentials.

    Each row represents one registered authenticator for a user (Touch ID,
    Face ID, Windows Hello, hardware security key, etc.).
    """

    credential_id: Any = models.CharField(max_length=512, unique=True, db_index=True)
    public_key: Any = models.TextField()
    sign_count: Any = models.IntegerField(default=0)
    name: Any = models.CharField(max_length=255, default="Passkey")
    created_at: Any = models.DateTimeField(auto_now_add=True)
    updated_at: Any = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        abstract = True


class Passkey(PasskeyMixin):
    """Default Passkey credential table (``passkeys``)."""

    id: Any = models.BigAutoField(primary_key=True)
    user: Any = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="passkeys"
    )

    class Meta:
        db_table = "passkeys"
