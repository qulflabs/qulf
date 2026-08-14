"""Django ORM models and adapter.

This module provides reusable abstract Django model mixins, default concrete
models, and a Django ORM database adapter implementing Qulf's database
interface.

Applications can use the provided default models or extend the abstract
mixins to define their own models while keeping compatibility with Qulf.
"""

from datetime import datetime
from typing import Any

from asgiref.sync import sync_to_async
from django.db import IntegrityError, models
from django.utils import timezone

from qulf.adapters.base import DatabaseAdapter
from qulf.config import DeletionStrategy
from qulf.exceptions import QulfException
from qulf.types import (
    Account as QulfAccountType,
)
from qulf.types import (
    AccountCreate,
    UserCreate,
    UserWithPassword,
)
from qulf.types import (
    Permission as QulfPermissionType,
)
from qulf.types import (
    Role as QulfRoleType,
)
from qulf.types import (
    Session as QulfSessionType,
)
from qulf.types import (
    User as QulfUserType,
)


# ABSTRACT MODELS
class UserMixin(models.Model):
    email: Any = models.EmailField(unique=True, db_index=True)
    name: Any = models.CharField(max_length=255, null=True, blank=True)
    username: Any = models.CharField(
        max_length=255, unique=True, db_index=True, null=True, blank=True
    )
    hashed_password: Any = models.CharField(max_length=255, null=True, blank=True)
    created_at: Any = models.DateTimeField(auto_now_add=True)
    updated_at: Any = models.DateTimeField(auto_now=True, null=True)
    deleted_at: Any = models.DateTimeField(null=True, blank=True)
    last_login: Any = models.DateTimeField(null=True, blank=True)
    email_verified_at: Any = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True


class SessionMixin(models.Model):
    token: Any = models.CharField(max_length=255, unique=True, db_index=True)
    expires_at: Any = models.DateTimeField()
    ip_address: Any = models.CharField(max_length=255, null=True, blank=True)
    user_agent: Any = models.TextField(null=True, blank=True)
    created_at: Any = models.DateTimeField(auto_now_add=True)
    updated_at: Any = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        abstract = True


# TODO: Create AccountMixin, RoleMixin, PermissionMixin
class AccountMixin(models.Model):
    """
    SQLAlchemy column definitions for the Qulf Account model.
    """

    provider_id: Any = models.CharField(max_length=255, null=True, blank=True)
    account_id: Any = models.CharField(max_length=255, null=True, blank=True)

    access_token: Any = models.CharField(max_length=255, null=True, blank=True)
    refresh_token: Any = models.CharField(max_length=255, null=True, blank=True)
    expires_at: Any = models.DateTimeField(auto_now=True, null=True)
    scope: Any = models.CharField(max_length=255, null=True, blank=True)
    id_token: Any = models.CharField(max_length=255, null=True, blank=True)

    created_at: Any = models.DateTimeField(auto_now_add=True)
    updated_at: Any = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        abstract = True


class RoleMixin(models.Model):
    name: Any = models.CharField(max_length=255, unique=True, db_index=True)
    description: Any = models.CharField(max_length=255, null=True, blank=True)
    created_at: Any = models.DateTimeField(auto_now_add=True)
    updated_at: Any = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        abstract = True


class PermissionMixin(models.Model):
    name: Any = models.CharField(max_length=255, unique=True, db_index=True)
    description: Any = models.CharField(max_length=255, null=True, blank=True)
    created_at: Any = models.DateTimeField(auto_now_add=True)
    updated_at: Any = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        abstract = True


# DEFAULT CONCRETE MODELS
class DefaultUser(UserMixin):
    id: Any = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "users"
        app_label = "qulf"


class DefaultSession(SessionMixin):
    id: Any = models.BigAutoField(primary_key=True)
    user: Any = models.ForeignKey(
        DefaultUser, on_delete=models.CASCADE, related_name="sessions"
    )

    class Meta:
        db_table = "sessions"
        app_label = "qulf"


class DefaultAccount(AccountMixin):
    id: Any = models.BigAutoField(primary_key=True)
    user: Any = models.ForeignKey(
        DefaultUser, on_delete=models.CASCADE, related_name="accounts"
    )

    class Meta:
        db_table = "accounts"
        app_label = "qulf"


class DefaultRole(RoleMixin):
    id: Any = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "roles"
        app_label = "qulf"


class DefaultPermission(PermissionMixin):
    id: Any = models.BigAutoField(primary_key=True)

    class Meta:
        db_table = "permissions"
        app_label = "qulf"


class DefaultUserRole(models.Model):
    id: Any = models.BigAutoField(primary_key=True)
    user: Any = models.ForeignKey(
        DefaultUser, on_delete=models.CASCADE, related_name="user_roles"
    )
    role: Any = models.ForeignKey(
        DefaultRole, on_delete=models.CASCADE, related_name="role_users"
    )

    class Meta:
        db_table = "user_roles"
        app_label = "qulf"


class DefaultRolePermission(models.Model):
    id: Any = models.BigAutoField(primary_key=True)
    role: Any = models.ForeignKey(
        DefaultRole, on_delete=models.CASCADE, related_name="role_permissions"
    )
    permission: Any = models.ForeignKey(
        DefaultPermission, on_delete=models.CASCADE, related_name="permission_roles"
    )

    class Meta:
        db_table = "role_permissions"
        app_label = "qulf"


# ADAPTER
class DjangoORMAdapter(DatabaseAdapter):
    def __init__(
        self,
        user_model: type[models.Model] = DefaultUser,
        session_model: type[models.Model] = DefaultSession,
        account_model: type[models.Model] = DefaultAccount,
        role_model: type[models.Model] = DefaultRole,
        permission_model: type[models.Model] = DefaultPermission,
        user_role_model: type[models.Model] = DefaultUserRole,
        role_permission_model: type[models.Model] = DefaultRolePermission,
    ) -> None:
        self.user_model = user_model
        self.session_model = session_model
        self.account_model = account_model
        self.role_model = role_model
        self.permission_model = permission_model
        self.user_role_model = user_role_model
        self.role_permission_model = role_permission_model

    # PYDANTIC MAPPERS
    def _to_pydantic_user(self, db_user: Any) -> QulfUserType:
        return QulfUserType(
            id=str(db_user.id),
            email=db_user.email,
            name=db_user.name,
            username=db_user.username,
            email_verified_at=db_user.email_verified_at,
            created_at=db_user.created_at,
            updated_at=db_user.updated_at,
            deleted_at=db_user.deleted_at,
        )

    def _to_pydantic_user_with_password(self, db_user: Any) -> UserWithPassword:
        user = self._to_pydantic_user(db_user)
        return UserWithPassword(
            **user.model_dump(), hashed_password=db_user.hashed_password
        )

    def _to_pydantic_session(self, db_session: Any) -> QulfSessionType:
        return QulfSessionType(
            id=db_session.id,
            user_id=db_session.user_id,
            token=db_session.token,
            expires_at=db_session.expires_at,
            ip_address=db_session.ip_address,
            user_agent=db_session.user_agent,
            created_at=db_session.created_at,
            updated_at=db_session.updated_at,
        )

    def _to_pydantic_account(self, db_account: Any) -> QulfAccountType:
        return QulfAccountType(
            id=db_account.id,
            user_id=db_account.user_id,
            provider_id=db_account.provider_id,
            account_id=db_account.account_id,
            access_token=db_account.access_token,
            refresh_token=db_account.refresh_token,
            expires_at=db_account.expires_at,
            scope=db_account.scope,
            id_token=db_account.id_token,
            created_at=db_account.created_at,
            updated_at=db_account.updated_at,
        )

    def _to_pydantic_role(self, db_role: Any) -> QulfRoleType:
        return QulfRoleType(
            id=db_role.id,
            name=db_role.name,
            description=db_role.description,
            created_at=db_role.created_at,
            updated_at=db_role.updated_at,
        )

    def _to_pydantic_permission(self, db_permission: Any) -> QulfPermissionType:
        return QulfPermissionType(
            id=db_permission.id,
            name=db_permission.name,
            description=db_permission.description,
            created_at=db_permission.created_at,
            updated_at=db_permission.updated_at,
        )

    async def get_user_by_email(self, email: str) -> QulfUserType | None:
        db_user: Any = await self.user_model.objects.filter(email=email).afirst()
        if not db_user:
            return None
        return self._to_pydantic_user(db_user)

    async def get_user_by_email_with_password(
        self, email: str
    ) -> UserWithPassword | None:
        db_user: Any = await self.user_model.objects.filter(email=email).afirst()
        if not db_user:
            return None
        return self._to_pydantic_user_with_password(db_user)

    async def get_user_by_id(self, user_id: str | int) -> QulfUserType | None:
        db_user: Any = await self.user_model.objects.filter(id=user_id).afirst()
        if not db_user:
            return None
        return self._to_pydantic_user(db_user)

    async def get_user_by_id_with_password(
        self, user_id: str | int
    ) -> UserWithPassword | None:
        db_user: Any = await self.user_model.objects.filter(id=user_id).afirst()
        if not db_user:
            return None
        return self._to_pydantic_user_with_password(db_user)

    async def create_user(
        self, user_data: UserCreate, hashed_password: str
    ) -> QulfUserType:
        try:
            dump = user_data.model_dump(exclude={"password", "password_confirmation"})
            db_user: Any = await self.user_model.objects.acreate(
                **dump, hashed_password=hashed_password
            )
            return self._to_pydantic_user(db_user)
        except IntegrityError:
            raise QulfException("User already exists")
        except QulfException as e:
            raise e

    async def update_user(
        self, user_id: str | int, update_data: dict[str, Any]
    ) -> QulfUserType:
        user: Any = await self.user_model.objects.filter(id=user_id).afirst()
        if not user:
            raise ValueError("User not found")
        for field, value in update_data.items():
            setattr(user, field, value)
        await user.asave()
        return self._to_pydantic_user(user)

    async def delete_user(self, user_id: str | int, strategy: DeletionStrategy) -> bool:
        user: Any = await self.user_model.objects.filter(id=user_id).afirst()
        if not user:
            return False

        if strategy == DeletionStrategy.HARD:
            deleted_count, _ = await user.adelete()
            return bool(deleted_count > 0)  # used bool to silence mypy
        else:
            user.deleted_at = timezone.now()
            await user.asave(update_fields=["deleted_at"])
            return True

    # SESSION MANAGEMENT
    async def create_session(
        self,
        user_id: str | int,
        token: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> QulfSessionType:
        session = await self.session_model.objects.acreate(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return self._to_pydantic_session(session)

    async def get_session(self, token: str) -> QulfSessionType | None:
        session: Any = await self.session_model.objects.filter(token=token).afirst()
        return self._to_pydantic_session(session) if session else None

    async def delete_session(self, token: str) -> bool:
        session: Any = await self.session_model.objects.filter(token=token).afirst()
        if session:
            deleted_session: tuple[int, dict[str, int]] = await session.adelete()
            if deleted_session[0] > 0:
                return True
        return False

    async def get_user_sessions(self, user_id: str | int) -> list[QulfSessionType]:
        def _get_sessions() -> list[Any]:
            return list(self.session_model.objects.filter(user_id=user_id))

        sessions: list[Any] = await sync_to_async(_get_sessions)()
        return [self._to_pydantic_session(s) for s in sessions]

    async def delete_user_session(
        self, user_id: str | int, token: str | None = None
    ) -> bool:
        if token is None:
            return False
        session: Any = await self.session_model.objects.filter(
            user_id=user_id, token=token
        ).afirst()
        if session:
            deleted_count, _ = await session.adelete()
            return bool(deleted_count > 0)  # used bool to silence mypy
        return False

    async def delete_all_user_sessions(
        self, user_id: str | int, except_token: str | None = None
    ) -> list[str]:
        def _get_tokens() -> list[str]:
            qs = self.session_model.objects.filter(user_id=user_id)
            if except_token:
                qs = qs.exclude(token=except_token)
            return list(qs.values_list("token", flat=True))

        deleted_tokens = await sync_to_async(_get_tokens)()
        if deleted_tokens:
            await self.session_model.objects.filter(token__in=deleted_tokens).adelete()
        return deleted_tokens

    async def create_account(self, account_data: AccountCreate) -> QulfAccountType:
        db_account: Any = await self.account_model.objects.acreate(
            user_id=account_data.user_id,
            provider_id=account_data.provider_id,
            account_id=account_data.account_id,
            access_token=account_data.access_token,
            refresh_token=account_data.refresh_token,
            expires_at=account_data.expires_at,
            scope=account_data.scope,
            id_token=account_data.id_token,
        )
        return self._to_pydantic_account(db_account)

    async def get_account_by_provider(
        self, provider_id: str, account_id: str
    ) -> QulfAccountType | None:
        db_account: Any = await self.account_model.objects.filter(
            provider_id=provider_id, account_id=account_id
        ).afirst()
        if not db_account:
            return None
        return self._to_pydantic_account(db_account)

    # RBAC MANAGEMENT
    async def create_role(
        self, name: str, description: str | None = None
    ) -> QulfRoleType:
        db_role: Any = await self.role_model.objects.acreate(
            name=name, description=description
        )
        return self._to_pydantic_role(db_role)

    async def get_role_by_name(self, name: str) -> QulfRoleType | None:
        db_role: Any = await self.role_model.objects.filter(name=name).afirst()
        if not db_role:
            return None
        return self._to_pydantic_role(db_role)

    async def create_permission(
        self, name: str, description: str | None = None
    ) -> QulfPermissionType:
        db_permission: Any = await self.permission_model.objects.acreate(
            name=name, description=description
        )
        return self._to_pydantic_permission(db_permission)

    async def get_permission_by_name(self, name: str) -> QulfPermissionType | None:
        db_permission: Any = await self.permission_model.objects.filter(
            name=name
        ).afirst()
        if not db_permission:
            return None
        return self._to_pydantic_permission(db_permission)

    async def assign_role_to_user(self, user_id: str | int, role_name: str) -> None:
        role: Any = await self.role_model.objects.filter(name=role_name).afirst()
        if not role:
            raise ValueError(f"Role '{role_name}' does not exist.")

        try:
            await self.user_role_model.objects.acreate(user_id=user_id, role_id=role.id)
        except IntegrityError:
            pass # Already assigned

    async def remove_role_from_user(self, user_id: str | int, role_name: str) -> None:
        role: Any = await self.role_model.objects.filter(name=role_name).afirst()
        if role:
            await self.user_role_model.objects.filter(
                user_id=user_id, role_id=role.id
            ).adelete()

    async def grant_permission_to_role(
        self, role_name: str, permission_name: str
    ) -> None:
        role: Any = await self.role_model.objects.filter(name=role_name).afirst()
        if not role:
            raise ValueError(f"Role '{role_name}' does not exist.")

        permission: Any = await self.permission_model.objects.filter(
            name=permission_name
        ).afirst()
        if not permission:
            raise ValueError(f"Permission '{permission_name}' does not exist.")

        try:
            await self.role_permission_model.objects.acreate(
                role_id=role.id, permission_id=permission.id
            )
        except IntegrityError:
            pass # Already assigned

    async def get_user_roles(self, user_id: str | int) -> list[QulfRoleType]:
        def _get_roles() -> list[Any]:
            role_ids = self.user_role_model.objects.filter(user_id=user_id).values_list(
                "role_id", flat=True
            )
            return list(self.role_model.objects.filter(id__in=role_ids))

        roles: list[Any] = await sync_to_async(_get_roles)()
        return [self._to_pydantic_role(r) for r in roles]

    async def get_user_permissions(
        self, user_id: str | int
    ) -> list[QulfPermissionType]:
        def _get_permissions() -> list[Any]:
            role_ids = self.user_role_model.objects.filter(user_id=user_id).values_list(
                "role_id", flat=True
            )
            perm_ids = self.role_permission_model.objects.filter(
                role_id__in=role_ids
            ).values_list("permission_id", flat=True)
            return list(
                self.permission_model.objects.filter(id__in=perm_ids).distinct()
            )

        permissions: list[Any] = await sync_to_async(_get_permissions)()
        return [self._to_pydantic_permission(p) for p in permissions]
