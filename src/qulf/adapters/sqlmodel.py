from datetime import datetime, timezone
from typing import Any, ClassVar

from sqlalchemy import Boolean, Integer, String, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import attributes, mapped_column
from sqlmodel import Field, SQLModel, col, select

from qulf.adapters.base import DatabaseAdapter
from qulf.config import DeletionStrategy
from qulf.types import (
    Account as QulfAccountType,
)
from qulf.types import (
    AccountCreate,
    PasskeyCredential,
    PasskeyCredentialCreate,
    Permission,
    Role,
    UserCreate,
    UserWithPassword,
)
from qulf.types import (
    Session as QulfSessionType,
)
from qulf.types import (
    User as QulfUserType,
)


class UserMixin(SQLModel):
    """
    SQLModel column definitions for the Qulf User model.
    """

    email: str = Field(unique=True, index=True)
    name: str
    username: str = Field(unique=True, index=True)
    hashed_password: str
    created_at: datetime
    updated_at: datetime | None = None
    deleted_at: datetime | None = None
    last_login: datetime | None = None


class SessionMixin(SQLModel):
    """
    SQLModel column definitions for the Qulf Session model.
    """

    token: str = Field(unique=True, index=True)
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class AccountMixin(SQLModel):
    """
    SQLModel column definitions for the Qulf Account model.
    """

    provider_id: str = Field(index=True)
    account_id: str = Field(index=True)
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None
    scope: str | None = None
    id_token: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class DefaultUser(UserMixin, table=True):
    """Default User table schema."""

    __tablename__: ClassVar[Any] = "users"

    id: int | None = Field(default=None, primary_key=True)


class DefaultSession(SessionMixin, table=True):
    """Default Session table schema."""

    __tablename__: ClassVar[Any] = "sessions"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")


class DefaultAccount(AccountMixin, table=True):
    """Default Account table schema."""

    __tablename__: ClassVar[Any] = "accounts"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")


# RBAC Link Models (Many-to-Many)


class UserRoleLink(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "user_roles"
    user_id: int = Field(foreign_key="users.id", primary_key=True)
    role_id: int = Field(foreign_key="roles.id", primary_key=True)


class RolePermissionLink(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "role_permissions"
    role_id: int = Field(foreign_key="roles.id", primary_key=True)
    permission_id: int = Field(foreign_key="permissions.id", primary_key=True)


# RBAC Default Models
class DefaultRole(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "roles"
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = None


class DefaultPermission(SQLModel, table=True):
    __tablename__: ClassVar[Any] = "permissions"
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = None


class DefaultPasskey(SQLModel, table=True):
    """
    Default Passkey credential table (``passkeys``).

    Each row represents one WebAuthn credential for a user. A user may have
    multiple rows — one per authenticator device (Touch ID, Face ID, etc.).
    """

    __tablename__: ClassVar[Any] = "passkeys"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    credential_id: str = Field(unique=True, index=True)
    public_key: str
    sign_count: int = 0
    name: str = "Passkey"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = None


class SQLModelAdapter(DatabaseAdapter):
    """
    Concrete DatabaseAdapter subclass leveraging SQLModel (and SQLAlchemy 2.0).
    """

    def __init__(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        user_model: Any = DefaultUser,
        session_model: Any = DefaultSession,
        account_model: Any = DefaultAccount,
        role_model: Any = DefaultRole,
        permission_model: Any = DefaultPermission,
        passkey_model: Any = DefaultPasskey,
    ):
        self.session_maker = session_maker
        self.user_model = user_model
        self.session_model = session_model
        self.account_model = account_model
        self.role_model = role_model
        self.permission_model = permission_model
        self.passkey_model = passkey_model

        self.models = {
            "user": self.user_model,
            "session": self.session_model,
            "account": self.account_model,
            "role_model": self.role_model,
            "permission_model": self.permission_model,
        }

    @staticmethod
    def _to_dict(obj: Any) -> dict[str, Any] | None:
        if obj is None:
            return obj
        d = dict(obj.__dict__)
        d.pop("_sa_instance_state", None)
        return d

    def inject_custom_columns(self, custom_columns: dict[str, dict[str, Any]]) -> None:
        type_mapping = {str: String, bool: Boolean, int: Integer}

        for table_name, columns in custom_columns.items():
            model = self.models.get(table_name)
            if not model:
                continue

            for col_name, col_type in columns.items():
                if not hasattr(model, col_name):
                    sa_type = type_mapping.get(col_type, String)
                    # We inject at the SQLAlchemy level so the schema builder sees it.
                    # SQLModel models are SQLAlchemy Declarative classes underneath.
                    setattr(model, col_name, mapped_column(sa_type, nullable=True))

    async def get_user_by_email(self, email: str) -> UserWithPassword | None:
        async with self.session_maker() as session:
            stmt = select(self.user_model).where(self.user_model.email == email)
            result = await session.execute(stmt)
            db_user = result.scalar_one_or_none()
            if not db_user:
                return None
            return UserWithPassword.model_validate(self._to_dict(db_user))

    async def get_user_by_id(self, user_id: str | int) -> QulfUserType | None:
        async with self.session_maker() as session:
            stmt = select(self.user_model).where(self.user_model.id == user_id)
            result = await session.execute(stmt)
            db_user = result.scalar_one_or_none()
            if not db_user:
                return None
            return QulfUserType.model_validate(self._to_dict(db_user))

    async def get_user_by_email_with_password(
        self, email: str
    ) -> UserWithPassword | None:
        async with self.session_maker() as session:
            statement = select(self.user_model).where(self.user_model.email == email)
            result = await session.execute(statement)
            db_user = result.scalar_one_or_none()
            if db_user is None:
                return None
            return UserWithPassword.model_validate(self._to_dict(db_user))

    async def get_user_by_id_with_password(
        self, user_id: int | str
    ) -> UserWithPassword | None:
        async with self.session_maker() as session:
            db_user = await session.get(self.user_model, str(user_id))
            if db_user is None:
                return None
            return UserWithPassword.model_validate(self._to_dict(db_user))

    async def delete_user(self, user_id: str, strategy: DeletionStrategy) -> None:
        async with self.session_maker() as session:
            db_user = await session.get(self.user_model, user_id)
            if db_user:
                if strategy == DeletionStrategy.HARD:
                    await session.delete(db_user)
                else:
                    db_user.deleted_at = datetime.now(timezone.utc)
                await session.commit()

    async def create_user(
        self, user_data: UserCreate, hashed_password: str
    ) -> QulfUserType:
        async with self.session_maker() as session:
            new_user = self.user_model(
                email=user_data.email,
                name=user_data.name,
                username=user_data.username,
                hashed_password=hashed_password,
                created_at=datetime.now(timezone.utc),
            )
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
            return QulfUserType.model_validate(self._to_dict(new_user))

    async def update_user(
        self, user_id: str | int, update_data: dict[str, Any]
    ) -> QulfUserType:
        async with self.session_maker() as session:
            result = await session.execute(
                select(self.user_model).where(self.user_model.id == user_id)
            )
            user = result.scalars().first()
            if not user:
                raise ValueError("User not found")

            for field, value in update_data.items():
                # SQLModel's ``__setattr__`` rejects columns that are not
                # declared as SQLModel ``Field``s like plugin injected columns..
                attributes.set_attribute(user, field, value)

            await session.commit()
            await session.refresh(user)
            return QulfUserType.model_validate(self._to_dict(user))

    async def create_session(
        self,
        user_id: str | int,
        token: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> QulfSessionType:
        async with self.session_maker() as session:
            new_session = self.session_model(
                user_id=user_id,
                token=token,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=datetime.now(timezone.utc),
            )
            session.add(new_session)
            await session.commit()
            await session.refresh(new_session)
            return QulfSessionType.model_validate(self._to_dict(new_session))

    async def get_session(self, token: str) -> QulfSessionType | None:
        async with self.session_maker() as session:
            stmt = select(self.session_model).where(self.session_model.token == token)
            result = await session.execute(stmt)
            db_session = result.scalar_one_or_none()
            if not db_session:
                return None
            return QulfSessionType.model_validate(self._to_dict(db_session))

    async def delete_session(self, token: str) -> bool:

        async with self.session_maker() as session:
            stmt = (
                delete(self.session_model)
                .where(self.session_model.token == token)
                .returning(self.session_model.id)
            )
            result = await session.execute(stmt)
            await session.commit()
            deleted_id = result.scalar()

            return deleted_id is not None

    async def get_user_sessions(self, user_id: str | int) -> list[QulfSessionType]:
        async with self.session_maker() as session:
            stmt = select(self.session_model).where(
                self.session_model.user_id == user_id
            )
            result = await session.execute(stmt)
            db_session = result.scalars().all()
            return [
                QulfSessionType.model_validate(self._to_dict(db_s))
                for db_s in db_session
            ]

    async def delete_user_session(
        self, user_id: str | int, token: str | None = None
    ) -> bool:
        from sqlalchemy import delete

        async with self.session_maker() as session:
            stmt = (
                delete(self.session_model)
                .where(
                    self.session_model.user_id == user_id,
                    self.session_model.token == token,
                )
                .returning(self.session_model.id)
            )
            result = await session.execute(stmt)
            await session.commit()
            deleted_id = result.scalar()

            return deleted_id is not None

    async def delete_all_user_sessions(
        self, user_id: str | int, except_token: str | None = None
    ) -> list[str]:
        from sqlalchemy import delete

        async with self.session_maker() as session:
            delete_stmt = delete(self.session_model).where(
                self.session_model.user_id == user_id
            )

            if except_token is not None:
                where_stmt = delete_stmt.where(self.session_model.token != except_token)
            else:
                where_stmt = delete_stmt

            stmt = where_stmt.returning(self.session_model.token)

            result = await session.execute(stmt)
            await session.commit()

            deleted_tokens = list(result.scalars().all())

            return deleted_tokens

    async def create_account(self, account_data: AccountCreate) -> QulfAccountType:
        async with self.session_maker() as session:
            new_account = self.account_model(
                user_id=account_data.user_id,
                account_id=account_data.account_id,
                provider_id=account_data.provider_id,
                access_token=account_data.access_token,
                refresh_token=account_data.refresh_token,
                expires_at=account_data.expires_at,
                scope=account_data.scope,
                id_token=account_data.id_token,
                created_at=datetime.now(timezone.utc),
            )
            session.add(new_account)
            await session.commit()
            await session.refresh(new_account)
            return QulfAccountType.model_validate(self._to_dict(new_account))

    async def get_account_by_provider(
        self, provider_id: str, account_id: str
    ) -> QulfAccountType | None:
        async with self.session_maker() as session:
            stmt = select(self.account_model).where(
                self.account_model.provider_id == provider_id,
                self.account_model.account_id == account_id,
            )
            result = await session.execute(stmt)
            db_account = result.scalar_one_or_none()
            if not db_account:
                return None
            return QulfAccountType.model_validate(self._to_dict(db_account))

    # ROlES & PERMISSIONS:
    async def create_role(self, name: str, description: str | None = None) -> Role:
        async with self.session_maker() as session:
            new_role = self.role_model(
                name=name,
                description=description,
                created_at=datetime.now(timezone.utc),
            )
            session.add(new_role)
            await session.commit()
            await session.refresh(new_role)
            return Role.model_validate(self._to_dict(new_role))

    async def get_role_by_name(self, name: str) -> Role | None:
        async with self.session_maker() as session:
            stmt = select(self.role_model).where(self.role_model.name == name)
            result = await session.execute(stmt)
            db_role = result.scalar_one_or_none()
            return Role.model_validate(self._to_dict(db_role)) if db_role else None

    async def create_permission(
        self, name: str, description: str | None = None
    ) -> Permission:
        async with self.session_maker() as session:
            new_perm = self.permission_model(
                name=name,
                description=description,
                created_at=datetime.now(timezone.utc),
            )
            session.add(new_perm)
            await session.commit()
            await session.refresh(new_perm)
            return Permission.model_validate(self._to_dict(new_perm))

    async def get_permission_by_name(self, name: str) -> Permission | None:
        async with self.session_maker() as session:
            stmt = select(self.permission_model).where(
                self.permission_model.name == name
            )
            result = await session.execute(stmt)
            db_perm = result.scalar_one_or_none()
            return (
                Permission.model_validate(self._to_dict(db_perm)) if db_perm else None
            )

    async def assign_role_to_user(self, user_id: str | int, role_name: str) -> None:
        async with self.session_maker() as session:
            stmt = select(self.role_model.id).where(self.role_model.name == role_name)
            result = await session.execute(stmt)
            role_id = result.scalar_one_or_none()

            if not role_id:
                raise ValueError(f"Role '{role_name}' does not exist.")

            # Create the link model instance
            link = UserRoleLink(user_id=user_id, role_id=role_id)
            session.add(link)
            try:
                await session.commit()
            except IntegrityError:
                # Already assigned, perfectly fine!
                await session.rollback()

    async def remove_role_from_user(self, user_id: str | int, role_name: str) -> None:
        async with self.session_maker() as session:
            stmt = select(self.role_model.id).where(self.role_model.name == role_name)
            role_id = (await session.execute(stmt)).scalar_one_or_none()

            if role_id:
                await session.execute(
                    delete(UserRoleLink).where(
                        col(UserRoleLink.user_id) == user_id,
                        col(UserRoleLink.role_id) == role_id,
                    )
                )
                await session.commit()

    async def grant_permission_to_role(
        self, role_name: str, permission_name: str
    ) -> None:
        async with self.session_maker() as session:
            role_id = (
                await session.execute(
                    select(self.role_model.id).where(self.role_model.name == role_name)
                )
            ).scalar_one_or_none()
            if not role_id:
                raise ValueError(f"Role '{role_name}' does not exist.")

            perm_id = (
                await session.execute(
                    select(self.permission_model.id).where(
                        self.permission_model.name == permission_name
                    )
                )
            ).scalar_one_or_none()
            if not perm_id:
                raise ValueError(f"Permission '{permission_name}' does not exist.")

            link = RolePermissionLink(role_id=role_id, permission_id=perm_id)
            session.add(link)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()

    async def get_user_roles(self, user_id: str | int) -> list[Role]:
        async with self.session_maker() as session:
            stmt = (
                select(self.role_model)
                .join(UserRoleLink, self.role_model.id == col(UserRoleLink.role_id))
                .where(col(UserRoleLink.user_id) == user_id)
            )
            result = await session.execute(stmt)
            return [
                Role.model_validate(self._to_dict(r)) for r in result.scalars().all()
            ]

    async def get_user_permissions(self, user_id: str | int) -> list[Permission]:
        async with self.session_maker() as session:
            stmt = (
                select(self.permission_model)
                .join(
                    RolePermissionLink,
                    self.permission_model.id == col(RolePermissionLink.permission_id),
                )
                .join(
                    self.role_model,
                    self.role_model.id == col(RolePermissionLink.role_id),
                )
                .join(UserRoleLink, self.role_model.id == col(UserRoleLink.role_id))
                .where(col(UserRoleLink.user_id) == user_id)
                .distinct()
            )
            result = await session.execute(stmt)
            return [
                Permission.model_validate(self._to_dict(p))
                for p in result.scalars().all()
            ]

    # Passkey operations

    async def create_passkey(self, data: PasskeyCredentialCreate) -> PasskeyCredential:
        """Inserts a new passkey credential row and returns the persisted record."""
        now = datetime.now(timezone.utc)
        async with self.session_maker() as session:
            row = self.passkey_model(
                user_id=data.user_id,
                credential_id=data.credential_id,
                public_key=data.public_key,
                sign_count=data.sign_count,
                name=data.name,
                created_at=now,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return PasskeyCredential.model_validate(self._to_dict(row))

    async def get_passkeys_by_user(self, user_id: str | int) -> list[PasskeyCredential]:
        """Returns all passkey credentials registered for a user."""
        async with self.session_maker() as session:
            stmt = select(self.passkey_model).where(
                self.passkey_model.user_id == user_id
            )
            result = await session.execute(stmt)
            return [
                PasskeyCredential.model_validate(self._to_dict(row))
                for row in result.scalars().all()
            ]

    async def get_passkey_by_credential_id(
        self, credential_id: str
    ) -> PasskeyCredential | None:
        """Looks up a single passkey row by its hex-encoded credential ID."""
        async with self.session_maker() as session:
            stmt = select(self.passkey_model).where(
                self.passkey_model.credential_id == credential_id
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return PasskeyCredential.model_validate(self._to_dict(row))

    async def update_passkey_sign_count(
        self, credential_id: str, new_sign_count: int
    ) -> None:
        """Updates the monotonic sign counter after a successful authentication."""
        async with self.session_maker() as session:
            stmt = select(self.passkey_model).where(
                self.passkey_model.credential_id == credential_id
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if row:
                row.sign_count = new_sign_count
                row.updated_at = datetime.now(timezone.utc)
                session.add(row)
                await session.commit()

    async def delete_passkey(self, credential_id: str) -> bool:
        """Removes a passkey credential row. Returns True if a row was deleted."""
        async with self.session_maker() as session:
            stmt = delete(self.passkey_model).where(
                self.passkey_model.credential_id == credential_id
            )
            result = await session.execute(stmt)
            await session.commit()
            rowcount = getattr(result, "rowcount", 0)
            return bool(rowcount and rowcount > 0)
