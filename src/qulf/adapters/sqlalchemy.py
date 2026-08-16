from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

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


class UserMixin:
    """
    SQLAlchemy column definitions for the Qulf User model.

    Using a Mixin allows developers to inherit these field definitions directly
    into their existing SQLAlchemy user models, avoiding database migration rewrites
    and letting them extend user schemas with custom application fields.
    """

    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class SessionMixin:
    """
    SQLAlchemy column definitions for the Qulf Session model.

    Like UserMixin, this is modular to facilitate schema integration with
    custom developer session tables.
    """

    token: Mapped[str] = mapped_column(String, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class QulfBase(DeclarativeBase):
    """Base declarative class for default out-of-the-box Qulf schemas."""

    pass


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


class AccountMixin:
    """
    SQLAlchemy column definitions for the Qulf Account model.
    """

    provider_id: Mapped[str] = mapped_column(String, index=True)
    account_id: Mapped[str] = mapped_column(String, index=True)

    access_token: Mapped[str | None] = mapped_column(String, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    scope: Mapped[str | None] = mapped_column(String, nullable=True)
    id_token: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


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


class RoleMixin:
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class PermissionMixin:
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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


class SQLAlchemyAdapter(DatabaseAdapter):
    """
    Concrete DatabaseAdapter subclass leveraging SQLAlchemy 2.0 async capabilities.
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
            "role": self.role_model,
            "permission": self.permission_model,
            "passkey": self.passkey_model,
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

        # Iterate dynamically over ANY table the plugins request
        for table_name, columns in custom_columns.items():
            # Check if Qulf manages table
            model = self.models.get(table_name)
            if not model:
                continue  # Ignore if plugin tries to inject into a table we don't know

            for col_name, col_type in columns.items():
                if not hasattr(model, col_name):
                    sa_type = type_mapping.get(col_type, String)
                    setattr(model, col_name, mapped_column(sa_type, nullable=True))

    async def get_user_by_email_with_password(
        self, email: str
    ) -> UserWithPassword | None:
        async with self.session_maker() as session:
            stmt = select(self.user_model).where(self.user_model.email == email)
            result = await session.execute(stmt)
            db_user = result.scalar_one_or_none()
            if not db_user:
                return None
            return UserWithPassword.model_validate(self._to_dict(db_user))

    async def get_user_by_email(self, email: str) -> QulfUserType | None:
        async with self.session_maker() as session:
            stmt = select(self.user_model).where(self.user_model.email == email)
            result = await session.execute(stmt)
            db_user = result.scalar_one_or_none()
            if not db_user:
                return None
            return QulfUserType.model_validate(self._to_dict(db_user))

    async def get_user_by_id_with_password(
        self, user_id: str | int
    ) -> UserWithPassword | None:
        async with self.session_maker() as session:
            stmt = select(self.user_model).where(self.user_model.id == user_id)
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
        """
        Args:
            user_id (str | int)
            update_data (dict[str, Any]): **Trusted data!**

        Raises:
            ValueError: User not found

        Returns:
            User
        """
        async with self.session_maker() as session:
            result = await session.execute(
                select(self.user_model).where(self.user_model.id == user_id)
            )
            user = result.scalars().first()
            if not user:
                raise ValueError("User not found")

            for field, value in update_data.items():
                setattr(user, field, value)

            await session.commit()
            await session.refresh(user)
            return QulfUserType.model_validate(self._to_dict(user))

    async def delete_user(self, user_id: str, strategy: DeletionStrategy) -> None:

        async with self.session_maker() as session:
            if strategy == DeletionStrategy.HARD:
                await session.execute(
                    delete(self.user_model).where(self.user_model.id == user_id)
                )
            else:
                await session.execute(
                    update(self.user_model)
                    .where(self.user_model.id == user_id)
                    .values(deleted_at=datetime.now(timezone.utc))
                )
                await session.commit()

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
        async with self.session_maker() as session:
            stmt = delete(self.session_model).where(
                self.session_model.user_id == user_id
            )

            if except_token is not None:
                stmt = stmt.where(self.session_model.token != except_token)
            final_stmt = stmt.returning(self.session_model.token)

            result = await session.execute(final_stmt)
            await session.commit()

            return list(result.scalars().all())

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

    async def create_role(self, name: str, description: str | None = None) -> Role:
        """Create a new role in the roles table."""
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
        """Fetch a role by its unique name."""
        async with self.session_maker() as session:
            stmt = select(self.role_model).where(self.role_model.name == name)
            result = await session.execute(stmt)
            db_role = result.scalar_one_or_none()
            return Role.model_validate(self._to_dict(db_role)) if db_role else None

    async def create_permission(
        self, name: str, description: str | None = None
    ) -> Permission:
        """Create a new permission in the permissions table."""
        async with self.session_maker() as session:
            new_permission = self.permission_model(
                name=name,
                description=description,
                created_at=datetime.now(timezone.utc),
            )
            session.add(new_permission)
            await session.commit()
            await session.refresh(new_permission)
            return Permission.model_validate(self._to_dict(new_permission))

    async def get_permission_by_name(self, name: str) -> Permission | None:
        """Fetch a permission by its unique name."""
        async with self.session_maker() as session:
            stmt = select(self.permission_model).where(
                self.permission_model.name == name
            )
            result = await session.execute(stmt)
            db_permission = result.scalar_one_or_none()
            return (
                Permission.model_validate(self._to_dict(db_permission))
                if db_permission
                else None
            )

    async def assign_role_to_user(self, user_id: str | int, role_name: str) -> None:
        """Link a user to a role via the user_roles mapping table."""
        async with self.session_maker() as session:
            # 1. Fetch the role by name to get its ID
            stmt = select(self.role_model.id).where(self.role_model.name == role_name)
            result = await session.execute(stmt)
            role_id = result.scalar_one_or_none()

            if not role_id:
                raise ValueError(f"Role '{role_name}' does not exist.")

            try:
                await session.execute(
                    insert(user_roles).values(user_id=user_id, role_id=role_id)
                )
                await session.commit()
            except Exception:
                pass  # Already assigned

    async def remove_role_from_user(self, user_id: str | int, role_name: str) -> None:
        """Remove a link from the user_roles mapping table."""
        async with self.session_maker() as session:
            # 1. Get role_id
            stmt = select(self.role_model.id).where(self.role_model.name == role_name)
            role_id = (await session.execute(stmt)).scalar_one_or_none()

            if role_id:
                # 2. Delete from mapping table
                await session.execute(
                    delete(user_roles).where(
                        user_roles.c.user_id == user_id, user_roles.c.role_id == role_id
                    )
                )
                await session.commit()

    async def grant_permission_to_role(
        self, role_name: str, permission_name: str
    ) -> None:
        """Link a permission to a role via the role_permissions table."""
        async with self.session_maker() as session:
            # 1. Fetch the role by name to get its ID
            role_stmt = select(self.role_model.id).where(
                self.role_model.name == role_name
            )
            result = await session.execute(role_stmt)
            role_id = result.scalar_one_or_none()

            if not role_id:
                raise ValueError(f"Role '{role_name}' does not exist.")

            # 1. Fetch the role by name to get its ID
            perm_stmt = select(self.permission_model.id).where(
                self.permission_model.name == permission_name
            )
            result = await session.execute(perm_stmt)
            permission_id = result.scalar_one_or_none()

            if not permission_id:
                raise ValueError(f"Permission '{permission_name}' does not exist.")

            try:
                await session.execute(
                    insert(role_permissions).values(
                        permission_id=permission_id, role_id=role_id
                    )
                )
                await session.commit()
            except Exception:
                pass  # Already assigned

    async def get_user_roles(self, user_id: str | int) -> list[Role]:
        """Fetch all roles directly assigned to a user."""
        async with self.session_maker() as session:
            stmt = (
                select(self.role_model)
                .join(user_roles, self.role_model.id == user_roles.c.role_id)
                .where(user_roles.c.user_id == user_id)
            )
            result = await session.execute(stmt)
            return [
                Role.model_validate(self._to_dict(r)) for r in result.scalars().all()
            ]

    async def get_user_permissions(self, user_id: str | int) -> list[Permission]:
        """Fetch all unique permissions the user has through their assigned roles."""
        async with self.session_maker() as session:
            stmt = (
                select(self.permission_model)
                .join(
                    role_permissions,
                    self.permission_model.id == role_permissions.c.permission_id,
                )
                .join(self.role_model, self.role_model.id == role_permissions.c.role_id)
                .join(user_roles, self.role_model.id == user_roles.c.role_id)
                .where(user_roles.c.user_id == user_id)
                .distinct()  # strip duplicates
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
            stmt = (
                update(self.passkey_model)
                .where(self.passkey_model.credential_id == credential_id)
                .values(
                    sign_count=new_sign_count,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await session.execute(stmt)
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
