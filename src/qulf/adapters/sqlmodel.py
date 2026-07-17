from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import mapped_column
from sqlmodel import Field, SQLModel, select

from qulf.adapters.base import DatabaseAdapter
from qulf.types import (
    Account as QulfAccountType,
)
from qulf.types import (
    AccountCreate,
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

    __tablename__ = "user"  # pyrefly: ignore[bad-override]

    id: int | None = Field(default=None, primary_key=True)


class DefaultSession(SessionMixin, table=True):
    """Default Session table schema."""

    __tablename__ = "session"  # pyrefly: ignore[bad-override]

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")


class DefaultAccount(AccountMixin, table=True):
    """Default Account table schema."""

    __tablename__ = "account"  # pyrefly: ignore[bad-override]

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")


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
    ):
        self.session_maker = session_maker
        self.user_model = user_model
        self.session_model = session_model
        self.account_model = account_model

        self.models = {
            "user": self.user_model,
            "session": self.session_model,
            "account": self.account_model,
        }

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
            return UserWithPassword.model_validate(db_user, from_attributes=True)

    async def get_user_by_id(self, user_id: str | int) -> QulfUserType | None:
        async with self.session_maker() as session:
            stmt = select(self.user_model).where(self.user_model.id == user_id)
            result = await session.execute(stmt)
            db_user = result.scalar_one_or_none()
            if not db_user:
                return None
            return QulfUserType.model_validate(db_user, from_attributes=True)

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
            return QulfUserType.model_validate(new_user, from_attributes=True)

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
                setattr(user, field, value)

            await session.commit()
            await session.refresh(user)
            return QulfUserType.model_validate(user, from_attributes=True)

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
            return QulfSessionType.model_validate(new_session, from_attributes=True)

    async def get_session(self, token: str) -> QulfSessionType | None:
        async with self.session_maker() as session:
            stmt = select(self.session_model).where(self.session_model.token == token)
            result = await session.execute(stmt)
            db_session = result.scalar_one_or_none()
            if not db_session:
                return None
            return QulfSessionType.model_validate(db_session, from_attributes=True)

    async def delete_session(self, token: str) -> bool:
        from sqlalchemy import delete

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
                QulfSessionType.model_validate(db_s, from_attributes=True)
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
            return QulfAccountType.model_validate(new_account, from_attributes=True)

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
            return QulfAccountType.model_validate(db_account, from_attributes=True)
