from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from qulf.adapters.base import DatabaseAdapter
from qulf.types import (
    Session as QulfSessionType,
)
from qulf.types import (
    User as QulfUserType,
)
from qulf.types import (
    UserCreate,
    UserWithPassword,
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

    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)


class DefaultSession(QulfBase, SessionMixin):
    """Default Session table schema ('qulf_session')
    used if no custom model is supplied."""

    __tablename__ = "qulf_session"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"))


class SQLAlchemyAdapter(DatabaseAdapter):
    """
    Concrete DatabaseAdapter subclass leveraging SQLAlchemy 2.0 async capabilities.
    """

    def __init__(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        user_model: Any = DefaultUser,
        session_model: Any = DefaultSession,
    ):
        self.session_maker = session_maker
        self.user_model = user_model
        self.session_model = session_model

        self.models = {"user": self.user_model, "session": self.session_model}

    def inject_custom_columns(self, custom_columns: dict[str, dict[str, Any]]) -> None:
        type_mapping = {str: String, bool: Boolean, int: Integer}

        # Iterate dynamically over ANY table the plugins request
        for table_name, columns in custom_columns.items():
            # Check if Qulf actually manages this table
            model = self.models.get(table_name)
            if not model:
                continue  # Ignore if  plugin tries to inject into a table we don't know

            for col_name, col_type in columns.items():
                if not hasattr(model, col_name):
                    sa_type = type_mapping.get(col_type, String)
                    setattr(model, col_name, mapped_column(sa_type, nullable=True))

    async def get_user_by_email(self, email: str) -> UserWithPassword | None:
        # We retrieve short-lived sessions directly inside database operations to
        # make sure connections are checked back into the pool as fast as possible,
        # avoiding connection starvation during long-running API operations.
        async with self.session_maker() as session:
            stmt = select(self.user_model).where(self.user_model.email == email)
            result = await session.execute(stmt)
            db_user = result.scalar_one_or_none()
            if not db_user:
                return None
            # Enforcing from_attributes=True instructs Pydantic to read SQLAlchemy ORM
            # properties as attributes (obj.field) rather than searching for dict keys.
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

    async def delete_session(self, token: str) -> None:
        async with self.session_maker() as session:
            stmt = delete(self.session_model).where(self.session_model.token == token)
            await session.execute(stmt)
            await session.commit()
