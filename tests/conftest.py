from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from qulf.adapters.base import DatabaseAdapter
from qulf.adapters.sqlalchemy import QulfBase, SQLAlchemyAdapter
from qulf.config import QulfConfig
from qulf.core import Qulf
from qulf.types import (
    Account,
    AccountCreate,
    Session,
    User,
    UserCreate,
    UserWithPassword,
)


class MemoryAdapter(DatabaseAdapter):
    def __init__(self):
        self.users: dict[str, UserWithPassword] = {}
        self.sessions: dict[str, Session] = {}
        self.accounts: dict[str, Account] = {}
        self._id_counter = 1

    async def get_user_by_email(self, email: str) -> UserWithPassword | None:
        for u in self.users.values():
            if u.email == email:
                return u
        return None

    async def get_user_by_id(self, user_id: str | int) -> User | None:
        user = self.users.get(str(user_id))
        return User.model_validate(user, from_attributes=True) if user else None

    async def create_user(self, user_data: UserCreate, hashed_password: str) -> User:
        new_id = str(self._id_counter)
        self._id_counter += 1
        new_user = UserWithPassword(
            id=new_id,
            email=user_data.email,
            name=user_data.name,
            username=user_data.username,
            hashed_password=hashed_password,
            created_at=datetime.now(timezone.utc),
        )
        self.users[new_id] = new_user
        return User.model_validate(new_user, from_attributes=True)

    async def update_user(self, user_id: str | int, update_data: dict) -> User:

        user = self.users.get(str(user_id))
        if not user:
            raise ValueError("User not found")

        for key, value in update_data.items():
            # Because we set extra="allow" on CoreModel, we can just use setattr
            setattr(user, key, value)

        return User.model_validate(user, from_attributes=True)

    async def create_session(
        self, user_id, token, expires_at, ip_address=None, user_agent=None
    ) -> Session:
        new_session = Session(
            id=str(self._id_counter),
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.now(timezone.utc),
        )
        self._id_counter += 1
        self.sessions[token] = new_session
        return new_session

    async def get_session(self, token: str) -> Session | None:
        return self.sessions.get(token)

    async def delete_session(self, token: str) -> bool:
        session = self.sessions.pop(token, False)
        return bool(session)

    async def get_user_sessions(self, user_id: str | int) -> list[Session]:
        return [s for s in self.sessions.values() if str(s.user_id) == str(user_id)]

    async def delete_user_session(
        self, user_id: str | int, token: str | None = None
    ) -> bool:
        if token and token in self.sessions:
            if str(self.sessions[token].user_id) == str(user_id):
                self.sessions.pop(token)
                return True
        return False

    async def delete_all_user_sessions(
        self, user_id: str | int, except_token: str | None = None
    ) -> list[str]:
        tokens_to_delete = [
            t
            for t, s in self.sessions.items()
            if str(s.user_id) == str(user_id) and t != except_token
        ]
        for t in tokens_to_delete:
            self.sessions.pop(t)
        return tokens_to_delete

    async def create_account(self, account_data: AccountCreate) -> Account:
        new_id = str(self._id_counter)
        self._id_counter += 1
        new_account = Account(
            id=new_id,
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
        self.accounts[new_id] = new_account
        return new_account

    async def get_account_by_provider(
        self, provider_id: str, account_id: str
    ) -> Account | None:
        for acc in self.accounts.values():
            if acc.provider_id == provider_id and acc.account_id == account_id:
                return acc
        return None


@pytest.fixture
def memory_db():
    return MemoryAdapter()


@pytest.fixture
def auth(memory_db):
    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
    )
    return Qulf(db=memory_db, config=config)


@pytest_asyncio.fixture
async def sqlite_adapter():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    # Create the tables
    async with engine.begin() as conn:
        await conn.run_sync(QulfBase.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    return SQLAlchemyAdapter(session_maker)
