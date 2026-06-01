from datetime import datetime, timezone

import pytest

from qulf.adapters.base import DatabaseAdapter
from qulf.types import Session, User, UserCreate, UserWithPassword


class MemoryAdapter(DatabaseAdapter):
    def __init__(self):
        self.users: dict[str, UserWithPassword] = {}
        self.sessions: dict[str, Session] = {}
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

    async def delete_session(self, token: str) -> None:
        self.sessions.pop(token, None)


@pytest.fixture
def memory_db():
    return MemoryAdapter()
