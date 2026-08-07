from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from qulf.adapters.base import DatabaseAdapter
from qulf.adapters.sqlalchemy import QulfBase, SQLAlchemyAdapter
from qulf.config import DeletionStrategy, QulfConfig
from qulf.core import Qulf
from qulf.plugins.base import QulfPlugin
from qulf.routing import CookieOptions, HttpMethod, QulfRequest, QulfResponse, QulfRoute
from qulf.types import (
    Account,
    AccountCreate,
    Permission,
    Role,
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
        self.roles: dict[str, Role] = {}
        self.permissions: dict[str, Permission] = {}
        self.user_roles: dict[str, set[str]] = {}
        self.role_permissions: dict[str, set[str]] = {}

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
            # we set extra="allow" on CoreModel, to use setattr
            setattr(user, key, value)

        return User.model_validate(user, from_attributes=True)

    async def delete_user(self, user_id: str, strategy: DeletionStrategy) -> None:
        user = self.users.get(str(user_id))
        if strategy == DeletionStrategy.HARD:
            self.users.pop(str(user_id))
        else:
            setattr(user, "deleted_at", datetime.now(timezone.utc))

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

    async def get_user_by_email_with_password(self, email: str):
        # In memory, we just return the same user object
        for user in self.users.values():
            if user.email == email:
                return user
        return None

    async def get_user_by_id_with_password(self, user_id: int | str):
        return self.users.get(str(user_id))

    async def create_role(self, name: str, description: str | None = None) -> Role:
        role = Role(
            id=str(self._id_counter),
            name=name,
            description=description,
            created_at=datetime.now(timezone.utc),
            updated_at=None,
        )
        self.roles[name] = role
        return role

    async def get_role_by_name(self, name: str) -> Role | None:
        return self.roles.get(name)

    async def create_permission(
        self, name: str, description: str | None = None
    ) -> Permission:
        permission = Permission(
            id=str(self._id_counter),
            name=name,
            description=description,
            created_at=datetime.now(timezone.utc),
            updated_at=None,
        )
        self.permissions[name] = permission
        return permission

    async def get_permission_by_name(self, name: str) -> Permission | None:
        return self.permissions.get(name)

    async def assign_role_to_user(self, user_id: str | int, role_name: str) -> None:
        if role_name not in self.roles:
            raise ValueError(f"Role '{role_name}' does not exist.")

        uid = str(user_id)
        if uid not in self.user_roles:
            self.user_roles[uid] = set()
        self.user_roles[uid].add(role_name)

    async def remove_role_from_user(self, user_id: str | int, role_name: str) -> None:
        uid = str(user_id)
        if uid in self.user_roles and role_name in self.user_roles[uid]:
            self.user_roles[uid].remove(role_name)

    async def grant_permission_to_role(
        self, role_name: str, permission_name: str
    ) -> None:
        if role_name not in self.roles:
            raise ValueError(f"Role '{role_name}' does not exist.")
        if permission_name not in self.permissions:
            raise ValueError(f"Permission '{permission_name}' does not exist.")

        if role_name not in self.role_permissions:
            self.role_permissions[role_name] = set()
        self.role_permissions[role_name].add(permission_name)

    async def get_user_roles(self, user_id: str | int) -> list[Role]:
        uid = str(user_id)
        role_names = self.user_roles.get(uid, set())
        return [self.roles[name] for name in role_names if name in self.roles]

    async def get_user_permissions(self, user_id: str | int) -> list[Permission]:
        uid = str(user_id)
        role_names = self.user_roles.get(uid, set())

        perm_names = set()
        for role in role_names:
            perm_names.update(self.role_permissions.get(role, set()))

        return [
            self.permissions[name] for name in perm_names if name in self.permissions
        ]


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
async def sqlalchemy_adapter():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    # Create the tables
    async with engine.begin() as conn:
        await conn.run_sync(QulfBase.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    yield SQLAlchemyAdapter(session_maker)

    await engine.dispose()


@pytest_asyncio.fixture
async def sqlmodel_adapter():
    from sqlmodel import SQLModel

    from qulf.adapters.sqlmodel import SQLModelAdapter

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)

    yield SQLModelAdapter(session_maker)

    await engine.dispose()


@pytest_asyncio.fixture
async def motor_adapter():
    import mongomock_motor

    from qulf.adapters.motor import MotorAdapter

    client = mongomock_motor.AsyncMongoMockClient()
    db = client["qulf_test"]
    yield MotorAdapter(db)
    client.close()


@pytest.fixture
def dummy_user():
    return User(
        id="123",
        email="test@example.com",
        name="Test User",
        username="testuser",
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def dummy_session():
    return Session(
        id="123",
        token="test_token",
        user_id="123",
        expires_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def auth_mock(dummy_user, dummy_session):
    """A completely mocked Qulf engine for testing framework wrappers and routing."""
    auth = MagicMock(spec=Qulf)
    auth.config = QulfConfig(secret_key="test_secret_key_needs_to_be_long_enough")
    auth._get_authenticated_user_id = AsyncMock()
    auth.sign_up = AsyncMock()
    auth.sign_in = AsyncMock()
    auth.sign_out = AsyncMock()
    auth.validate_session = AsyncMock()
    auth.generate_password_reset_token = AsyncMock()
    auth.reset_password = AsyncMock()
    auth.verify_email = AsyncMock()
    auth.change_password = AsyncMock()
    auth.delete_account = AsyncMock()
    auth.revoke_all_user_sessions = AsyncMock()
    auth.get_session_from_cookies = AsyncMock()
    auth.has_role = AsyncMock()
    auth.has_permission = AsyncMock()

    class MockRBACPlugin(QulfPlugin):
        name = "mock_rbac"

        def get_routes(self) -> list[QulfRoute]:
            async def handler(req: QulfRequest) -> QulfResponse:
                return QulfResponse(status_code=200, body={"ok": True})

            async def complex_handler(req: QulfRequest) -> QulfResponse:
                return QulfResponse(
                    status_code=201,
                    body={"complex": True},
                    headers={"X-Custom-Header": "qulf-rocks"},
                    set_cookies=[
                        CookieOptions(
                            key="new_cookie",
                            value="val",
                            httponly=True,
                            secure=True,
                            samesite="strict",
                        )
                    ],
                    delete_cookies=["old_cookie"],
                )

            return [
                QulfRoute(
                    path="/plugin-role",
                    methods=[HttpMethod.GET],
                    handler=handler,
                    require_roles=["admin"],
                ),
                QulfRoute(
                    path="/plugin-perm",
                    methods=[HttpMethod.GET],
                    handler=handler,
                    require_permissions=["write:docs"],
                ),
                QulfRoute(
                    path="/plugin-complex",
                    methods=[HttpMethod.POST, HttpMethod.PUT],
                    handler=complex_handler,
                ),
            ]

    auth.plugins = {"mock": MockRBACPlugin()}
    return auth
