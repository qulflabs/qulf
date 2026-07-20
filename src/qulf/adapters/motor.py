from datetime import datetime, timezone
from typing import Any

from bson import ObjectId

from qulf.adapters.base import DatabaseAdapter
from qulf.types import Account as QulfAccountType
from qulf.types import AccountCreate, UserCreate, UserWithPassword
from qulf.types import Session as QulfSessionType
from qulf.types import User as QulfUserType


def _id_to_str(doc: dict[str, Any]) -> dict[str, Any]:
    """Convert MongoDB's _id (ObjectId) to a string 'id' field."""
    doc = dict(doc)
    doc["id"] = str(doc.pop("_id"))
    return doc


class MotorAdapter(DatabaseAdapter):
    """
    Concrete DatabaseAdapter backed by MongoDB via the Motor async driver.

    Accepts an ``AsyncIOMotorDatabase`` instance and operates on three
    collections: ``users``, ``sessions``, and ``accounts``.

    MongoDB's native ``_id`` (ObjectId) is transparently mapped to the
    string ``id`` field expected by all Qulf Pydantic types.

    Example usage::

        from motor.motor_asyncio import AsyncIOMotorClient
        from qulf.adapters.motor import MotorAdapter

        client = AsyncIOMotorClient("mongodb://localhost:27017")
        adapter = MotorAdapter(client["mydb"])
    """

    def __init__(self, db: Any) -> None:
        """
        Args:
            db: An ``AsyncIOMotorDatabase`` instance.
        """
        self.db = db

    # Internal helpers
    def _to_user(self, doc: dict[str, Any]) -> QulfUserType:
        return QulfUserType.model_validate(_id_to_str(doc))

    def _to_user_with_password(self, doc: dict[str, Any]) -> UserWithPassword:
        return UserWithPassword.model_validate(_id_to_str(doc))

    def _to_session(self, doc: dict[str, Any]) -> QulfSessionType:
        return QulfSessionType.model_validate(_id_to_str(doc))

    def _to_account(self, doc: dict[str, Any]) -> QulfAccountType:
        return QulfAccountType.model_validate(_id_to_str(doc))

    # User operations
    async def get_user_by_email(self, email: str) -> UserWithPassword | None:
        doc = await self.db.users.find_one({"email": email})
        if doc is None:
            return None
        return self._to_user_with_password(doc)

    async def get_user_by_id(self, user_id: str | int) -> QulfUserType | None:
        try:
            oid = ObjectId(str(user_id))
        except Exception:
            return None
        doc = await self.db.users.find_one({"_id": oid})
        if doc is None:
            return None
        return self._to_user(doc)

    async def create_user(
        self, user_data: UserCreate, hashed_password: str
    ) -> QulfUserType:
        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "email": user_data.email,
            "name": user_data.name,
            "username": user_data.username,
            "hashed_password": hashed_password,
            "created_at": now,
            "updated_at": None,
            "last_login": None,
        }
        result = await self.db.users.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_user(doc)

    async def update_user(
        self, user_id: str | int, update_data: dict[str, Any]
    ) -> QulfUserType:
        try:
            oid = ObjectId(str(user_id))
        except Exception:
            raise ValueError("User not found")

        update_data = dict(update_data)
        update_data["updated_at"] = datetime.now(timezone.utc)

        doc = await self.db.users.find_one_and_update(
            {"_id": oid},
            {"$set": update_data},
            return_document=True,  # pymongo ReturnDocument.AFTER == True
        )
        if doc is None:
            raise ValueError("User not found")
        return self._to_user(doc)

    # Session operations
    async def create_session(
        self,
        user_id: str | int,
        token: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> QulfSessionType:
        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "user_id": str(user_id),
            "token": token,
            "expires_at": expires_at,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": now,
            "updated_at": None,
        }
        result = await self.db.sessions.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_session(doc)

    async def get_session(self, token: str) -> QulfSessionType | None:
        doc = await self.db.sessions.find_one({"token": token})
        if doc is None:
            return None
        return self._to_session(doc)

    async def delete_session(self, token: str) -> bool:
        result = await self.db.sessions.delete_one({"token": token})
        return result.deleted_count > 0

    async def get_user_sessions(self, user_id: str | int) -> list[QulfSessionType]:
        cursor = self.db.sessions.find({"user_id": str(user_id)})
        docs = await cursor.to_list(length=None)
        return [self._to_session(doc) for doc in docs]

    async def delete_user_session(
        self, user_id: str | int, token: str | None = None
    ) -> bool:
        result = await self.db.sessions.delete_one(
            {"user_id": str(user_id), "token": token}
        )
        return result.deleted_count > 0

    async def delete_all_user_sessions(
        self, user_id: str | int, except_token: str | None = None
    ) -> list[str]:
        query: dict[str, Any] = {"user_id": str(user_id)}
        if except_token is not None:
            query["token"] = {"$ne": except_token}

        # Collect tokens before deletion so we can return them
        cursor = self.db.sessions.find(query, {"token": 1})
        docs = await cursor.to_list(length=None)
        tokens = [doc["token"] for doc in docs]

        if tokens:
            await self.db.sessions.delete_many(query)

        return tokens

    # Account (OAuth) operations
    async def create_account(self, account_data: AccountCreate) -> QulfAccountType:
        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "user_id": str(account_data.user_id),
            "account_id": account_data.account_id,
            "provider_id": account_data.provider_id,
            "access_token": account_data.access_token,
            "refresh_token": account_data.refresh_token,
            "expires_at": account_data.expires_at,
            "scope": account_data.scope,
            "id_token": account_data.id_token,
            "created_at": now,
            "updated_at": None,
        }
        result = await self.db.accounts.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_account(doc)

    async def get_account_by_provider(
        self, provider_id: str, account_id: str
    ) -> QulfAccountType | None:
        doc = await self.db.accounts.find_one(
            {"provider_id": provider_id, "account_id": account_id}
        )
        if doc is None:
            return None
        return self._to_account(doc)

    # Schema injection (no-op for MongoDB)
    def inject_custom_columns(self, custom_columns: dict[str, dict[str, type]]) -> None:
        """
        No-op for MongoDB.

        MongoDB is schema-less; additional fields are stored automatically
        without any pre-declaration or migration.
        """
        pass  # pragma: no cover
