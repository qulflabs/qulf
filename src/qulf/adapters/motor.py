from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase

from qulf.adapters.base import DatabaseAdapter
from qulf.config import DeletionStrategy
from qulf.types import Account as QulfAccountType
from qulf.types import (
    AccountCreate,
    PasskeyCredential,
    PasskeyCredentialCreate,
    Permission,
    Role,
    UserCreate,
    UserWithPassword,
)
from qulf.types import Session as QulfSessionType
from qulf.types import User as QulfUserType


class MotorAdapter(DatabaseAdapter):
    name = "motor"
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

    def __init__(self, db: AsyncIOMotorDatabase[dict[str, Any]]):
        self.users: AsyncIOMotorCollection[dict[str, Any]] = db.users
        self.sessions: AsyncIOMotorCollection[dict[str, Any]] = db.sessions
        self.accounts: AsyncIOMotorCollection[dict[str, Any]] = db.accounts
        self.roles: AsyncIOMotorCollection[dict[str, Any]] = db.roles
        self.permissions: AsyncIOMotorCollection[dict[str, Any]] = db.permissions
        self.passkeys: AsyncIOMotorCollection[dict[str, Any]] = db.passkeys

    @staticmethod
    def _id_to_str(doc: dict[str, Any]) -> dict[str, Any]:
        """Convert MongoDB's _id (ObjectId) to a string 'id' field."""
        doc = dict(doc)
        doc["id"] = str(doc.pop("_id"))
        return doc

    @staticmethod
    def _to_object_id(value: str | int) -> ObjectId | str:
        try:
            return ObjectId(str(value))
        except InvalidId:
            return str(value)

    # Internal helpers
    def _to_user(self, doc: dict[str, Any]) -> QulfUserType:
        return QulfUserType.model_validate(self._id_to_str(doc))

    def _to_user_with_password(self, doc: dict[str, Any]) -> UserWithPassword:
        return UserWithPassword.model_validate(self._id_to_str(doc))

    def _to_session(self, doc: dict[str, Any]) -> QulfSessionType:
        return QulfSessionType.model_validate(self._id_to_str(doc))

    def _to_account(self, doc: dict[str, Any]) -> QulfAccountType:
        return QulfAccountType.model_validate(self._id_to_str(doc))

    def _to_role(self, doc: dict[str, Any]) -> Role:
        return Role.model_validate(self._id_to_str(doc))

    def _to_permission(self, doc: dict[str, Any]) -> Permission:
        return Permission.model_validate(self._id_to_str(doc))

    def _to_passkey(self, doc: dict[str, Any]) -> PasskeyCredential:
        return PasskeyCredential.model_validate(self._id_to_str(doc))

    # Schema injection (no-op for MongoDB)
    def inject_custom_columns(self, custom_columns: dict[str, dict[str, type]]) -> None:
        """
        No-op for MongoDB.

        MongoDB is schema-less; additional fields are stored automatically
        without any pre-declaration or migration.
        """
        pass  # pragma: no cover

    # User operations
    async def get_user_by_email(self, email: str) -> UserWithPassword | None:
        doc = await self.users.find_one({"email": email})
        if doc is None:
            return None
        return self._to_user_with_password(doc)

    async def get_user_by_id(self, user_id: str | int) -> QulfUserType | None:
        doc = await self.users.find_one({"_id": self._to_object_id(user_id)})
        if doc is None:
            return None
        return self._to_user(doc)

    async def get_user_by_email_with_password(
        self, email: str
    ) -> UserWithPassword | None:
        doc = await self.users.find_one({"email": email})
        if doc:
            doc["id"] = str(doc.pop("_id"))
            return UserWithPassword(**doc)
        return None

    async def get_user_by_id_with_password(
        self, user_id: int | str
    ) -> UserWithPassword | None:
        doc = await self.users.find_one({"_id": self._to_object_id(user_id)})
        if doc:
            doc["id"] = str(doc.pop("_id"))
            return UserWithPassword(**doc)
        return None

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
        result = await self.users.insert_one(doc)
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

        doc = await self.users.find_one_and_update(
            {"_id": oid},
            {"$set": update_data},
            return_document=True,
        )
        if doc is None:
            raise ValueError("User not found")
        return self._to_user(doc)

    async def delete_user(self, user_id: str, strategy: DeletionStrategy) -> None:
        if strategy == DeletionStrategy.HARD:
            await self.users.delete_one({"_id": self._to_object_id(user_id)})
        else:
            await self.users.update_one(
                {"_id": self._to_object_id(user_id)},
                {"$set": {"deleted_at": datetime.now(timezone.utc)}},
            )

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
        result = await self.sessions.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_session(doc)

    async def get_session(self, token: str) -> QulfSessionType | None:
        doc = await self.sessions.find_one({"token": token})
        if doc is None:
            return None
        return self._to_session(doc)

    async def delete_session(self, token: str) -> bool:
        result = await self.sessions.delete_one({"token": token})
        return result.deleted_count > 0

    async def get_user_sessions(self, user_id: str | int) -> list[QulfSessionType]:
        cursor = self.sessions.find({"user_id": str(user_id)})
        docs = await cursor.to_list(length=None)
        return [self._to_session(doc) for doc in docs]

    async def delete_user_session(
        self, user_id: str | int, token: str | None = None
    ) -> bool:
        result = await self.sessions.delete_one(
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
        cursor = self.sessions.find(query, {"token": 1})
        docs = await cursor.to_list(length=None)
        tokens = [doc["token"] for doc in docs]

        if tokens:
            await self.sessions.delete_many(query)

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
        result = await self.accounts.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_account(doc)

    async def get_account_by_provider(
        self, provider_id: str, account_id: str
    ) -> QulfAccountType | None:
        doc = await self.accounts.find_one(
            {"provider_id": provider_id, "account_id": account_id}
        )
        if doc is None:
            return None
        return self._to_account(doc)

    async def create_permission(
        self, name: str, description: str | None = None
    ) -> Permission:
        doc = {
            "name": name,
            "description": description,
            "created_at": datetime.now(timezone.utc),
            "updated_at": None,
        }
        result = await self.permissions.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_permission(doc)

    async def get_permission_by_name(self, name: str) -> Permission | None:
        doc = await self.permissions.find_one({"name": name})
        return self._to_permission(doc) if doc else None

    async def create_role(self, name: str, description: str | None = None) -> Role:
        doc = {
            "name": name,
            "description": description,
            "created_at": datetime.now(timezone.utc),
            "updated_at": None,
        }
        result = await self.roles.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_role(doc)

    async def get_role_by_name(self, name: str) -> Role | None:
        doc = await self.roles.find_one({"name": name})
        return self._to_role(doc) if doc else None

    async def assign_role_to_user(self, user_id: str | int, role_name: str) -> None:
        # Verify role exists
        if not await self.roles.find_one({"name": role_name}):
            raise ValueError(f"Role '{role_name}' does not exist.")

        uid = self._to_object_id(user_id)
        await self.users.update_one({"_id": uid}, {"$addToSet": {"roles": role_name}})

    async def remove_role_from_user(self, user_id: str | int, role_name: str) -> None:
        uid = self._to_object_id(user_id)
        await self.users.update_one({"_id": uid}, {"$pull": {"roles": role_name}})

    async def grant_permission_to_role(
        self, role_name: str, permission_name: str
    ) -> None:
        # Verify permission exists
        if not await self.permissions.find_one({"name": permission_name}):
            raise ValueError(f"Permission '{permission_name}' does not exist.")

        result = await self.roles.update_one(
            {"name": role_name}, {"$addToSet": {"permissions": permission_name}}
        )
        if result.matched_count == 0:
            raise ValueError(f"Role '{role_name}' does not exist.")

    async def get_user_roles(self, user_id: str | int) -> list[Role]:
        uid = self._to_object_id(user_id)
        user_doc = await self.users.find_one({"_id": uid}, {"roles": 1})

        if not user_doc or not user_doc.get("roles"):
            return []

        cursor = self.roles.find({"name": {"$in": user_doc["roles"]}})
        roles = await cursor.to_list(length=None)

        return [self._to_role(r) for r in roles]

    async def get_user_permissions(self, user_id: str | int) -> list[Permission]:
        uid = self._to_object_id(user_id)
        user_doc = await self.users.find_one({"_id": uid}, {"roles": 1})

        if not user_doc or not user_doc.get("roles"):
            return []

        roles_cursor = self.roles.find(
            {"name": {"$in": user_doc["roles"]}}, {"permissions": 1}
        )
        roles = await roles_cursor.to_list(length=None)

        perm_names = set()
        for r in roles:
            perm_names.update(r.get("permissions", []))

        if not perm_names:
            return []

        perms_cursor = self.permissions.find({"name": {"$in": list(perm_names)}})
        perms = await perms_cursor.to_list(length=None)

        return [self._to_permission(p) for p in perms]

    # Passkey operations

    async def create_passkey(self, data: PasskeyCredentialCreate) -> PasskeyCredential:
        """Inserts a new passkey credential document and returns it."""
        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "user_id": str(data.user_id),
            "credential_id": data.credential_id,
            "public_key": data.public_key,
            "sign_count": data.sign_count,
            "name": data.name,
            "created_at": now,
            "updated_at": None,
        }
        result = await self.passkeys.insert_one(doc)
        doc["_id"] = result.inserted_id
        return self._to_passkey(doc)

    async def get_passkeys_by_user(self, user_id: str | int) -> list[PasskeyCredential]:
        """Returns all passkey credentials registered for a user."""
        cursor = self.passkeys.find({"user_id": str(user_id)})
        docs = await cursor.to_list(length=None)
        return [self._to_passkey(d) for d in docs]

    async def get_passkey_by_credential_id(
        self, credential_id: str
    ) -> PasskeyCredential | None:
        """Looks up a single passkey document by its hex-encoded credential ID."""
        doc = await self.passkeys.find_one({"credential_id": credential_id})
        if doc is None:
            return None
        return self._to_passkey(doc)

    async def update_passkey_sign_count(
        self, credential_id: str, new_sign_count: int
    ) -> None:
        """Updates the monotonic sign counter after a successful authentication."""
        await self.passkeys.update_one(
            {"credential_id": credential_id},
            {
                "$set": {
                    "sign_count": new_sign_count,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

    async def delete_passkey(self, credential_id: str) -> bool:
        """Removes a passkey document. Returns True if a document was deleted."""
        result = await self.passkeys.delete_one({"credential_id": credential_id})
        return result.deleted_count > 0
