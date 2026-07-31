import pytest

from qulf.core import Qulf
from qulf.exceptions import QulfException
from qulf.plugins.base import QulfPlugin
from qulf.types import Session, User, UserCreate


class MockLifecyclePlugin(QulfPlugin):
    name = "mock_lifecycle"

    def __init__(self):
        self.events = []

    def setup(self, auth):
        self.auth = auth

    async def before_user_create(self, user_data: UserCreate) -> UserCreate:
        # Mutate the data: Capitalize the name
        user_data.name = user_data.name.upper()
        self.events.append("before_user_create_fired")
        return user_data

    async def after_user_create(self, user: User) -> None:
        self.events.append(f"after_user_create_fired_for_{user.email}")

    async def before_sign_in(self, email: str, ip_address: str | None = None) -> None:
        # Block flow: Ban a specific email
        if email == "banned@test.com":
            raise QulfException("This user is banned!")
        self.events.append("before_sign_in_fired")

    async def after_sign_in(self, user: User, session: Session) -> None:
        self.events.append("after_sign_in_fired")


@pytest.mark.asyncio
async def test_plugin_lifecycle_hooks(memory_db):
    mock_plugin = MockLifecyclePlugin()

    # Initialize Qulf with our mock plugin!
    from qulf.config import QulfConfig

    config = QulfConfig(
        secret_key="super_secret_test_key_that_is_at_least_32_bytes_long"
    )
    auth = Qulf(db=memory_db, config=config, plugins=[mock_plugin])

    # 1. Test Sign Up (Mutating and After Hooks)
    user_data = UserCreate(
        name="lowercase name",
        email="good@test.com",
        username="tester1",
        password="password",
        password_confirmation="password",
    )
    user = await auth.sign_up(user_data)

    # Assert the BEFORE hook successfully mutated the name
    assert user.name == "LOWERCASE NAME"

    # Assert the hooks fired in order
    assert "before_user_create_fired" in mock_plugin.events
    assert "after_user_create_fired_for_good@test.com" in mock_plugin.events

    # 2. Test Sign In (After Hook)
    _session = await auth.sign_in("good@test.com", "password")
    assert "before_sign_in_fired" in mock_plugin.events
    assert "after_sign_in_fired" in mock_plugin.events

    # 3. Test Sign In Blocking (Before Hook)
    await auth.sign_up(
        UserCreate(
            name="Banned Guy",
            email="banned@test.com",
            username="banned",
            password="password",
            password_confirmation="password",
        )
    )

    # Assert the BEFORE hook throws an exception and stops the login
    with pytest.raises(QulfException, match="This user is banned!"):
        await auth.sign_in("banned@test.com", "password")
