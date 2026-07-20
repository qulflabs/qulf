from collections.abc import Sequence

from qulf.exceptions import RateLimitExceededError
from qulf.plugins.base import QulfPlugin
from qulf.rate_limit.base import BaseRateLimiter


class RateLimitPlugin(QulfPlugin):
    name = "rate_limit"

    def __init__(self, limiter: BaseRateLimiter, protect_sign_in: bool = True):
        self.limiter = limiter
        self.protect_sign_in = protect_sign_in

    async def enforce(
        self, action: str, identifier: str | Sequence[str | None], tokens: int = 1
    ) -> None:
        """
        Generic method developers can call in ANY route to enforce rate limits.
        Accepts a string or a list of strings
        to create composite keys (e.g. ['ip', 'email']).
        """
        if isinstance(identifier, (list, tuple)):
            id_str = ":".join(i for i in identifier if i)
        else:
            id_str = identifier

        key = f"{action}:{id_str}"
        result = await self.limiter.consume(key, tokens=tokens)

        if not result.allowed:
            raise RateLimitExceededError(
                message=f"Rate limit exceeded for action: {action}",
                retry_after=int(result.reset_in),
            )

    async def before_sign_in(self, email: str, ip_address: str | None = None) -> None:
        """Out-of-the-box protection for the sign-in route."""
        if not self.protect_sign_in:
            return

        # Creates a composite lock if IP present
        # otherwise locks the email
        target = [ip_address, email] if ip_address else email
        await self.enforce("signin", target)
