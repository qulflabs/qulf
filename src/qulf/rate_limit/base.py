from abc import ABC, abstractmethod

from pydantic import BaseModel


class RateLimitResult(BaseModel):
    """Structured result returned by any rate limiter in Qulf."""
    allowed: bool
    remaining: int
    reset_in: float


class BaseRateLimiter(ABC):
    """Abstract contract for a rate limiter in Qulf."""

    @abstractmethod
    async def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        """
        Consume a specific number of tokens for a given key.
        Returns a RateLimitResult containing allowed status and retry info.
        """
        pass  # pragma: no cover
