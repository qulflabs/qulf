import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any


class BaseRateLimiter(ABC):
    """
    Abstract contract for a rate limiter in Qulf.
    """

    @abstractmethod
    async def consume(self, key: str, tokens: int = 1) -> bool:
        """
        Consume a specific number of tokens for a given key.

        Args:
            key: The unique identifier to rate limit (e.g., IP address, user ID).
            tokens: The number of tokens to consume.

        Returns:
            True if the tokens were successfully consumed, False otherwise.
        """
        pass  # pragma: no cover


class BucketState:
    def __init__(self, capacity: int):
        self.tokens: float = float(capacity)
        self.last_refill: float = time.monotonic()
        self.lock = asyncio.Lock()


class InMemoryTokenBucket(BaseRateLimiter):
    """
    An asynchronous, thread-safe, in-memory implementation
    of the Token Bucket algorithm.

    This is suitable for single-process deployments. For multi-process
    deployments (e.g., multiple Uvicorn workers), a centralized rate limiter
    like Redis should be used.
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize the Token Bucket.

        Args:
            capacity: The maximum burst capacity of the bucket.
            refill_rate: The rate at which tokens are added to the bucket per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets: dict[str, BucketState] = {}
        self._global_lock = asyncio.Lock()

    async def _get_bucket(self, key: str) -> BucketState:
        async with self._global_lock:
            if key not in self._buckets:
                self._buckets[key] = BucketState(self.capacity)
            return self._buckets[key]

    async def consume(self, key: str, tokens: int = 1) -> bool:
        bucket = await self._get_bucket(key)

        async with bucket.lock:
            now = time.monotonic()
            elapsed = now - bucket.last_refill

            # Refill tokens based on elapsed time
            refill_amount = elapsed * self.refill_rate
            if refill_amount > 0:
                bucket.tokens = min(float(self.capacity), bucket.tokens + refill_amount)
                bucket.last_refill = now

            # Check if there are enough tokens
            if bucket.tokens >= tokens:
                bucket.tokens -= tokens
                return True

            return False


class RedisTokenBucket(BaseRateLimiter):
    """
    An asynchronous, Redis-backed implementation of the Token Bucket algorithm.

    This uses an atomic Lua script to evaluate the token limits, ensuring
    100% race-condition immunity in distributed, multi-worker environments.
    """

    LUA_SCRIPT = """
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])
    local requested = tonumber(ARGV[3])
    local now = tonumber(ARGV[4])

    local bucket = redis.call("HMGET", key, "tokens", "last_refill")
    local tokens = tonumber(bucket[1])
    local last_refill = tonumber(bucket[2])

    if tokens == nil then
        tokens = capacity
        last_refill = now
    end

    local elapsed = now - last_refill
    local refill_amount = elapsed * refill_rate
    if refill_amount > 0 then
        tokens = math.min(capacity, tokens + refill_amount)
        last_refill = now
    end

    local success = 0
    if tokens >= requested then
        tokens = tokens - requested
        success = 1
    end

    redis.call("HSET", key, "tokens", tokens, "last_refill", last_refill)
    -- Expire the key once it would have naturally fully refilled to save memory
    redis.call("EXPIRE", key, math.ceil(capacity / refill_rate))
    
    return success
    """

    def __init__(self, redis_client: "Any", capacity: int, refill_rate: float):
        """
        Initialize the Redis Token Bucket.

        Args:
            redis_client: An instance of `redis.asyncio.Redis`.
            capacity: The maximum burst capacity of the bucket.
            refill_rate: The rate at which tokens are added to the bucket per second.
        """
        self.redis = redis_client
        self.capacity = capacity
        self.refill_rate = refill_rate

    async def consume(self, key: str, tokens: int = 1) -> bool:
        redis_key = f"qulf:ratelimit:{key}"
        now = time.time()

        # eval returns an int (0 or 1) based on our Lua script
        result = await self.redis.eval(
            self.LUA_SCRIPT,
            1,
            redis_key,
            self.capacity,
            self.refill_rate,
            tokens,
            now,
        )
        return bool(result)
