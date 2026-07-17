import asyncio
import collections
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class RateLimitResult:
    """
    Structured result returned by a sliding window rate limiter.

    Provides rich metadata to allow callers to construct informative
    HTTP 429 responses (e.g., Retry-After, X-RateLimit-Remaining headers).
    """

    allowed: bool
    remaining: int  # Requests remaining in the current window
    reset_in: float  # Seconds until the oldest request expires from the window


class BaseSlidingWindowLimiter(ABC):
    """
    Abstract contract for Sliding Window Log rate limiters in Qulf.

    Unlike the Token Bucket which manages a token supply, the Sliding Window
    Log tracks exact request timestamps to provide strict, burst-resistant
    rate enforcement for security-sensitive endpoints.
    """

    @abstractmethod
    async def consume(self, key: str) -> RateLimitResult:
        """
        Record a request attempt for the given key and evaluate it against
        the rolling time window.

        Args:
            key: The unique identifier to rate limit (e.g., IP address, user ID).

        Returns:
            A RateLimitResult with allowed status, remaining count, and reset_in time.
        """
        pass  # pragma: no cover



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


class WindowState:
    def __init__(self) -> None:
        self.timestamps: collections.deque[float] = collections.deque()
        self.lock = asyncio.Lock()


class InMemorySlidingWindowLog(BaseSlidingWindowLimiter):
    """
    An asynchronous, thread-safe, in-memory Sliding Window Log rate limiter.

    Stores exact request timestamps per key and evaluates each request against
    a rolling time window. Old timestamps are pruned on every request call to
    keep memory usage bounded.

    Suitable for single-process deployments. For multi-worker environments
    use RedisSlidingWindowLog.
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        """
        Initialize the Sliding Window Log.

        Args:
            max_requests: Maximum number of requests allowed in the window.
            window_seconds: Duration of the rolling window in seconds.
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: dict[str, WindowState] = {}
        self._global_lock = asyncio.Lock()

    async def _get_window(self, key: str) -> WindowState:
        async with self._global_lock:
            if key not in self._windows:
                self._windows[key] = WindowState()
            return self._windows[key]

    async def consume(self, key: str) -> RateLimitResult:
        window = await self._get_window(key)

        async with window.lock:
            now = time.time()
            cutoff = now - self.window_seconds

            # Prune expired timestamps from the left (oldest first)
            while window.timestamps and window.timestamps[0] <= cutoff:
                window.timestamps.popleft()

            current_count = len(window.timestamps)
            remaining = max(0, self.max_requests - current_count)

            if current_count < self.max_requests:
                window.timestamps.append(now)
                remaining -= 1
                # Time until the oldest request expires from the window
                reset_in = (
                    (window.timestamps[0] + self.window_seconds - now)
                    if window.timestamps
                    else self.window_seconds
                )
                return RateLimitResult(
                    allowed=True, remaining=remaining, reset_in=reset_in
                )

            # Blocked — report when the oldest timestamp will fall out
            oldest = window.timestamps[0]
            reset_in = oldest + self.window_seconds - now
            return RateLimitResult(
                allowed=False, remaining=0, reset_in=max(0.0, reset_in)
            )


class RedisSlidingWindowLog(BaseSlidingWindowLimiter):
    """
    An asynchronous, Redis-backed Sliding Window Log rate limiter.

    Uses a Redis Sorted Set (ZSET) to store request timestamps atomically.
    The Lua script guarantees race-condition immunity across distributed,
    multi-worker environments.
    """

    LUA_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local max_requests = tonumber(ARGV[3])
    local member = ARGV[4]
    local cutoff = now - window

    -- Remove expired timestamps
    redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)

    local current_count = redis.call("ZCARD", key)

    if current_count < max_requests then
        -- Add this request's timestamp
        redis.call("ZADD", key, now, member)
        -- Expire the key after the window duration to clean up idle keys
        redis.call("EXPIRE", key, math.ceil(window))

        local oldest_score = tonumber(redis.call("ZRANGE", key, 0, 0, "WITHSCORES")[2])
        local reset_in = (oldest_score ~= nil)
            and (oldest_score + window - now) or window
        local remaining = max_requests - current_count - 1

        -- Pack result: allowed=1, remaining, reset_in (as integer milliseconds)
        return {1, remaining, math.ceil(reset_in * 1000)}
    else
        local oldest_score = tonumber(redis.call("ZRANGE", key, 0, 0, "WITHSCORES")[2])
        local reset_in = (oldest_score ~= nil)
            and (oldest_score + window - now) or window

        return {0, 0, math.ceil(reset_in * 1000)}
    end
    """

    def __init__(
        self, redis_client: Any, max_requests: int, window_seconds: float
    ) -> None:
        """
        Initialize the Redis Sliding Window Log.

        Args:
            redis_client: An instance of `redis.asyncio.Redis`.
            max_requests: Maximum number of requests allowed in the window.
            window_seconds: Duration of the rolling window in seconds.
        """
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def consume(self, key: str) -> RateLimitResult:
        redis_key = f"qulf:swl:{key}"
        now = time.time()
        member = str(uuid.uuid4())

        result = await self.redis.eval(
            self.LUA_SCRIPT,
            1,
            redis_key,
            now,
            self.window_seconds,
            self.max_requests,
            member,
        )

        allowed = bool(result[0])
        remaining = int(result[1])
        reset_in = int(result[2]) / 1000.0  # Convert ms back to seconds

        return RateLimitResult(allowed=allowed, remaining=remaining, reset_in=reset_in)
