import asyncio
import collections
import time
import uuid
from typing import Any

from qulf.rate_limit import BaseRateLimiter, RateLimitResult, SlidingWindowConfig


class WindowState:
    def __init__(self) -> None:
        self.timestamps: collections.deque[float] = collections.deque()
        self.lock = asyncio.Lock()


class InMemorySlidingWindowLog(BaseRateLimiter):
    def __init__(self, config: SlidingWindowConfig) -> None:
        self.config = config
        self._windows: dict[str, WindowState] = {}
        self._global_lock = asyncio.Lock()

    def _prune(self, now: float) -> None:
        """
        Removes windows that are completely outside the sliding timeframe.
        """
        for key in list(self._windows.keys()):
            window = self._windows[key]
            # If the deque is empty OR the most
            # recent request is older than the window size
            if (
                not window.timestamps
                or (now - window.timestamps[-1]) >= self.config.window_seconds
            ):
                del self._windows[key]

    async def _get_window(self, key: str) -> WindowState:
        async with self._global_lock:
            # Trigger pruning if we hit our max memory limit!
            if len(self._windows) >= self.config.max_memory_keys:
                self._prune(time.time())

            if key not in self._windows:
                self._windows[key] = WindowState()
            return self._windows[key]

    async def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        window = await self._get_window(key)

        async with window.lock:
            now = time.time()
            cutoff = now - self.config.window_seconds

            while window.timestamps and window.timestamps[0] <= cutoff:
                window.timestamps.popleft()

            current_count = len(window.timestamps)
            remaining = max(0, self.config.max_requests - current_count)

            if current_count < self.config.max_requests:
                window.timestamps.append(now)
                remaining -= 1
                reset_in = window.timestamps[0] + self.config.window_seconds - now

                return RateLimitResult(
                    allowed=True, remaining=remaining, reset_in=reset_in
                )

            oldest = window.timestamps[0]
            reset_in = oldest + self.config.window_seconds - now
            return RateLimitResult(
                allowed=False, remaining=0, reset_in=max(0.0, reset_in)
            )


class RedisSlidingWindowLog(BaseRateLimiter):
    LUA_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local max_requests = tonumber(ARGV[3])
    local member = ARGV[4]
    local cutoff = now - window

    -- Remove elements outside the current window
    redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)
    local current_count = redis.call("ZCARD", key)

    local allowed = 0
    local remaining = 0

    if current_count < max_requests then
        redis.call("ZADD", key, now, member)
        redis.call("EXPIRE", key, math.ceil(window))
        allowed = 1
        remaining = max_requests - current_count - 1
    end

    local oldest_score_data = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
    local reset_in = window

    if oldest_score_data[2] ~= nil then
        local oldest_score = tonumber(oldest_score_data[2])
        reset_in = oldest_score + window - now
    end

    -- Preemptively applying the * 1000 multiplier trick for safe float parsing
    return {allowed, remaining, math.ceil(reset_in * 1000)}
    """

    def __init__(self, redis_client: Any, config: SlidingWindowConfig) -> None:
        self.redis = redis_client
        self.config = config
        self._script = self.redis.register_script(self.LUA_SCRIPT)

    async def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        redis_key = f"{self.config.key_prefix}{key}"
        now = time.time()
        member = str(uuid.uuid4())

        result = await self._script(
            keys=[redis_key],
            args=[now, self.config.window_seconds, self.config.max_requests, member],
        )

        return RateLimitResult(
            allowed=bool(result[0]),
            remaining=int(result[1]),
            reset_in=float(result[2]) / 1000.0,
        )
