import asyncio
import time
from typing import Any

from qulf.rate_limit import BaseRateLimiter, FixedWindowConfig, RateLimitResult


class WindowData:
    def __init__(self, window_start: float) -> None:
        self.window_start = window_start
        self.count = 0
        self.lock = asyncio.Lock()


class InMemoryFixedWindow(BaseRateLimiter):
    def __init__(self, config: FixedWindowConfig) -> None:
        self.config = config
        self._windows: dict[str, WindowData] = {}
        self._global_lock = asyncio.Lock()

    def _prune(self, current_window_start: float) -> None:
        for key in list(self._windows.keys()):
            if self._windows[key].window_start < current_window_start:
                del self._windows[key]

    async def _get_window(self, key: str, current_window_start: float) -> WindowData:
        async with self._global_lock:
            if len(self._windows) >= self.config.max_memory_keys:
                self._prune(current_window_start)

            if (
                key not in self._windows
                or self._windows[key].window_start != current_window_start
            ):
                self._windows[key] = WindowData(current_window_start)
            return self._windows[key]

    async def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        now = time.time()
        window_start = (now // self.config.window_seconds) * self.config.window_seconds

        window = await self._get_window(key, window_start)

        async with window.lock:
            allowed = (window.count + tokens) <= self.config.max_requests
            if allowed:
                window.count += tokens

            reset_in = (window_start + self.config.window_seconds) - now
            remaining = max(0, self.config.max_requests - window.count)

            return RateLimitResult(
                allowed=allowed, remaining=remaining, reset_in=max(0.0, reset_in)
            )


class RedisFixedWindow(BaseRateLimiter):
    LUA_SCRIPT = """
    local key = KEYS[1]
    local max_requests = tonumber(ARGV[1])
    local window_seconds = tonumber(ARGV[2])
    local tokens = tonumber(ARGV[3])
    
    local current_count = redis.call("GET", key)
    if current_count == false then
        current_count = 0
    else
        current_count = tonumber(current_count)
    end
    
    local allowed = 0
    local remaining = 0
    local new_count = current_count + tokens
    
    if new_count <= max_requests then
        redis.call("INCRBY", key, tokens)
        if current_count == 0 then
            redis.call("EXPIRE", key, window_seconds)
        end
        allowed = 1
        remaining = max_requests - new_count
    end
    
    local ttl = redis.call("TTL", key)
    if ttl < 0 then
        ttl = window_seconds
    end
    
    -- Using the * 1000 trick to safely return the TTL float
    return {allowed, remaining, ttl * 1000}
    """

    def __init__(self, redis_client: Any, config: FixedWindowConfig) -> None:
        self.redis = redis_client
        self.config = config
        self._script = self.redis.register_script(self.LUA_SCRIPT)

    async def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        now = time.time()
        window_start = int(
            (now // self.config.window_seconds) * self.config.window_seconds
        )

        redis_key = f"{self.config.key_prefix}{key}:{window_start}"

        result = await self._script(
            keys=[redis_key],
            args=[self.config.max_requests, self.config.window_seconds, tokens],
        )

        allowed, remaining, reset_in = result
        return RateLimitResult(
            allowed=bool(allowed), remaining=remaining, reset_in=reset_in / 1000.0
        )
