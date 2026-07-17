import asyncio
import time
from typing import Any

from qulf.rate_limit.base import BaseRateLimiter, RateLimitResult
from qulf.rate_limit.config import TokenBucketConfig




class BucketState:
    def __init__(self, capacity: int) -> None:
        self.tokens: float = float(capacity)
        self.last_refill: float = time.monotonic()
        self.lock = asyncio.Lock()


class InMemoryTokenBucket(BaseRateLimiter):
    # Notice the __init__ strictly takes the config model now!
    def __init__(self, config: TokenBucketConfig) -> None:
        self.config = config
        self._buckets: dict[str, BucketState] = {}
        self._global_lock = asyncio.Lock()

    def _prune(self, now: float) -> None:
        """
        Removes buckets that have been idle long enough to completely refill.
        This prevents an out-of-memory (OOM) leak from an unbounded dictionary.
        """
        full_refill_time = self.config.capacity / self.config.refill_rate
        
        for key in list(self._buckets.keys()):
            if (now - self._buckets[key].last_refill) >= full_refill_time:
                del self._buckets[key]

    async def _get_bucket(self, key: str) -> BucketState:
        async with self._global_lock:
            if len(self._buckets) >= self.config.max_memory_keys:
                self._prune(time.monotonic())
                
            if key not in self._buckets:
                self._buckets[key] = BucketState(self.config.capacity)
            return self._buckets[key]

    async def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        bucket = await self._get_bucket(key)
        async with bucket.lock:
            now = time.monotonic()
            elapsed = now - bucket.last_refill
            refill_amount = elapsed * self.config.refill_rate
            
            if refill_amount > 0:
                bucket.tokens = min(float(self.config.capacity), bucket.tokens + refill_amount)
                bucket.last_refill = now
                
            allowed = bucket.tokens >= tokens
            if allowed:
                bucket.tokens -= tokens
                
            remaining = int(bucket.tokens)
            reset_in = (
                max(0.0, (tokens - bucket.tokens) / self.config.refill_rate)
                if not allowed
                else 0.0
            )
            return RateLimitResult(
                allowed=allowed, remaining=remaining, reset_in=reset_in
            )

class RedisTokenBucket(BaseRateLimiter):
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
    
    local allowed = 0
    local reset_in = 0
    
    if tokens >= requested then
        tokens = tokens - requested
        allowed = 1
    else
        reset_in = (requested - tokens) / refill_rate
    end
    
    redis.call("HSET", key, "tokens", tokens, "last_refill", last_refill)
    redis.call("EXPIRE", key, math.ceil(capacity / refill_rate))
    
    -- THE FIX: Scale floats to integers by multiplying by 1000
    return {allowed, math.floor(tokens), math.ceil(reset_in * 1000)}
    """

    def __init__(self, redis_client: Any, config: TokenBucketConfig) -> None:
        self.redis = redis_client
        self.config = config
        self._script = self.redis.register_script(self.LUA_SCRIPT)

    async def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        redis_key = f"{self.config.key_prefix}{key}"
        now = time.time()
        
        result = await self._script(
            keys=[redis_key],
            args=[self.config.capacity, self.config.refill_rate, tokens, now]
        )
        
        # THE FIX: Divide the returned integer by 1000.0 to safely reconstruct the float!
        return RateLimitResult(
            allowed=bool(result[0]), 
            remaining=int(result[1]), 
            reset_in=float(result[2]) / 1000.0
        )