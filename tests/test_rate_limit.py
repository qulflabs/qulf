import asyncio
from typing import Any

import pytest
import pytest_asyncio

from qulf.rate_limit import (
    InMemorySlidingWindowLog,
    InMemoryTokenBucket,
    RateLimitResult,
)


@pytest.mark.asyncio
async def test_token_bucket_initial_capacity() -> None:
    bucket = InMemoryTokenBucket(capacity=5, refill_rate=1.0)

    # Should be able to consume 5 tokens immediately
    for _ in range(5):
        assert await bucket.consume("test_user_1") is True

    # The 6th should fail
    assert await bucket.consume("test_user_1") is False


@pytest.mark.asyncio
async def test_token_bucket_multiple_keys() -> None:
    bucket = InMemoryTokenBucket(capacity=2, refill_rate=1.0)

    assert await bucket.consume("user_a") is True
    assert await bucket.consume("user_a") is True
    assert await bucket.consume("user_a") is False

    # Another user should have their own isolated bucket
    assert await bucket.consume("user_b") is True
    assert await bucket.consume("user_b") is True
    assert await bucket.consume("user_b") is False


@pytest.mark.asyncio
async def test_token_bucket_refill() -> None:
    # Small capacity, fast refill
    # 10 tokens per second = 1 token every 0.1s
    bucket = InMemoryTokenBucket(capacity=2, refill_rate=10.0)

    assert await bucket.consume("user_c", tokens=2) is True
    assert await bucket.consume("user_c") is False

    # Wait for 0.15 seconds to guarantee 1 token is refilled
    await asyncio.sleep(0.15)

    # Should have 1 token refilled
    assert await bucket.consume("user_c", tokens=1) is True
    assert await bucket.consume("user_c", tokens=1) is False


@pytest.mark.asyncio
async def test_token_bucket_concurrency() -> None:
    bucket = InMemoryTokenBucket(capacity=50, refill_rate=1.0)
    key = "concurrent_user"

    async def try_consume() -> bool:
        return await bucket.consume(key)

    # Launch 100 simultaneous consume requests
    results = await asyncio.gather(*(try_consume() for _ in range(100)))

    # Exactly 50 should succeed, and 50 should fail, despite concurrency
    successes = sum(1 for result in results if result)
    assert successes == 50


@pytest_asyncio.fixture
async def fake_redis():
    from fakeredis.aioredis import FakeRedis

    client = FakeRedis()
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_redis_token_bucket_initial_capacity(fake_redis: "Any") -> None:
    from qulf.rate_limit import RedisTokenBucket

    bucket = RedisTokenBucket(fake_redis, capacity=5, refill_rate=1.0)

    for _ in range(5):
        assert await bucket.consume("test_redis_1") is True

    assert await bucket.consume("test_redis_1") is False


@pytest.mark.asyncio
async def test_redis_token_bucket_refill(fake_redis: "Any") -> None:
    from qulf.rate_limit import RedisTokenBucket

    bucket = RedisTokenBucket(fake_redis, capacity=2, refill_rate=10.0)

    assert await bucket.consume("user_redis", tokens=2) is True
    assert await bucket.consume("user_redis") is False

    # Wait for enough time to guarantee 1 token
    await asyncio.sleep(0.15)

    assert await bucket.consume("user_redis", tokens=1) is True
    assert await bucket.consume("user_redis", tokens=1) is False


@pytest.mark.asyncio
async def test_redis_token_bucket_concurrency(fake_redis: "Any") -> None:
    from qulf.rate_limit import RedisTokenBucket

    bucket = RedisTokenBucket(fake_redis, capacity=50, refill_rate=1.0)
    key = "concurrent_redis_user"

    async def try_consume() -> bool:
        return await bucket.consume(key)

    results = await asyncio.gather(*(try_consume() for _ in range(100)))

    successes = sum(1 for result in results if result)
    assert successes == 50


@pytest.mark.asyncio
async def test_sliding_window_allows_up_to_limit() -> None:
    limiter = InMemorySlidingWindowLog(max_requests=3, window_seconds=10.0)

    for _ in range(3):
        result = await limiter.consume("user_swl_1")
        assert result.allowed is True


@pytest.mark.asyncio
async def test_sliding_window_blocks_at_limit() -> None:
    limiter = InMemorySlidingWindowLog(max_requests=3, window_seconds=10.0)

    for _ in range(3):
        await limiter.consume("user_swl_2")

    result = await limiter.consume("user_swl_2")
    assert result.allowed is False
    assert result.remaining == 0
    assert result.reset_in > 0


@pytest.mark.asyncio
async def test_sliding_window_returns_correct_remaining() -> None:
    limiter = InMemorySlidingWindowLog(max_requests=5, window_seconds=10.0)

    result = await limiter.consume("user_swl_3")
    assert result.allowed is True
    assert result.remaining == 4

    result = await limiter.consume("user_swl_3")
    assert result.allowed is True
    assert result.remaining == 3


@pytest.mark.asyncio
async def test_sliding_window_multiple_keys_isolated() -> None:
    limiter = InMemorySlidingWindowLog(max_requests=2, window_seconds=10.0)

    await limiter.consume("user_a_swl")
    await limiter.consume("user_a_swl")
    blocked = await limiter.consume("user_a_swl")
    assert blocked.allowed is False

    # user_b should have a fresh independent window
    result = await limiter.consume("user_b_swl")
    assert result.allowed is True


@pytest.mark.asyncio
async def test_sliding_window_resets_after_window_expires() -> None:
    # 2 requests in a 0.2-second window
    limiter = InMemorySlidingWindowLog(max_requests=2, window_seconds=0.2)

    await limiter.consume("user_swl_exp")
    await limiter.consume("user_swl_exp")
    blocked = await limiter.consume("user_swl_exp")
    assert blocked.allowed is False

    # After the window expires, requests should be allowed again
    await asyncio.sleep(0.25)

    result = await limiter.consume("user_swl_exp")
    assert result.allowed is True


@pytest.mark.asyncio
async def test_sliding_window_result_is_dataclass() -> None:
    limiter = InMemorySlidingWindowLog(max_requests=5, window_seconds=10.0)
    result = await limiter.consume("user_swl_type")
    assert isinstance(result, RateLimitResult)
    assert isinstance(result.allowed, bool)
    assert isinstance(result.remaining, int)
    assert isinstance(result.reset_in, float)


@pytest.mark.asyncio
async def test_sliding_window_concurrency() -> None:
    limiter = InMemorySlidingWindowLog(max_requests=50, window_seconds=60.0)
    key = "concurrent_swl_user"

    async def try_consume() -> bool:
        result = await limiter.consume(key)
        return result.allowed

    results = await asyncio.gather(*(try_consume() for _ in range(100)))

    successes = sum(1 for r in results if r)
    assert successes == 50


# ---------------------------------------------------------------------------
# RedisSlidingWindowLog tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_sliding_window_allows_up_to_limit(fake_redis: Any) -> None:
    from qulf.rate_limit import RedisSlidingWindowLog

    limiter = RedisSlidingWindowLog(fake_redis, max_requests=3, window_seconds=10.0)

    for _ in range(3):
        result = await limiter.consume("redis_swl_1")
        assert result.allowed is True


@pytest.mark.asyncio
async def test_redis_sliding_window_blocks_at_limit(fake_redis: Any) -> None:
    from qulf.rate_limit import RedisSlidingWindowLog

    limiter = RedisSlidingWindowLog(fake_redis, max_requests=3, window_seconds=10.0)

    for _ in range(3):
        await limiter.consume("redis_swl_2")

    result = await limiter.consume("redis_swl_2")
    assert result.allowed is False
    assert result.remaining == 0
    assert result.reset_in > 0


@pytest.mark.asyncio
async def test_redis_sliding_window_returns_correct_remaining(fake_redis: Any) -> None:
    from qulf.rate_limit import RedisSlidingWindowLog

    limiter = RedisSlidingWindowLog(fake_redis, max_requests=5, window_seconds=10.0)

    result = await limiter.consume("redis_swl_3")
    assert result.allowed is True
    assert result.remaining == 4

    result = await limiter.consume("redis_swl_3")
    assert result.allowed is True
    assert result.remaining == 3


@pytest.mark.asyncio
async def test_redis_sliding_window_resets_after_expiry(fake_redis: Any) -> None:
    from qulf.rate_limit import RedisSlidingWindowLog

    limiter = RedisSlidingWindowLog(fake_redis, max_requests=2, window_seconds=0.2)

    await limiter.consume("redis_swl_exp")
    await limiter.consume("redis_swl_exp")
    blocked = await limiter.consume("redis_swl_exp")
    assert blocked.allowed is False

    await asyncio.sleep(0.25)

    result = await limiter.consume("redis_swl_exp")
    assert result.allowed is True


@pytest.mark.asyncio
async def test_redis_sliding_window_concurrency(fake_redis: Any) -> None:
    from qulf.rate_limit import RedisSlidingWindowLog

    limiter = RedisSlidingWindowLog(fake_redis, max_requests=50, window_seconds=60.0)
    key = "concurrent_redis_swl"

    async def try_consume() -> bool:
        result = await limiter.consume(key)
        return result.allowed

    results = await asyncio.gather(*(try_consume() for _ in range(100)))

    successes = sum(1 for r in results if r)
    assert successes == 50
