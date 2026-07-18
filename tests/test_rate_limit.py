import asyncio
from typing import Any

import pytest
import pytest_asyncio
from pydantic import ValidationError

from qulf.exceptions import RateLimitExceededError
from qulf.plugins import RateLimitPlugin
from qulf.rate_limit import (
    FixedWindowConfig,
    InMemoryFixedWindow,
    InMemorySlidingWindowLog,
    InMemoryTokenBucket,
    RedisFixedWindow,
    RedisSlidingWindowLog,
    RedisTokenBucket,
    SlidingWindowConfig,
    TokenBucketConfig,
)


@pytest.mark.asyncio
async def test_rate_limit_plugin_enforce():
    # Setup a limiter that allows 2 requests per 10 seconds
    limiter = InMemoryFixedWindow(FixedWindowConfig(max_requests=2, window_seconds=10))
    plugin = RateLimitPlugin(limiter=limiter)

    # 1. Enforce with a standard string identifier
    await plugin.enforce("test_action", "user1")

    # 2. Enforce with a list identifier (include None to test the `if i` filter)
    await plugin.enforce("test_action", ["127.0.0.1", None, "user2"])

    # 3. Exhaust the limiter to trigger RateLimitExceededError
    await plugin.enforce("test_action", "exhausted_user")
    await plugin.enforce("test_action", "exhausted_user")

    with pytest.raises(RateLimitExceededError) as exc_info:
        await plugin.enforce("test_action", "exhausted_user")

    assert "Rate limit exceeded for action: test_action" in str(exc_info.value)
    assert exc_info.value.retry_after >= 0


@pytest.mark.asyncio
async def test_rate_limit_plugin_before_sign_in():
    limiter = InMemoryFixedWindow(FixedWindowConfig(max_requests=5, window_seconds=10))

    # 1. Protect sign in DISABLED
    plugin_disabled = RateLimitPlugin(limiter=limiter, protect_sign_in=False)
    await plugin_disabled.before_sign_in(email="test@test.com")
    # Because it returns early, the limiter should not have consumed any keys
    assert not limiter._windows

    # 2. Protect sign in ENABLED (Without IP)
    plugin = RateLimitPlugin(limiter=limiter, protect_sign_in=True)
    await plugin.before_sign_in(email="test2@test.com")
    # Limiter key should be formatted as action:email
    assert "signin:test2@test.com" in limiter._windows

    # 3. Protect sign in ENABLED (With IP)
    await plugin.before_sign_in(email="test3@test.com", ip_address="192.168.1.1")
    # Limiter key should be formatted as action:ip:email
    assert "signin:192.168.1.1:test3@test.com" in limiter._windows


# Configuration Tests
def test_token_bucket_config_validation() -> None:
    # Valid config
    config = TokenBucketConfig(capacity=10, refill_rate=2.5, max_memory_keys=100)
    assert config.capacity == 10

    # Invalid config
    with pytest.raises(ValidationError):
        TokenBucketConfig(capacity=-5, refill_rate=1.0)  # capacity must be > 0


# In-Memory Token Bucket Tests


@pytest.mark.asyncio
async def test_in_memory_tb_basic_and_reset_math() -> None:
    config = TokenBucketConfig(capacity=3, refill_rate=1.0)
    bucket = InMemoryTokenBucket(config)

    res1 = await bucket.consume("user_1")
    assert res1.allowed is True
    assert res1.remaining == 2
    assert res1.reset_in == 0.0

    await bucket.consume("user_1")
    res3 = await bucket.consume("user_1")
    assert res3.allowed is True
    assert res3.remaining == 0

    # Bucket is empty, should reject and calculate exact reset_in
    res4 = await bucket.consume("user_1")
    assert res4.allowed is False
    assert res4.remaining == 0
    # Needs 1 token, refill rate is 1.0/sec, so reset_in should be ~1.0
    assert 0.9 < res4.reset_in <= 1.0


@pytest.mark.asyncio
async def test_in_memory_tb_refill_simulation() -> None:
    # Refills 10 tokens/sec (0.1s per token)
    config = TokenBucketConfig(capacity=5, refill_rate=10.0)
    bucket = InMemoryTokenBucket(config)

    # Drain completely
    for _ in range(5):
        await bucket.consume("fast_user")

    assert (await bucket.consume("fast_user")).allowed is False

    # Manually hack the internal state to simulate time passing (0.2 seconds)
    # This avoids using flaky time.sleep() in async tests!
    state = bucket._buckets["fast_user"]
    state.last_refill -= 0.25

    # 0.25 seconds * 10 tokens/sec = 2.5 tokens refilled. Floor is 2.
    res = await bucket.consume("fast_user", tokens=2)
    assert res.allowed is True
    assert res.remaining == 0


@pytest.mark.asyncio
async def test_in_memory_tb_prune_memory_leak_fix() -> None:
    # Max keys is 2. full_refill_time = 10.0 / 1.0 = 10 seconds.
    config = TokenBucketConfig(capacity=10, refill_rate=1.0, max_memory_keys=2)
    bucket = InMemoryTokenBucket(config)

    await bucket.consume("key_1")
    await bucket.consume("key_2")

    # Manually age key_1 past the full_refill_time (10+ seconds)
    bucket._buckets["key_1"].last_refill -= 15.0
    # Age key_2 just a little bit (should NOT be pruned)
    bucket._buckets["key_2"].last_refill -= 2.0

    # Hitting key_3 will trigger the prune because len(_buckets) >= 2
    await bucket.consume("key_3")

    assert "key_1" not in bucket._buckets  # Pruned! Memory saved!
    assert "key_2" in bucket._buckets  # Kept! Still partially active.
    assert "key_3" in bucket._buckets  # Added!


@pytest.mark.asyncio
async def test_in_memory_tb_concurrency() -> None:
    config = TokenBucketConfig(capacity=50, refill_rate=0.1)
    bucket = InMemoryTokenBucket(config)

    async def try_consume() -> bool:
        return (await bucket.consume("concurrent_user")).allowed

    results = await asyncio.gather(*(try_consume() for _ in range(100)))
    successes = sum(1 for r in results if r)
    assert successes == 50


# Redis Token Bucket Tests
@pytest_asyncio.fixture
async def fake_redis() -> Any:
    from fakeredis.aioredis import FakeRedis

    client = FakeRedis()
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_redis_tb_basic(fake_redis: Any) -> None:
    config = TokenBucketConfig(capacity=5, refill_rate=1.0, key_prefix="test:tb:")
    bucket = RedisTokenBucket(fake_redis, config)

    for _ in range(5):
        assert (await bucket.consume("redis_user")).allowed is True

    res = await bucket.consume("redis_user")
    assert res.allowed is False
    assert res.remaining == 0
    assert 0.9 < res.reset_in <= 1.0


@pytest.mark.asyncio
async def test_redis_tb_concurrency(fake_redis: Any) -> None:
    config = TokenBucketConfig(capacity=50, refill_rate=0.01, key_prefix="test:tb:")
    bucket = RedisTokenBucket(fake_redis, config)

    async def try_consume() -> bool:
        return (await bucket.consume("concurrent_redis")).allowed

    results = await asyncio.gather(*(try_consume() for _ in range(100)))
    assert sum(1 for r in results if r) == 50


def test_sliding_window_config_validation() -> None:
    config = SlidingWindowConfig(max_requests=10, window_seconds=60.0)
    assert config.max_requests == 10

    with pytest.raises(ValidationError):
        SlidingWindowConfig(max_requests=0, window_seconds=10.0)


# In-Memory Sliding Window Tests
@pytest.mark.asyncio
async def test_in_memory_swl_basic() -> None:
    config = SlidingWindowConfig(max_requests=3, window_seconds=1.0)
    limiter = InMemorySlidingWindowLog(config)

    # Send 3 allowed requests
    for expected_remaining in [2, 1, 0]:
        res = await limiter.consume("swl_user")
        assert res.allowed is True
        assert res.remaining == expected_remaining

    # 4th request should be rejected
    res_reject = await limiter.consume("swl_user")
    assert res_reject.allowed is False
    assert res_reject.remaining == 0
    assert res_reject.reset_in > 0.0


@pytest.mark.asyncio
async def test_in_memory_swl_pruning() -> None:
    config = SlidingWindowConfig(max_requests=5, window_seconds=1.0, max_memory_keys=2)
    limiter = InMemorySlidingWindowLog(config)

    await limiter.consume("user1")
    await limiter.consume("user2")

    # Hack time backward for user1 so it expires completely
    limiter._windows["user1"].timestamps[0] -= 5.0

    # Trigger prune by adding a 3rd key
    await limiter.consume("user3")

    assert "user1" not in limiter._windows  # Successfully pruned!
    assert "user2" in limiter._windows
    assert "user3" in limiter._windows


@pytest.mark.asyncio
async def test_in_memory_swl_popleft() -> None:
    config = SlidingWindowConfig(max_requests=5, window_seconds=2.0)
    limiter = InMemorySlidingWindowLog(config)

    # 1. Add a normal request
    await limiter.consume("pop_user")

    # 2. Hack the timestamp so it falls completely outside the 2.0s sliding window
    limiter._windows["pop_user"].timestamps[0] -= 5.0

    # 3. Call consume again.
    # Because we haven't hit max_memory_keys, _prune is NOT triggered.
    # Instead, consume() evaluates the cutoff and calls `window.timestamps.popleft()`!
    res = await limiter.consume("pop_user")

    assert res.allowed is True
    # The old timestamp was popped, leaving only the newly added one.
    assert len(limiter._windows["pop_user"].timestamps) == 1


@pytest.mark.asyncio
async def test_in_memory_swl_concurrency() -> None:
    config = SlidingWindowConfig(max_requests=50, window_seconds=10.0)
    limiter = InMemorySlidingWindowLog(config)

    async def try_consume() -> bool:
        return (await limiter.consume("swl_concurrent")).allowed

    results = await asyncio.gather(*(try_consume() for _ in range(100)))
    assert sum(1 for r in results if r) == 50


# Redis Sliding Window Tests
@pytest.mark.asyncio
async def test_redis_swl_basic(fake_redis: Any) -> None:
    config = SlidingWindowConfig(max_requests=2, window_seconds=5.0)
    limiter = RedisSlidingWindowLog(fake_redis, config)

    assert (await limiter.consume("redis_swl")).allowed is True
    assert (await limiter.consume("redis_swl")).allowed is True

    reject = await limiter.consume("redis_swl")
    assert reject.allowed is False
    assert reject.reset_in > 0


@pytest.mark.asyncio
async def test_redis_swl_concurrency(fake_redis: Any) -> None:
    config = SlidingWindowConfig(max_requests=50, window_seconds=10.0)
    limiter = RedisSlidingWindowLog(fake_redis, config)

    async def try_consume() -> bool:
        return (await limiter.consume("redis_swl_conc")).allowed

    results = await asyncio.gather(*(try_consume() for _ in range(100)))
    assert sum(1 for r in results if r) == 50


# Fixed Window Configuration Tests
def test_fixed_window_config_validation() -> None:
    config = FixedWindowConfig(max_requests=100, window_seconds=60)
    assert config.max_requests == 100

    with pytest.raises(ValidationError):
        FixedWindowConfig(max_requests=-1, window_seconds=60)


# In-Memory Fixed Window Tests
@pytest.mark.asyncio
async def test_in_memory_fw_basic() -> None:
    config = FixedWindowConfig(max_requests=2, window_seconds=5)
    limiter = InMemoryFixedWindow(config)

    assert (await limiter.consume("fw_user")).allowed is True
    assert (await limiter.consume("fw_user")).allowed is True

    reject = await limiter.consume("fw_user")
    assert reject.allowed is False
    assert reject.remaining == 0


@pytest.mark.asyncio
async def test_in_memory_fw_pruning() -> None:
    config = FixedWindowConfig(max_requests=5, window_seconds=10, max_memory_keys=2)
    limiter = InMemoryFixedWindow(config)

    # Fake window starts to simulate passage of time
    await limiter._get_window("user1", 1000.0)
    await limiter._get_window("user2", 1000.0)

    # Hitting max memory triggers prune for the new current window start (2000.0)
    await limiter._get_window("user3", 2000.0)

    assert "user1" not in limiter._windows
    assert "user2" not in limiter._windows
    assert "user3" in limiter._windows


# Redis Fixed Window Tests
@pytest.mark.asyncio
async def test_redis_fw_basic(fake_redis: Any) -> None:
    config = FixedWindowConfig(max_requests=3, window_seconds=10)
    limiter = RedisFixedWindow(fake_redis, config)

    for expected_rem in [2, 1, 0]:
        res = await limiter.consume("redis_fw")
        assert res.allowed is True
        assert res.remaining == expected_rem

    res_reject = await limiter.consume("redis_fw")
    assert res_reject.allowed is False
    assert res_reject.reset_in > 0
