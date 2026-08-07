import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fakeredis.aioredis import FakeRedis
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


@pytest_asyncio.fixture
async def fake_redis() -> AsyncGenerator[FakeRedis, None]:
    client = FakeRedis()
    yield client
    await client.aclose()


@pytest.mark.asyncio
class TestRateLimitPlugin:
    async def test_rate_limit_plugin_enforce(self) -> None:
        limiter = InMemoryFixedWindow(
            FixedWindowConfig(max_requests=2, window_seconds=10)
        )
        plugin = RateLimitPlugin(limiter=limiter)

        await plugin.enforce("test_action", "user1")
        await plugin.enforce("test_action", ["127.0.0.1", None, "user2"])

        await plugin.enforce("test_action", "exhausted_user")
        await plugin.enforce("test_action", "exhausted_user")

        with pytest.raises(RateLimitExceededError) as exc_info:
            await plugin.enforce("test_action", "exhausted_user")

        assert "Rate limit exceeded for action: test_action" in str(exc_info.value)
        assert exc_info.value.retry_after >= 0

    async def test_rate_limit_plugin_before_sign_in(self) -> None:
        limiter = InMemoryFixedWindow(
            FixedWindowConfig(max_requests=5, window_seconds=10)
        )

        plugin_disabled = RateLimitPlugin(limiter=limiter, protect_sign_in=False)
        await plugin_disabled.before_sign_in(email="test@test.com")
        assert not limiter._windows

        plugin = RateLimitPlugin(limiter=limiter, protect_sign_in=True)
        await plugin.before_sign_in(email="test2@test.com")
        assert "signin:test2@test.com" in limiter._windows

        await plugin.before_sign_in(email="test3@test.com", ip_address="192.168.1.1")
        assert "signin:192.168.1.1:test3@test.com" in limiter._windows


class TestRateLimitConfigs:
    def test_token_bucket_config_validation(self) -> None:
        config = TokenBucketConfig(capacity=10, refill_rate=2.5, max_memory_keys=100)
        assert config.capacity == 10

        with pytest.raises(ValidationError):
            TokenBucketConfig(capacity=-5, refill_rate=1.0)

    def test_sliding_window_config_validation(self) -> None:
        config = SlidingWindowConfig(max_requests=10, window_seconds=60.0)
        assert config.max_requests == 10

        with pytest.raises(ValidationError):
            SlidingWindowConfig(max_requests=0, window_seconds=10.0)

    def test_fixed_window_config_validation(self) -> None:
        config = FixedWindowConfig(max_requests=100, window_seconds=60)
        assert config.max_requests == 100

        with pytest.raises(ValidationError):
            FixedWindowConfig(max_requests=-1, window_seconds=60)


@pytest.mark.asyncio
class TestInMemoryTokenBucket:
    async def test_in_memory_tb_basic_and_reset_math(self) -> None:
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

        res4 = await bucket.consume("user_1")
        assert res4.allowed is False
        assert res4.remaining == 0
        assert 0.9 < res4.reset_in <= 1.0

    async def test_in_memory_tb_refill_simulation(self) -> None:
        config = TokenBucketConfig(capacity=5, refill_rate=10.0)
        bucket = InMemoryTokenBucket(config)

        for _ in range(5):
            await bucket.consume("fast_user")

        assert (await bucket.consume("fast_user")).allowed is False

        state = bucket._buckets["fast_user"]
        state.last_refill -= 0.25

        res = await bucket.consume("fast_user", tokens=2)
        assert res.allowed is True
        assert res.remaining == 0

    async def test_in_memory_tb_prune_memory_leak_fix(self) -> None:
        config = TokenBucketConfig(capacity=10, refill_rate=1.0, max_memory_keys=2)
        bucket = InMemoryTokenBucket(config)

        await bucket.consume("key_1")
        await bucket.consume("key_2")

        bucket._buckets["key_1"].last_refill -= 15.0
        bucket._buckets["key_2"].last_refill -= 2.0

        await bucket.consume("key_3")

        assert "key_1" not in bucket._buckets
        assert "key_2" in bucket._buckets
        assert "key_3" in bucket._buckets

    async def test_in_memory_tb_concurrency(self) -> None:
        config = TokenBucketConfig(capacity=50, refill_rate=0.1)
        bucket = InMemoryTokenBucket(config)

        async def try_consume() -> bool:
            return (await bucket.consume("concurrent_user")).allowed

        results = await asyncio.gather(*(try_consume() for _ in range(100)))
        successes = sum(1 for r in results if r)
        assert successes == 50


@pytest.mark.asyncio
class TestRedisTokenBucket:
    async def test_redis_tb_basic(self, fake_redis: FakeRedis) -> None:
        config = TokenBucketConfig(capacity=5, refill_rate=1.0, key_prefix="test:tb:")
        bucket = RedisTokenBucket(fake_redis, config)

        for _ in range(5):
            assert (await bucket.consume("redis_user")).allowed is True

        res = await bucket.consume("redis_user")
        assert res.allowed is False
        assert res.remaining == 0
        assert 0.5 < res.reset_in <= 1.0

    async def test_redis_tb_concurrency(self, fake_redis: FakeRedis) -> None:
        config = TokenBucketConfig(capacity=50, refill_rate=0.01, key_prefix="test:tb:")
        bucket = RedisTokenBucket(fake_redis, config)

        async def try_consume() -> bool:
            return (await bucket.consume("concurrent_redis")).allowed

        results = await asyncio.gather(*(try_consume() for _ in range(100)))
        assert sum(1 for r in results if r) == 50


@pytest.mark.asyncio
class TestInMemorySlidingWindow:
    async def test_in_memory_swl_basic(self) -> None:
        config = SlidingWindowConfig(max_requests=3, window_seconds=1.0)
        limiter = InMemorySlidingWindowLog(config)

        for expected_remaining in [2, 1, 0]:
            res = await limiter.consume("swl_user")
            assert res.allowed is True
            assert res.remaining == expected_remaining

        res_reject = await limiter.consume("swl_user")
        assert res_reject.allowed is False
        assert res_reject.remaining == 0
        assert res_reject.reset_in > 0.0

    async def test_in_memory_swl_pruning(self) -> None:
        config = SlidingWindowConfig(
            max_requests=5, window_seconds=1.0, max_memory_keys=2
        )
        limiter = InMemorySlidingWindowLog(config)

        await limiter.consume("user1")
        await limiter.consume("user2")

        limiter._windows["user1"].timestamps[0] -= 5.0

        await limiter.consume("user3")

        assert "user1" not in limiter._windows
        assert "user2" in limiter._windows
        assert "user3" in limiter._windows

    async def test_in_memory_swl_popleft(self) -> None:
        config = SlidingWindowConfig(max_requests=5, window_seconds=2.0)
        limiter = InMemorySlidingWindowLog(config)

        await limiter.consume("pop_user")

        limiter._windows["pop_user"].timestamps[0] -= 5.0

        res = await limiter.consume("pop_user")

        assert res.allowed is True
        assert len(limiter._windows["pop_user"].timestamps) == 1

    async def test_in_memory_swl_concurrency(self) -> None:
        config = SlidingWindowConfig(max_requests=50, window_seconds=10.0)
        limiter = InMemorySlidingWindowLog(config)

        async def try_consume() -> bool:
            return (await limiter.consume("swl_concurrent")).allowed

        results = await asyncio.gather(*(try_consume() for _ in range(100)))
        assert sum(1 for r in results if r) == 50


@pytest.mark.asyncio
class TestRedisSlidingWindow:
    async def test_redis_swl_basic(self, fake_redis: FakeRedis) -> None:
        config = SlidingWindowConfig(max_requests=2, window_seconds=5.0)
        limiter = RedisSlidingWindowLog(fake_redis, config)

        assert (await limiter.consume("redis_swl")).allowed is True
        assert (await limiter.consume("redis_swl")).allowed is True

        reject = await limiter.consume("redis_swl")
        assert reject.allowed is False
        assert reject.reset_in > 0

    async def test_redis_swl_concurrency(self, fake_redis: FakeRedis) -> None:
        config = SlidingWindowConfig(max_requests=50, window_seconds=10.0)
        limiter = RedisSlidingWindowLog(fake_redis, config)

        async def try_consume() -> bool:
            return (await limiter.consume("redis_swl_conc")).allowed

        results = await asyncio.gather(*(try_consume() for _ in range(100)))
        assert sum(1 for r in results if r) == 50


@pytest.mark.asyncio
class TestInMemoryFixedWindow:
    async def test_in_memory_fw_basic(self) -> None:
        config = FixedWindowConfig(max_requests=2, window_seconds=5)
        limiter = InMemoryFixedWindow(config)

        assert (await limiter.consume("fw_user")).allowed is True
        assert (await limiter.consume("fw_user")).allowed is True

        reject = await limiter.consume("fw_user")
        assert reject.allowed is False
        assert reject.remaining == 0

    async def test_in_memory_fw_pruning(self) -> None:
        config = FixedWindowConfig(max_requests=5, window_seconds=10, max_memory_keys=2)
        limiter = InMemoryFixedWindow(config)

        await limiter._get_window("user1", 1000.0)
        await limiter._get_window("user2", 1000.0)

        await limiter._get_window("user3", 2000.0)

        assert "user1" not in limiter._windows
        assert "user2" not in limiter._windows
        assert "user3" in limiter._windows


@pytest.mark.asyncio
class TestRedisFixedWindow:
    async def test_redis_fw_basic(self, fake_redis: FakeRedis) -> None:
        config = FixedWindowConfig(max_requests=3, window_seconds=10)
        limiter = RedisFixedWindow(fake_redis, config)

        for expected_rem in [2, 1, 0]:
            res = await limiter.consume("redis_fw")
            assert res.allowed is True
            assert res.remaining == expected_rem

        res_reject = await limiter.consume("redis_fw")
        assert res_reject.allowed is False
        assert res_reject.reset_in > 0
