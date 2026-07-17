import asyncio
from typing import Any

import pytest
import pytest_asyncio
from pydantic import ValidationError

from qulf.rate_limit.config import TokenBucketConfig
from qulf.rate_limit.token_bucket import InMemoryTokenBucket, RedisTokenBucket


# ==========================================
# 1. Configuration Tests
# ==========================================
def test_token_bucket_config_validation() -> None:
    # Valid config
    config = TokenBucketConfig(capacity=10, refill_rate=2.5, max_memory_keys=100)
    assert config.capacity == 10
    
    # Invalid config (should fail fast due to Pydantic strictness)
    with pytest.raises(ValidationError):
        TokenBucketConfig(capacity=-5, refill_rate=1.0)  # capacity must be > 0


# ==========================================
# 2. In-Memory Token Bucket Tests
# ==========================================
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
    assert "key_2" in bucket._buckets      # Kept! Still partially active.
    assert "key_3" in bucket._buckets      # Added!


@pytest.mark.asyncio
async def test_in_memory_tb_concurrency() -> None:
    config = TokenBucketConfig(capacity=50, refill_rate=0.1)
    bucket = InMemoryTokenBucket(config)
    
    async def try_consume() -> bool:
        return (await bucket.consume("concurrent_user")).allowed
        
    results = await asyncio.gather(*(try_consume() for _ in range(100)))
    successes = sum(1 for r in results if r)
    assert successes == 50


# ==========================================
# 3. Redis Token Bucket Tests
# ==========================================
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