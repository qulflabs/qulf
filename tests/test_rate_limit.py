import asyncio
import time
from typing import Any

import pytest

from qulf.rate_limit import InMemoryTokenBucket


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
    bucket = InMemoryTokenBucket(capacity=2, refill_rate=10.0) # 10 tokens per second = 1 token every 0.1s
    
    assert await bucket.consume("user_c", tokens=2) is True
    assert await bucket.consume("user_c") is False
    
    # Wait for 0.11 seconds to guarantee 1 token is refilled
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


import pytest_asyncio

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
