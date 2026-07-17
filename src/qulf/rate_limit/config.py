from pydantic import BaseModel, Field


class TokenBucketConfig(BaseModel):
    capacity: int = Field(..., gt=0, description="Maximum tokens the bucket can hold")
    refill_rate: float = Field(
        ..., gt=0.0, description="Number of tokens refilled per second"
    )
    max_memory_keys: int = Field(
        10000, description="Max IPs/Keys to store in memory before forcing a cleanup"
    )
    key_prefix: str = Field("qulf:ratelimit:tb:", description="Redis key prefix")


class SlidingWindowConfig(BaseModel):
    max_requests: int = Field(
        ..., gt=0, description="Max allowed requests in the window"
    )
    window_seconds: float = Field(
        ..., gt=0.0, description="Size of the sliding window in seconds"
    )
    max_memory_keys: int = Field(10000, description="Max IPs/Keys to store in memory")
    key_prefix: str = Field("qulf:ratelimit:swl:", description="Redis key prefix")
