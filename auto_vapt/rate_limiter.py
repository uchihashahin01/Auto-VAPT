"""Token-bucket rate limiter for HTTP requests."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx


class TokenBucketRateLimiter:
    """Token bucket rate limiter.

    Allows a burst of requests up to `capacity` and refills
    at `rate` tokens per second.
    """

    def __init__(self, rate: float, capacity: int | None = None) -> None:
        self.rate = rate
        self.capacity = capacity or int(rate * 2)
        self.tokens = float(self.capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one."""
        while True:
            async with self._lock:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
            await asyncio.sleep(1.0 / self.rate)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self._last_refill = now


class RateLimitedTransport(httpx.AsyncBaseTransport):
    """HTTPX transport wrapper that enforces rate limiting."""

    def __init__(
        self,
        rate: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.limiter = TokenBucketRateLimiter(rate)
        self._transport = transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await self.limiter.acquire()
        return await self._transport.handle_async_request(request)
