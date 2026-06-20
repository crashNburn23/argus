from __future__ import annotations

import asyncio
import functools
import time
from typing import Any

import diskcache

from argus.config.settings import get_settings


@functools.lru_cache(maxsize=1)
def get_cache() -> diskcache.Cache:
    settings = get_settings()
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    return diskcache.Cache(
        str(settings.cache_dir),
        size_limit=settings.cache_size_bytes,
        eviction_policy="least-recently-used",
    )


def cache_get(key: str) -> Any | None:
    return get_cache().get(key)


def cache_set(key: str, value: Any, ttl: int) -> None:
    get_cache().set(key, value, expire=ttl)


def cache_clear() -> int:
    cache = get_cache()
    count = len(cache)
    cache.clear()
    return count


def cache_stats() -> dict[str, Any]:
    cache = get_cache()
    return {
        "size_bytes": cache.volume(),
        "item_count": len(cache),
        "directory": str(cache.directory),
    }


# Rate limits (calls per minute) per API
_RATE_LIMITS: dict[str, int] = {
    "virustotal": 4,
    "shodan": 1,
    "recorded_future": 30,
    "abuseipdb": 60,
    "otx": 100,
    "nvd": 50,
    "urlhaus": 60,
    "misp": 100,
}


class RateLimiter:
    """Token-bucket rate limiter backed by diskcache for cross-process persistence."""

    def __init__(self, api_name: str, calls_per_minute: int) -> None:
        self.api_name = api_name
        self.calls_per_minute = calls_per_minute
        self._key = f"ratelimit:{api_name}"
        self._window = 60.0  # seconds

    def _now(self) -> float:
        return time.monotonic()

    def acquire(self) -> bool:
        cache = get_cache()
        with cache.transact():
            record = cache.get(self._key)
            now = time.time()
            if record is None:
                cache.set(self._key, {"count": 1, "window_start": now}, expire=self._window)
                return True
            count, window_start = record["count"], record["window_start"]
            elapsed = now - window_start
            if elapsed >= self._window:
                cache.set(self._key, {"count": 1, "window_start": now}, expire=self._window)
                return True
            if count < self.calls_per_minute:
                cache.set(
                    self._key,
                    {"count": count + 1, "window_start": window_start},
                    expire=self._window - elapsed,
                )
                return True
            return False

    async def wait_and_acquire(self) -> None:
        while not self.acquire():
            await asyncio.sleep(1.0)


@functools.cache
def get_rate_limiter(api_name: str) -> RateLimiter:
    cpm = _RATE_LIMITS.get(api_name, 60)
    return RateLimiter(api_name, cpm)
