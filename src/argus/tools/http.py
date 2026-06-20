"""Shared httpx.AsyncClient pool for all tool requests.

Creating a new AsyncClient per request (the `async with httpx.AsyncClient() as c:`
pattern) tears down the TCP+TLS connection after every call. Module-level clients
reuse connections via httpx's built-in pool, which matters especially for retried
calls and concurrent tool dispatch.
"""

from __future__ import annotations

import functools

import httpx

_LIMITS = httpx.Limits(max_keepalive_connections=20, max_connections=100)
_LIMITS_SMALL = httpx.Limits(max_keepalive_connections=5, max_connections=20)


@functools.lru_cache(maxsize=1)
def get_client() -> httpx.AsyncClient:
    """Default client — 30 s timeout, shared connection pool."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        limits=_LIMITS,
    )


@functools.lru_cache(maxsize=1)
def get_redirect_client() -> httpx.AsyncClient:
    """15 s timeout, follows redirects — used for RDAP lookups."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(15.0, connect=10.0),
        follow_redirects=True,
        limits=_LIMITS_SMALL,
    )


@functools.lru_cache(maxsize=2)
def get_misp_client(verify_ssl: bool) -> httpx.AsyncClient:
    """MISP-specific client with configurable SSL verification."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        verify=verify_ssl,
        limits=_LIMITS_SMALL,
    )
