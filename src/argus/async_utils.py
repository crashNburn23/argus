"""Async helpers for running blocking SDK calls with deterministic cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, TypeVar

T = TypeVar("T")


async def run_sync(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a blocking call without retaining asyncio's process-wide executor."""
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="argus-sync") as executor:
        return await loop.run_in_executor(executor, partial(fn, *args, **kwargs))
