"""Structured logging setup — call configure_logging() at app startup."""
from __future__ import annotations

import logging
import sys

import structlog

from argus.config.settings import get_settings

_verbose = True


def configure_logging() -> None:
    settings = get_settings()
    configured_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    level = configured_level if _verbose else logging.CRITICAL

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            (
                structlog.dev.ConsoleRenderer()
                if sys.stderr.isatty()
                else structlog.processors.JSONRenderer()
            ),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def set_verbose(enabled: bool) -> None:
    global _verbose
    _verbose = enabled
    configure_logging()


def get_verbose() -> bool:
    return _verbose
