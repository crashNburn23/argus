"""Shared disclosure-policy helpers for model and tool execution boundaries."""

from __future__ import annotations

from typing import Any

DISCLOSURE_MODES = {"unrestricted", "confirm-external", "local-only"}


def disclosure_mode(settings: Any) -> str:
    mode = getattr(settings, "disclosure_mode", "unrestricted")
    if mode in DISCLOSURE_MODES:
        return str(mode)
    return "unrestricted"


def external_collection_allowed(settings: Any) -> bool:
    return disclosure_mode(settings) != "local-only"


def external_collection_block_reason(settings: Any) -> str:
    return f"blocked by {disclosure_mode(settings)} disclosure mode"
