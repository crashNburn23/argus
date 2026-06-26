from __future__ import annotations

from argus.web.api.chat import _visible_result_text


def test_visible_result_text_preserves_nonempty_result() -> None:
    assert _visible_result_text("  answer  ") == "answer"


def test_visible_result_text_replaces_blank_result() -> None:
    text = _visible_result_text("   ")

    assert "no response text" in text.lower()
