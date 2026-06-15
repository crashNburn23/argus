"""Session persistence — save and reload interactive CLI sessions."""
from __future__ import annotations

import json
import random
import string
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SESSIONS_DIR = Path.home() / ".argus_sessions"
_MAX_SESSIONS = 50


def _sessions_dir() -> Path:
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return _SESSIONS_DIR


def generate_session_id() -> str:
    """Return a short human-readable session ID: YYMMDD-XXXXX."""
    date_part = datetime.now(tz=UTC).strftime("%y%m%d")
    rand_part = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
    return f"{date_part}-{rand_part}"


def save_session(
    session_id: str,
    title: str,
    model_info: str,
    exchanges: list[dict[str, Any]],
) -> None:
    """Persist a session to ~/.argus_sessions/<id>.json."""
    path = _sessions_dir() / f"{session_id}.json"
    now_iso = datetime.now(tz=UTC).isoformat()

    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            created_at = existing.get("created_at", now_iso)
        except Exception:
            created_at = now_iso
    else:
        created_at = now_iso

    data: dict[str, Any] = {
        "id": session_id,
        "title": title,
        "model": model_info,
        "created_at": created_at,
        "updated_at": now_iso,
        "turns": sum(1 for ex in exchanges if ex.get("role") == "user"),
        "exchanges": exchanges,
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_session(session_id: str) -> dict[str, Any] | None:
    """Load a session by ID. Returns None if not found or unreadable."""
    path = _sessions_dir() / f"{session_id}.json"
    if not path.exists():
        return None
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data
    except Exception:
        return None


def list_sessions() -> list[dict[str, Any]]:
    """Return session metadata sorted newest-first, capped at _MAX_SESSIONS."""
    sessions_dir = _sessions_dir()
    results: list[dict[str, Any]] = []
    for p in sessions_dir.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            # Surface only metadata (omit exchanges to keep list lightweight)
            results.append({
                "id": data.get("id", p.stem),
                "title": data.get("title", ""),
                "model": data.get("model", ""),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
                "turns": data.get("turns", 0),
            })
        except Exception:
            continue

    results.sort(key=lambda d: d.get("updated_at", ""), reverse=True)
    return results[:_MAX_SESSIONS]


def delete_session(session_id: str) -> bool:
    """Delete a session file. Returns True if deleted, False if not found."""
    path = _sessions_dir() / f"{session_id}.json"
    if not path.exists():
        return False
    path.unlink()
    return True
