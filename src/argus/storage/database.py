from __future__ import annotations

import functools
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from argus.config.settings import get_settings
from argus.storage.models_db import Base


@functools.lru_cache(maxsize=1)
def _get_engine() -> Engine:
    settings = get_settings()
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        f"sqlite:///{settings.db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def set_wal(dbapi_connection: Any, connection_record: Any) -> None:
        dbapi_connection.execute("PRAGMA journal_mode=WAL")

    Base.metadata.create_all(engine)
    _migrate(engine)
    return engine


def _migrate(engine: Engine) -> None:
    """Add columns introduced after the initial schema without dropping data."""
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(agent_run_records)"))}
        if "status" not in existing:
            conn.execute(
                text("ALTER TABLE agent_run_records ADD COLUMN status TEXT DEFAULT 'success'")
            )
        if "error_category" not in existing:
            conn.execute(text("ALTER TABLE agent_run_records ADD COLUMN error_category TEXT"))
        if "ledger_json" not in existing:
            conn.execute(
                text("ALTER TABLE agent_run_records ADD COLUMN ledger_json TEXT DEFAULT '{}'")
            )
        conn.commit()


def _get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=_get_engine(), expire_on_commit=False)


@contextmanager
def get_session() -> Generator[Session, None, None]:
    factory = _get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
