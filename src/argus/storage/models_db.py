from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class IOCRecord(Base):
    __tablename__ = "ioc_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    raw_data: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class ReportRecord(Base):
    __tablename__ = "report_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AgentRunRecord(Base):
    __tablename__ = "agent_run_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_name: Mapped[str] = mapped_column(String(128), nullable=False)
    input_data: Mapped[str] = mapped_column(Text, default="{}")
    output_data: Mapped[str] = mapped_column(Text, default="{}")
    model_used: Mapped[str] = mapped_column(String(128), default="")
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="success")
    error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
