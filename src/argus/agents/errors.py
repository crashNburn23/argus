"""Typed agent error contract — distinguishes failure modes from empty results."""
from __future__ import annotations

from enum import StrEnum


class AgentFailureCategory(StrEnum):
    PARSE_ERROR = "parse_error"
    VALIDATION_ERROR = "validation_error"
    LOOP_EXHAUSTED = "loop_exhausted"
    LLM_ERROR = "llm_error"


class AgentError(Exception):
    """Raised when an agent cannot produce a valid structured result.

    Callers must distinguish this from a successful run that found nothing.
    """

    def __init__(
        self,
        category: AgentFailureCategory,
        agent: str,
        message: str,
        raw_output: str = "",
    ) -> None:
        super().__init__(message)
        self.category = category
        self.agent = agent
        self.raw_output = raw_output

    def to_dict(self) -> dict[str, object]:
        return {
            "error": True,
            "category": self.category.value,
            "agent": self.agent,
            "message": str(self),
        }
