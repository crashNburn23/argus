"""Capability hints for model selection and local-model safety checks."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelCapabilities:
    provider: str
    model: str
    tool_calling: bool
    structured_output: bool
    context_window: int | None
    recommended_for: tuple[str, ...]
    cautions: tuple[str, ...] = ()
    confidence: str = "known"

    @property
    def recommendation(self) -> str:
        if not self.recommended_for:
            return "manual validation"
        return ", ".join(self.recommended_for)

    @property
    def caution_summary(self) -> str:
        if not self.cautions:
            return ""
        return "; ".join(self.cautions)


_OLLAMA_PROFILES: tuple[ModelCapabilities, ...] = (
    ModelCapabilities(
        provider="ollama",
        model="qwen2.5",
        tool_calling=True,
        structured_output=True,
        context_window=32768,
        recommended_for=("structured extraction", "triage drafts", "tool loops"),
        cautions=("validate long-form CTI reports with review",),
    ),
    ModelCapabilities(
        provider="ollama",
        model="qwen3",
        tool_calling=True,
        structured_output=True,
        context_window=40960,
        recommended_for=("structured extraction", "triage drafts", "tool loops"),
        cautions=("reasoning traces may need cleanup before JSON parsing",),
    ),
    ModelCapabilities(
        provider="ollama",
        model="llama3.1",
        tool_calling=True,
        structured_output=True,
        context_window=131072,
        recommended_for=("summarization", "case Q&A", "report drafts"),
        cautions=("verify strict schema adherence on smaller quantizations",),
    ),
    ModelCapabilities(
        provider="ollama",
        model="llama3.2",
        tool_calling=True,
        structured_output=True,
        context_window=131072,
        recommended_for=("summarization", "case Q&A", "report drafts"),
        cautions=("use review for attribution-heavy CTI synthesis",),
    ),
    ModelCapabilities(
        provider="ollama",
        model="mistral",
        tool_calling=True,
        structured_output=True,
        context_window=32768,
        recommended_for=("routing", "classification", "summarization"),
        cautions=("benchmark before complex multi-tool CTI analysis",),
    ),
    ModelCapabilities(
        provider="ollama",
        model="phi4",
        tool_calling=False,
        structured_output=True,
        context_window=16384,
        recommended_for=("fast summarization", "single-step classification"),
        cautions=("avoid multi-tool agent loops until locally benchmarked",),
    ),
)


def model_capabilities(provider: str, model: str) -> ModelCapabilities:
    """Return conservative capability hints for a provider/model pair."""
    normalized_provider = provider.lower()
    normalized_model = model.lower()

    if normalized_provider == "anthropic":
        return ModelCapabilities(
            provider=provider,
            model=model,
            tool_calling=True,
            structured_output=True,
            context_window=None,
            recommended_for=("all Argus agent workflows",),
            confidence="provider",
        )

    if normalized_provider == "ollama":
        for profile in _OLLAMA_PROFILES:
            if normalized_model.startswith(profile.model):
                return ModelCapabilities(
                    provider=provider,
                    model=model,
                    tool_calling=profile.tool_calling,
                    structured_output=profile.structured_output,
                    context_window=profile.context_window,
                    recommended_for=profile.recommended_for,
                    cautions=profile.cautions,
                    confidence=profile.confidence,
                )

        return ModelCapabilities(
            provider=provider,
            model=model,
            tool_calling=False,
            structured_output=False,
            context_window=None,
            recommended_for=("manual validation",),
            cautions=("unknown local model; run benchmarks before agent use",),
            confidence="unknown",
        )

    return ModelCapabilities(
        provider=provider,
        model=model,
        tool_calling=False,
        structured_output=False,
        context_window=None,
        recommended_for=("manual validation",),
        cautions=("unknown provider",),
        confidence="unknown",
    )
