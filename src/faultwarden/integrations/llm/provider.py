"""LLM provider interface and deterministic placeholder implementation."""

from typing import Any, Protocol, runtime_checkable

from faultwarden.core.config import LLMSettings, get_settings
from faultwarden.core.logging import get_logger

logger = get_logger("faultwarden.integrations.llm")


@runtime_checkable
class LLMProvider(Protocol):
    """Abstract interface for LLM operations."""

    async def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        """Generate unstructured text from a prompt."""
        ...

    async def generate_structured(
        self,
        prompt: str,
        schema: type[Any],
        system_prompt: str | None = None,
    ) -> Any:
        """Generate a structured response adhering to a Pydantic schema."""
        ...


class PlaceholderLLMProvider(LLMProvider):
    """Deterministic placeholder LLM provider for scaffolding without external API calls."""

    def __init__(self, settings: LLMSettings | None = None) -> None:
        self._settings = settings or get_settings().llm

    async def generate_text(self, prompt: str, _system_prompt: str | None = None) -> str:
        logger.info("placeholder_llm_generate_text_invoked", prompt_length=len(prompt))
        return f"[PlaceholderLLM Response for prompt: '{prompt[:50]}...']"

    async def generate_structured(
        self,
        _prompt: str,
        schema: type[Any],
        _system_prompt: str | None = None,
    ) -> Any:
        logger.info(
            "placeholder_llm_generate_structured_invoked",
            schema=schema.__name__ if hasattr(schema, "__name__") else str(schema),
        )
        if hasattr(schema, "model_validate"):
            try:
                return schema()
            except Exception:
                pass
        return None
