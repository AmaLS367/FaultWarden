"""Embedding provider interface, OpenAI-compatible implementation, and deterministic mock provider."""

import hashlib
import math
import re
from typing import Protocol, runtime_checkable

import httpx

from faultwarden.core.config import MemorySettings, get_settings
from faultwarden.core.exceptions import ProviderError
from faultwarden.core.logging import get_logger

logger = get_logger("faultwarden.integrations.embedding")


# --- Provider Protocol ---
@runtime_checkable
class EmbeddingProvider(Protocol):
    """Abstract interface for text embedding generation."""

    async def embed(self, text: str) -> list[float]:
        """Generate a vector embedding for a single text."""
        ...

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate vector embeddings for a batch of texts."""
        ...


# --- OpenAI-Compatible Provider ---
class OpenAIEmbeddingProvider(EmbeddingProvider):
    """Concrete embedding provider calling OpenAI or OpenAI-compatible endpoints."""

    def __init__(self, settings: MemorySettings | None = None) -> None:
        self._settings = settings or get_settings().memory
        self._api_key = self._settings.embedding_api_key
        self._model = self._settings.embedding_model
        self._dimensions = self._settings.embedding_dimensions
        self._base_url = (self._settings.embedding_base_url or "https://api.openai.com/v1").rstrip(
            "/"
        )

    async def embed(self, text: str) -> list[float]:
        """Generate vector embedding for a single text."""
        batch_res = await self.embed_batch([text])
        if not batch_res:
            raise ProviderError("embedding", "Provider returned empty embeddings list.")
        return batch_res[0]

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate vector embeddings for a list of texts."""
        if not texts:
            return []

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, object] = {
            "model": self._model,
            "input": texts,
        }
        # Only pass dimensions if specified and supported
        if self._dimensions:
            payload["dimensions"] = self._dimensions

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self._base_url}/embeddings",
                    headers=headers,
                    json=payload,
                )
                if resp.status_code != 200:
                    raise ProviderError(
                        "embedding",
                        f"HTTP {resp.status_code}: {resp.text}",
                        resp.status_code,
                    )
                data = resp.json()
                embeddings_data = data.get("data", [])
                # Sort by index to preserve input ordering
                sorted_data = sorted(embeddings_data, key=lambda x: x.get("index", 0))
                return [item["embedding"] for item in sorted_data]
        except httpx.RequestError as exc:
            raise ProviderError(
                "embedding", f"Connection to embedding provider failed: {exc}"
            ) from exc


# --- Deterministic Mock Provider for Offline Tests ---
class MockEmbeddingProvider(EmbeddingProvider):
    """Deterministic token-hash unit vector generator for tests and offline development."""

    def __init__(
        self,
        settings: MemorySettings | None = None,
        dimensions: int | None = None,
    ) -> None:
        resolved = settings or get_settings().memory
        self.dimensions: int = (
            dimensions if dimensions is not None else resolved.embedding_dimensions
        )

    def _generate_vector(self, text: str) -> list[float]:
        """Create a deterministic unit-normalized float vector from text tokens and hash."""
        vec = [0.0] * self.dimensions
        cleaned = text.lower()
        words = re.findall(r"[a-z0-9_\-]+", cleaned)

        if not words:
            # Fallback uniform unit vector
            val = 1.0 / math.sqrt(self.dimensions)
            return [val] * self.dimensions

        for word in words:
            # Map word to deterministic dimensions using MD5
            digest = hashlib.md5(word.encode("utf-8")).digest()
            # Distribute across 4 slots per word
            for i in range(4):
                idx = (digest[i * 4] * 256 + digest[i * 4 + 1]) % self.dimensions
                weight = ((digest[i * 4 + 2] / 255.0) * 2.0) - 1.0
                vec[idx] += weight

        # Add whole-text hash seed for individuality
        text_digest = hashlib.sha256(cleaned.encode("utf-8")).digest()
        for i in range(min(16, self.dimensions)):
            idx = (text_digest[i * 2] * 256 + text_digest[i * 2 + 1]) % self.dimensions
            vec[idx] += 0.1

        # Normalize vector to unit length (L2 norm = 1.0)
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0.0:
            vec = [v / norm for v in vec]
        else:
            val = 1.0 / math.sqrt(self.dimensions)
            vec = [val] * self.dimensions

        return vec

    async def embed(self, text: str) -> list[float]:
        """Return deterministic vector for text."""
        return self._generate_vector(text)

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Return deterministic vectors for batch of texts."""
        return [self._generate_vector(t) for t in texts]


# --- Provider Factory ---
def get_embedding_provider(settings: MemorySettings | None = None) -> EmbeddingProvider:
    """Return configured EmbeddingProvider instance."""
    resolved = settings or get_settings().memory

    if (
        resolved.embedding_provider.lower() in ("mock", "placeholder")
        or not resolved.embedding_api_key.strip()
    ):
        logger.info("using_mock_embedding_provider", dimensions=resolved.embedding_dimensions)
        return MockEmbeddingProvider(resolved)

    logger.info(
        "using_openai_embedding_provider",
        model=resolved.embedding_model,
        dimensions=resolved.embedding_dimensions,
        base_url=resolved.embedding_base_url or "https://api.openai.com/v1",
    )
    return OpenAIEmbeddingProvider(resolved)
