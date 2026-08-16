"""LangGraph durable checkpointer lifecycle management and accessors."""

from contextlib import AbstractAsyncContextManager
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver

from faultwarden.core.config import Settings, get_settings
from faultwarden.core.logging import get_logger

logger = get_logger("faultwarden.graph.checkpointer")

# Module-level checkpointer singleton state
_checkpointer: BaseCheckpointSaver[Any] | None = None
_checkpointer_cm: AbstractAsyncContextManager[BaseCheckpointSaver[Any]] | None = None


# --- Checkpointer Accessors ---
def get_checkpointer() -> BaseCheckpointSaver[Any]:
    """Return the active checkpointer singleton or fall back to an ephemeral InMemorySaver."""
    global _checkpointer
    if _checkpointer is not None:
        return _checkpointer

    logger.warning(
        "checkpointer_uninitialized_fallback",
        message="Checkpointer accessed before explicit initialization; falling back to ephemeral InMemorySaver.",
    )
    _checkpointer = InMemorySaver()
    return _checkpointer


def set_checkpointer(checkpointer: BaseCheckpointSaver[Any] | None) -> None:
    """Explicitly override the checkpointer singleton (primarily for test harnesses)."""
    global _checkpointer
    _checkpointer = checkpointer


# --- Lifecycle Management ---
async def init_checkpointer(settings: Settings | None = None) -> BaseCheckpointSaver[Any]:
    """Initialize and set up the checkpointer for the application lifetime."""
    global _checkpointer, _checkpointer_cm
    active_settings = settings or get_settings()

    # SQLite dev/test fallback
    if (
        "sqlite" in active_settings.database.async_url
        or "sqlite" in active_settings.database.sync_url
    ):
        logger.info(
            "checkpointer_sqlite_init",
            message="SQLite database configured; using InMemorySaver for checkpointing.",
        )
        _checkpointer = InMemorySaver()
        return _checkpointer

    # PostgreSQL durable checkpointer
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

    conn_string = active_settings.database.sync_url
    logger.info("checkpointer_postgres_connecting", host=active_settings.database.host)

    cm = AsyncPostgresSaver.from_conn_string(conn_string)
    saver = await cm.__aenter__()
    await saver.setup()

    _checkpointer_cm = cm
    _checkpointer = saver
    logger.info("checkpointer_postgres_ready")
    return _checkpointer


async def close_checkpointer() -> None:
    """Cleanly close and tear down the active checkpointer connection."""
    global _checkpointer, _checkpointer_cm
    if _checkpointer_cm is not None:
        try:
            await _checkpointer_cm.__aexit__(None, None, None)
        except Exception as exc:
            logger.warning("checkpointer_close_error", error=str(exc))
        finally:
            _checkpointer_cm = None

    _checkpointer = None
    logger.info("checkpointer_closed")
