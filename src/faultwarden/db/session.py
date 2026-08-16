"""Async database session and engine management."""

from collections.abc import AsyncGenerator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from faultwarden.core.config import DatabaseSettings, get_settings
from faultwarden.db.base import Base


# --- Engine Management ---
def create_engine(db_settings: DatabaseSettings | None = None) -> AsyncEngine:
    """Create a new async SQLAlchemy engine."""
    settings = db_settings or get_settings().database
    is_sqlite = "sqlite" in settings.async_url

    connect_args = {}
    if is_sqlite:
        connect_args = {"check_same_thread": False}
        return create_async_engine(
            settings.async_url,
            echo=settings.echo,
            connect_args=connect_args,
        )

    return create_async_engine(
        settings.async_url,
        echo=settings.echo,
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Get or create singleton application database engine."""
    return create_engine()


# --- Session Management ---
@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get cached async session maker."""
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# --- Schema Initialization ---
async def init_db_models(engine: AsyncEngine | None = None) -> None:
    """Initialize database tables directly (for SQLite/test setups)."""
    target_engine = engine or get_engine()
    async with target_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
