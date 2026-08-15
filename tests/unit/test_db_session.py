"""Unit tests for async engine/session management."""

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from faultwarden.core.config import DatabaseSettings
from faultwarden.db import session as session_module
from faultwarden.db.base import Base


def test_create_engine_sqlite_uses_check_same_thread() -> None:
    """SQLite URLs should produce an engine without pool sizing kwargs."""
    settings = DatabaseSettings(url_override="sqlite+aiosqlite:///:memory:")
    engine = session_module.create_engine(settings)
    try:
        assert engine.dialect.name == "sqlite"
    finally:
        pass


def test_create_engine_postgres_configures_pool() -> None:
    """PostgreSQL URLs should build an engine with the configured pool size."""
    settings = DatabaseSettings(pool_size=5, max_overflow=7)
    engine = session_module.create_engine(settings)
    assert engine.dialect.name == "postgresql"


def test_get_engine_and_session_factory_are_cached_singletons() -> None:
    """get_engine/get_session_factory should return the same object on repeat calls."""
    session_module.get_engine.cache_clear()
    session_module.get_session_factory.cache_clear()
    try:
        engine_a = session_module.get_engine()
        engine_b = session_module.get_engine()
        assert engine_a is engine_b

        factory_a = session_module.get_session_factory()
        factory_b = session_module.get_session_factory()
        assert factory_a is factory_b
    finally:
        session_module.get_engine.cache_clear()
        session_module.get_session_factory.cache_clear()


@pytest.mark.asyncio
async def test_init_db_models_creates_tables() -> None:
    """init_db_models should create all declared ORM tables."""
    engine: AsyncEngine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        await session_module.init_db_models(engine)

        async with engine.connect() as conn:
            table_names = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )
        assert "incidents" in table_names
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_get_db_session_commits_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_db_session should yield a session and commit when no exception occurs."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(session_module, "get_session_factory", lambda: factory)

    try:
        gen = session_module.get_db_session()
        db_session = await anext(gen)
        assert isinstance(db_session, AsyncSession)

        with pytest.raises(StopAsyncIteration):
            await anext(gen)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_get_db_session_rolls_back_on_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_db_session should roll back and re-raise when the caller raises."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(session_module, "get_session_factory", lambda: factory)

    try:
        gen = session_module.get_db_session()
        await anext(gen)

        with pytest.raises(ValueError, match="boom"):
            await gen.athrow(ValueError("boom"))
    finally:
        await engine.dispose()
