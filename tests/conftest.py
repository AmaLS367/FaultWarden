"""Pytest configuration and test fixtures."""

import os

# Force hermetic provider settings before any faultwarden module is imported.
# Settings loads a repo-root .env (meant for local Docker/dev config) via
# pydantic-settings; a real LLM/embedding API key there would otherwise make
# the whole suite call out to a real, non-deterministic, paid provider instead
# of the deterministic Mock providers these tests are written against.
# Environment variables take precedence over .env file values, so this wins.
os.environ["FAULTWARDEN_LLM_PROVIDER"] = "mock"
os.environ["FAULTWARDEN_LLM_API_KEY"] = ""
os.environ["FAULTWARDEN_MEMORY_EMBEDDING_PROVIDER"] = "mock"
os.environ["FAULTWARDEN_MEMORY_EMBEDDING_API_KEY"] = ""

from collections.abc import AsyncGenerator  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from faultwarden.api.dependencies import get_db  # noqa: E402
from faultwarden.core.config import get_settings  # noqa: E402
from faultwarden.db.base import Base  # noqa: E402
from faultwarden.graph.builder import reset_production_graph  # noqa: E402
from faultwarden.graph.checkpointer import set_checkpointer  # noqa: E402
from faultwarden.main import app  # noqa: E402

get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_graph_state() -> Any:
    """Reset checkpointer and compiled production graph between tests."""
    reset_production_graph()
    set_checkpointer(None)
    yield
    reset_production_graph()
    set_checkpointer(None)


@pytest_asyncio.fixture(scope="function")
async def test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Create an isolated in-memory SQLite async engine for each test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional async database session."""
    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Provide an authenticated AsyncClient bound to the FastAPI application with test DB."""

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def sample_alertmanager_payload() -> dict[str, Any]:
    """Return a representative Alertmanager webhook payload."""
    now_iso = datetime.now(UTC).isoformat()
    return {
        "version": "4",
        "groupKey": '{}:{alertname="High5xxRate",service="demo-service"}',
        "truncatedAlerts": 0,
        "status": "firing",
        "receiver": "faultwarden_webhook",
        "groupLabels": {
            "alertname": "High5xxRate",
            "service": "demo-service",
        },
        "commonLabels": {
            "alertname": "High5xxRate",
            "service": "demo-service",
            "severity": "critical",
            "job": "demo-service",
        },
        "commonAnnotations": {
            "summary": "Elevated HTTP 5xx error rate on demo-service",
            "description": "demo-service is returning 5xx status codes for incoming requests.",
            "runbook_url": "https://wiki.internal/runbooks/demo-service-5xx",
        },
        "externalURL": "http://alertmanager:9093",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "High5xxRate",
                    "service": "demo-service",
                    "severity": "critical",
                    "instance": "demo-service:8001",
                },
                "annotations": {
                    "summary": "Elevated HTTP 5xx error rate on demo-service",
                    "description": "demo-service is returning 5xx status codes for incoming requests.",
                },
                "startsAt": now_iso,
                "endsAt": None,
                "generatorURL": "http://prometheus:9090/graph?g0.expr=rate%28demo_http_requests_total...",
                "fingerprint": "a1b2c3d4e5f6",
            }
        ],
    }
