"""FastAPI dependency injection providers."""

from collections.abc import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.db.session import get_db_session
from faultwarden.integrations.llm.provider import LLMProvider, PlaceholderLLMProvider
from faultwarden.integrations.loki.client import LogsProvider, LokiClient
from faultwarden.integrations.prometheus.client import MetricsProvider, PrometheusClient
from faultwarden.services.alert_service import AlertService
from faultwarden.services.incident_service import IncidentService


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing database session."""
    async for session in get_db_session():
        yield session


def get_incident_service(db: AsyncSession = Depends(get_db)) -> IncidentService:
    """Dependency for IncidentService."""
    return IncidentService(session=db)


def get_alert_service(
    incident_service: IncidentService = Depends(get_incident_service),
) -> AlertService:
    """Dependency for AlertService."""
    return AlertService(incident_service=incident_service)


def get_metrics_provider() -> MetricsProvider:
    """Dependency for Prometheus/MetricsProvider."""
    return PrometheusClient()


def get_logs_provider() -> LogsProvider:
    """Dependency for Loki/LogsProvider."""
    return LokiClient()


def get_llm_provider() -> LLMProvider:
    """Dependency for LLMProvider."""
    return PlaceholderLLMProvider()
