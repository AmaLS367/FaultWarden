"""FastAPI dependency injection providers."""

from collections.abc import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.db.session import get_db_session
from faultwarden.integrations.embedding.provider import (
    EmbeddingProvider,
)
from faultwarden.integrations.embedding.provider import (
    get_embedding_provider as get_default_embedding_provider,
)
from faultwarden.integrations.llm.provider import (
    LLMProvider,
)
from faultwarden.integrations.llm.provider import (
    get_llm_provider as get_default_llm_provider,
)
from faultwarden.integrations.loki.client import LogsProvider, LokiClient
from faultwarden.integrations.prometheus.client import MetricsProvider, PrometheusClient
from faultwarden.services.alert_service import AlertService
from faultwarden.services.incident_service import IncidentService
from faultwarden.services.investigation_service import InvestigationService
from faultwarden.services.memory_service import MemoryService
from faultwarden.services.postmortem_service import PostmortemService
from faultwarden.services.remediation_audit_service import RemediationAuditService


# --- Database Dependencies ---
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing database session."""
    async for session in get_db_session():
        yield session


# --- Service Dependencies ---
def get_incident_service(db: AsyncSession = Depends(get_db)) -> IncidentService:
    """Dependency for IncidentService."""
    return IncidentService(session=db)


def get_alert_service(
    incident_service: IncidentService = Depends(get_incident_service),
) -> AlertService:
    """Dependency for AlertService."""
    return AlertService(incident_service=incident_service)


def get_remediation_audit_service(db: AsyncSession = Depends(get_db)) -> RemediationAuditService:
    """Dependency for RemediationAuditService."""
    return RemediationAuditService(session=db)


def get_postmortem_service(
    db: AsyncSession = Depends(get_db),
    llm_provider: LLMProvider = Depends(lambda: get_default_llm_provider()),
) -> PostmortemService:
    """Dependency for PostmortemService."""
    return PostmortemService(session=db, llm_provider=llm_provider)


def get_memory_service(
    db: AsyncSession = Depends(get_db),
    embedding_provider: EmbeddingProvider = Depends(lambda: get_default_embedding_provider()),
) -> MemoryService:
    """Dependency for MemoryService."""
    return MemoryService(session=db, embedding_provider=embedding_provider)


# --- Integration Provider Dependencies ---
def get_metrics_provider() -> MetricsProvider:
    """Dependency for Prometheus/MetricsProvider."""
    return PrometheusClient()


def get_logs_provider() -> LogsProvider:
    """Dependency for Loki/LogsProvider."""
    return LokiClient()


def get_llm_provider() -> LLMProvider:
    """Dependency for LLMProvider."""
    return get_default_llm_provider()


def get_embedding_provider() -> EmbeddingProvider:
    """Dependency for EmbeddingProvider."""
    return get_default_embedding_provider()


def get_investigation_service(
    incident_service: IncidentService = Depends(get_incident_service),
    metrics_provider: MetricsProvider = Depends(get_metrics_provider),
    logs_provider: LogsProvider = Depends(get_logs_provider),
    llm_provider: LLMProvider = Depends(get_llm_provider),
    embedding_provider: EmbeddingProvider = Depends(get_embedding_provider),
) -> InvestigationService:
    """Dependency for InvestigationService."""
    return InvestigationService(
        incident_service=incident_service,
        metrics_provider=metrics_provider,
        logs_provider=logs_provider,
        llm_provider=llm_provider,
        embedding_provider=embedding_provider,
    )
