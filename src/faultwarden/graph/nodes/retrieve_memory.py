import contextlib
from typing import TYPE_CHECKING, Any
from uuid import UUID

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import (
    get_memory_service_from_config,
    resolve_service_from_state,
)
from faultwarden.graph.state import IncidentInvestigationState

if TYPE_CHECKING:
    from faultwarden.schemas.memory import SimilarIncidentMemory

logger = get_logger("faultwarden.graph.nodes.retrieve_memory")


# --- Memory Retrieval Logic ---
async def retrieve_incident_memory_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,
) -> dict[str, Any]:
    """Search long-term incident memory for historically similar resolved incidents to provide background context."""
    incident_id = state.get("incident_id", "unknown")
    settings = get_settings()

    if not settings.memory.enabled:
        logger.info("incident_memory_disabled_by_config", incident_id=incident_id)
        return {"similar_incidents": []}

    service_name = resolve_service_from_state(state, default="demo-service")
    classification = state.get("classification")
    category_str = classification.category.value if classification is not None else "UNKNOWN"
    alert = state.get("alert", {})
    ann = alert.get("commonAnnotations", {})
    alert_summary = (
        ann.get("summary")
        or ann.get("description")
        or state.get("incident_context", {}).get("title", "")
    )

    # Summarize initial telemetry observations
    telemetry_snippets: list[str] = []
    for m in state.get("metrics", []):
        if m.summary:
            telemetry_snippets.append(f"Metric: {m.summary}")
    for log_item in state.get("logs", []):
        if log_item.level in ("ERROR", "FATAL", "CRITICAL") or "error" in log_item.message.lower():
            telemetry_snippets.append(f"Log: {log_item.message[:120]}")

    symptoms_text = (
        "\n".join(telemetry_snippets[:4])
        if telemetry_snippets
        else f"Initial alert triggered on {service_name}."
    )

    query_text = (
        f"Service: {service_name}\n"
        f"Classification: {category_str}\n"
        f"Alert: {alert_summary}\n"
        f"Symptoms:\n{symptoms_text}"
    )

    logger.info(
        "retrieve_incident_memory_started",
        incident_id=incident_id,
        service=service_name,
        classification=category_str,
    )

    memory_svc = get_memory_service_from_config(config)
    similar_incidents: list[SimilarIncidentMemory] = []
    node_errors: list[str] = []

    if memory_svc is not None:
        try:
            exclude_id: UUID | None = None
            with contextlib.suppress(Exception):
                exclude_id = UUID(incident_id)

            similar_incidents = await memory_svc.search_similar(
                query=query_text,
                service=None,  # Cross-service retrieval supported with ranking
                limit=settings.memory.top_k,
                min_similarity=settings.memory.min_similarity,
                exclude_incident_id=exclude_id,
            )
            logger.info(
                "retrieve_incident_memory_completed",
                incident_id=incident_id,
                retrieved_count=len(similar_incidents),
                top_similarity=similar_incidents[0].similarity if similar_incidents else None,
            )
        except Exception as exc:
            logger.warning(
                "incident_memory_retrieval_failed_continuing_gracefully",
                incident_id=incident_id,
                error=str(exc),
            )
            node_errors.append(f"retrieve_incident_memory: Memory retrieval error: {exc}")
    else:
        logger.info(
            "incident_memory_service_not_configured_for_node",
            incident_id=incident_id,
        )

    return {
        "similar_incidents": similar_incidents,
        "errors": node_errors,
    }
