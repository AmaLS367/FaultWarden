"""Change collection node: retrieves recent Git, deployment, and configuration changes."""

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger
from faultwarden.graph.nodes._context import (
    get_change_provider_from_config,
    resolve_service_from_state,
)
from faultwarden.graph.state import IncidentInvestigationState

if TYPE_CHECKING:
    from faultwarden.schemas.change import OperationalChange

logger = get_logger("faultwarden.graph.nodes.collect_changes")


# --- Change Collection Node ---
async def collect_recent_changes_node(
    state: IncidentInvestigationState,
    config: RunnableConfig | None = None,
) -> dict[str, Any]:
    """Retrieve operational changes (commits, deployments, configs) surrounding incident onset."""
    incident_id = state.get("incident_id", "unknown")
    settings = get_settings()

    if not settings.change.enabled:
        logger.info("change_intelligence_disabled_by_config", incident_id=incident_id)
        return {"recent_changes": []}

    service_name = resolve_service_from_state(state, default="demo-service")

    # Resolve reference incident timestamp from alert startsAt or fallback to current UTC
    alert_info = state.get("alert", {})
    alerts_list = alert_info.get("alerts", [])
    ref_time: datetime = datetime.now(UTC)

    if alerts_list and isinstance(alerts_list, list) and isinstance(alerts_list[0], dict):
        starts_at_str = alerts_list[0].get("startsAt")
        if starts_at_str:
            try:
                norm_str = str(starts_at_str)
                if norm_str.endswith("Z"):
                    norm_str = norm_str[:-1] + "+00:00"
                ref_time = datetime.fromisoformat(norm_str)
                if ref_time.tzinfo is None:
                    ref_time = ref_time.replace(tzinfo=UTC)
            except Exception:
                pass

    start_window = ref_time - timedelta(minutes=settings.change.lookback_minutes)
    end_window = ref_time + timedelta(minutes=settings.change.lookahead_minutes)

    logger.info(
        "collect_recent_changes_started",
        incident_id=incident_id,
        service=service_name,
        start_time=start_window.isoformat(),
        end_time=end_window.isoformat(),
    )

    change_provider = get_change_provider_from_config(config)
    changes: list[OperationalChange] = []
    node_errors: list[str] = []

    if change_provider is not None:
        try:
            changes = await change_provider.list_changes(
                service=service_name,
                start_time=start_window,
                end_time=end_window,
                limit=settings.change.max_recent_changes,
            )
            logger.info(
                "collect_recent_changes_completed",
                incident_id=incident_id,
                changes_count=len(changes),
            )
        except Exception as exc:
            logger.warning(
                "change_collection_failed_continuing_gracefully",
                incident_id=incident_id,
                error=str(exc),
            )
            node_errors.append(f"collect_recent_changes: Change retrieval failed: {exc}")
    else:
        logger.info(
            "change_provider_not_configured_for_node",
            incident_id=incident_id,
        )

    return {
        "recent_changes": changes,
        "errors": node_errors,
    }
