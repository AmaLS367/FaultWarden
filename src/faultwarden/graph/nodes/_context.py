"""Shared helpers for LangGraph investigation nodes: label extraction and provider resolution."""

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from langchain_core.runnables import RunnableConfig

from faultwarden.core.config import get_settings
from faultwarden.integrations.llm.provider import LLMProvider
from faultwarden.integrations.llm.provider import get_llm_provider as _default_llm_provider
from faultwarden.integrations.loki.client import LogsProvider, LokiClient
from faultwarden.integrations.prometheus.client import MetricsProvider, PrometheusClient
from faultwarden.schemas.remediation import RemediationAction, RemediationResult


# --- Alert Label Extraction ---
def extract_service_name(common_labels: dict[str, str], default: str) -> str:
    """Resolve the affected service name, preferring the `service` label over `job`.

    Mirrors `AlertmanagerPayload.primary_service` (schemas/alert.py): a Kubernetes/ECS
    deployment commonly sets `service` to the logical service and `job` to the shared
    scrape-job name, so `service` must win to avoid aggregating telemetry across an
    entire scrape job instead of the actual affected service.
    """
    if common_labels.get("service"):
        return common_labels["service"]
    if common_labels.get("job"):
        return common_labels["job"]
    return default


def resolve_service_from_state(state: Mapping[str, Any], default: str = "demo-service") -> str:
    """Resolve the affected service name from incident context, common labels, or individual alert items."""
    ctx_service = state.get("incident_context", {}).get("service")
    if ctx_service and ctx_service not in ("unknown", "unknown-service"):
        return str(ctx_service)

    alert = state.get("alert", {})
    common_labels = alert.get("commonLabels", {})
    if common_labels.get("service"):
        return str(common_labels["service"])
    if common_labels.get("job"):
        return str(common_labels["job"])

    alerts = alert.get("alerts", [])
    if alerts and isinstance(alerts, list) and isinstance(alerts[0], dict):
        first_labels = alerts[0].get("labels", {})
        if first_labels.get("service"):
            return str(first_labels["service"])
        if first_labels.get("job"):
            return str(first_labels["job"])

    return default


# --- Provider Resolution (config-injected, falling back to direct construction) ---
def _configurable(config: RunnableConfig | None) -> dict[str, Any]:
    """Safely extract the `configurable` dict from a possibly-absent RunnableConfig."""
    if not config:
        return {}
    return config.get("configurable") or {}


def get_metrics_provider(config: RunnableConfig | None) -> MetricsProvider:
    """Resolve the MetricsProvider injected via graph config, or construct the default client."""
    provider = _configurable(config).get("metrics_provider")
    if provider is not None:
        return provider  # type: ignore[no-any-return]
    return PrometheusClient(get_settings().prometheus)


def get_logs_provider(config: RunnableConfig | None) -> LogsProvider:
    """Resolve the LogsProvider injected via graph config, or construct the default client."""
    provider = _configurable(config).get("logs_provider")
    if provider is not None:
        return provider  # type: ignore[no-any-return]
    return LokiClient(get_settings().loki)


def get_llm_provider_from_config(config: RunnableConfig | None) -> LLMProvider:
    """Resolve the LLMProvider injected via graph config, or construct the default provider."""
    provider = _configurable(config).get("llm_provider")
    if provider is not None:
        return provider  # type: ignore[no-any-return]
    return _default_llm_provider()


def get_remediation_executor_from_config(
    config: RunnableConfig | None,
) -> Callable[[RemediationAction], Awaitable[RemediationResult]]:
    """Resolve the remediation executor dispatcher injected via graph config, or use the real one."""
    executor = _configurable(config).get("remediation_executor")
    if executor is not None:
        return executor  # type: ignore[no-any-return]
    from faultwarden.integrations.executors import execute_remediation_action

    return execute_remediation_action


def get_remediation_validator_from_config(
    config: RunnableConfig | None,
) -> Callable[[RemediationAction], Awaitable[bool]]:
    """Resolve the post-remediation recovery-check dispatcher injected via graph config, or use the real one."""
    validator = _configurable(config).get("remediation_validator")
    if validator is not None:
        return validator  # type: ignore[no-any-return]
    from faultwarden.integrations.executors import check_remediation_recovered

    return check_remediation_recovered
