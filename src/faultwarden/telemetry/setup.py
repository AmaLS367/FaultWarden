"""OpenTelemetry and Prometheus metrics setup boundary."""

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger

logger = get_logger("faultwarden.telemetry")

# Core application metrics
HTTP_REQUESTS_TOTAL = Counter(
    "faultwarden_http_requests_total",
    "Total HTTP requests received by FaultWarden",
    ["method", "endpoint", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "faultwarden_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
)

INCIDENTS_CREATED_TOTAL = Counter(
    "faultwarden_incidents_created_total",
    "Total incidents created by source and severity",
    ["source", "severity"],
)


def setup_telemetry() -> None:
    """Initialize OpenTelemetry tracer and meter providers."""
    settings = get_settings().telemetry
    logger.info("telemetry_setup_initialized", service_name=settings.service_name)
    # OpenTelemetry tracer/meter providers can be attached here in full production mode


def prometheus_metrics_endpoint() -> Response:
    """FastAPI/Starlette response returning Prometheus text format metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
