"""Deliberately breakable FastAPI demo service for FaultWarden verification."""

import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

app = FastAPI(
    title="FaultWarden Demo Service",
    description="Intentionally breakable demo service for SRE incident simulation.",
    version="1.0.0",
)

# State for deterministic failure simulation
_ERROR_MODE_ENABLED: bool = False

# Prometheus metrics
DEMO_HTTP_REQUESTS_TOTAL = Counter(
    "demo_http_requests_total",
    "Total HTTP requests to the demo service",
    ["method", "endpoint", "status"],
)

DEMO_HTTP_DURATION_SECONDS = Histogram(
    "demo_http_request_duration_seconds",
    "HTTP request latency to the demo service in seconds",
    ["method", "endpoint"],
)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next: Any) -> Response:
    start_time = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start_time

    path = request.url.path
    if path != "/metrics":
        DEMO_HTTP_REQUESTS_TOTAL.labels(
            method=request.method,
            endpoint=path,
            status=str(response.status_code),
        ).inc()
        DEMO_HTTP_DURATION_SECONDS.labels(
            method=request.method,
            endpoint=path,
        ).observe(duration)

    return response


@app.get("/health", status_code=status.HTTP_200_OK)
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "demo-service"}


@app.get("/", status_code=status.HTTP_200_OK)
async def root() -> dict[str, Any]:
    """Main business endpoint (fails with 500 if error-mode is active)."""
    if _ERROR_MODE_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Simulated internal server failure in demo service.",
        )
    return {
        "service": "demo-service",
        "status": "healthy",
        "message": "Payment processing completed successfully.",
        "error_mode": False,
    }


@app.post("/debug/error-mode/{enabled}", status_code=status.HTTP_200_OK)
async def set_error_mode(enabled: bool) -> dict[str, Any]:
    """Toggle deterministic error injection."""
    global _ERROR_MODE_ENABLED
    _ERROR_MODE_ENABLED = enabled
    return {
        "status": "updated",
        "error_mode": _ERROR_MODE_ENABLED,
        "message": f"Error simulation set to {enabled}",
    }


@app.get("/debug/error-mode", status_code=status.HTTP_200_OK)
async def get_error_mode() -> dict[str, bool]:
    """Inspect current error injection state."""
    return {"error_mode": _ERROR_MODE_ENABLED}


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Prometheus metrics scrape target."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
