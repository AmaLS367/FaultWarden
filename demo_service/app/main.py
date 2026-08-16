"""Deliberately breakable FastAPI demo service for FaultWarden verification."""

import asyncio
import logging
import os
import sys
import time
from typing import Any
from urllib import request as urllib_request

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.routing import APIRoute
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("demo-service")

LOKI_URL = os.getenv("LOKI_URL", os.getenv("FAULTWARDEN_LOKI_URL", "http://loki:3100")).rstrip("/")
_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def _push_log_to_loki(level: str, message: str) -> None:
    """Best-effort log forwarder to Grafana Loki HTTP push API."""
    try:
        ts_ns = str(int(time.time() * 1e9))
        import json

        payload = {
            "streams": [
                {
                    "stream": {
                        "job": "demo-service",
                        "service": "demo-service",
                        "level": level.lower(),
                    },
                    "values": [[ts_ns, message]],
                }
            ]
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(
            f"{LOKI_URL}/loki/api/v1/push",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib_request.urlopen(req, timeout=1.0)
    except Exception:
        # Non-blocking best effort for standalone / local dev
        pass


def _dispatch_loki_log(level: str, message: str) -> None:
    """Dispatch background log forwarder task while keeping a reference to avoid GC."""
    task = asyncio.create_task(asyncio.to_thread(_push_log_to_loki, level, message))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)


app = FastAPI(
    title="FaultWarden Demo Service",
    description="Intentionally breakable demo service for SRE incident simulation.",
    version="1.0.0",
)

# --- State for Deterministic Failure Simulation ---
_ERROR_MODE_ENABLED: bool = False

# --- Prometheus Metrics ---
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests handled by the demo service",
    ["method", "path", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency for the demo service in seconds",
    ["method", "path"],
)


def _get_normalized_path(request: Request) -> str:
    """Extract parameterized route path or fallback to URL path to avoid label cardinality explosion."""
    route: Any = request.scope.get("route")
    if isinstance(route, APIRoute):
        return route.path
    return request.url.path


# --- Middleware ---
@app.middleware("http")
async def metrics_middleware(request: Request, call_next: Any) -> Response:
    """Record request count and latency metrics for every non-/metrics request."""
    start_time = time.perf_counter()
    response: Response = await call_next(request)
    duration = time.perf_counter() - start_time

    path = request.url.path
    if path != "/metrics":
        normalized_path = _get_normalized_path(request)
        HTTP_REQUESTS_TOTAL.labels(
            method=request.method,
            path=normalized_path,
            status=str(response.status_code),
        ).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=request.method,
            path=normalized_path,
        ).observe(duration)

    return response


# --- Diagnostic & Business Endpoints ---
@app.get("/health", status_code=status.HTTP_200_OK)
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "demo-service"}


@app.get("/", status_code=status.HTTP_200_OK)
async def root() -> dict[str, Any]:
    """Main business endpoint simulating payment checkout."""
    if _ERROR_MODE_ENABLED:
        err_msg_1 = (
            "[DB_POOL_EXHAUSTED] Database connection pool exhausted: "
            "active_connections=10/10, wait_queue=25, timeout=5000ms. "
            "Failed to acquire connection for transaction in /"
        )
        err_msg_2 = "[RETRY_FAILURE] Connection retry limit (3) exceeded for PostgreSQL cluster postgres:5432"
        logger.error(err_msg_1)
        logger.warning(err_msg_2)

        # Push directly to Loki HTTP API so observability aggregators capture error telemetry
        _dispatch_loki_log("ERROR", err_msg_1)
        _dispatch_loki_log("WARN", err_msg_2)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection timeout: pool exhausted",
        )

    info_msg = "Payment transaction completed successfully: order_id=ord-88392 status=COMPLETED duration_ms=45"
    logger.info(info_msg)
    _dispatch_loki_log("INFO", info_msg)

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
    state_str = (
        "ENABLED (database connection pool exhaustion simulated)"
        if enabled
        else "DISABLED (healthy)"
    )
    logger.info("Fault injection mode updated: %s", state_str)
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
