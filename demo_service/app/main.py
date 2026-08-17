"""Deliberately breakable FastAPI demo service for FaultWarden verification."""

import asyncio
import contextlib
import logging
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any
from urllib import request as urllib_request
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

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
    version="1.0.1",
)

# --- State for Deterministic Failure Simulation & Idempotency ---
_ERROR_MODE_ENABLED: bool = False
_DB_POOL_SIZE: int = 20
_DB_TIMEOUT_MS: int = 5000
_PROCESSED_IDEMPOTENCY_KEYS: dict[str, dict[str, Any]] = {}

_DEPLOYMENTS: list[dict[str, Any]] = [
    {
        "id": "deploy-001",
        "service": "demo-service",
        "version": "1.0.0",
        "environment": "production",
        "commit_sha": "f12a3b4c5d6e",
        "deployed_by": "ci-runner",
        "status": "SUCCESS",
        "timestamp": "2026-08-17T04:00:00Z",
        "config_changes": [],
    },
    {
        "id": "deploy-002",
        "service": "demo-service",
        "version": "1.0.1",
        "environment": "production",
        "commit_sha": "a81cf2e9401d",
        "deployed_by": "sre-deployer",
        "status": "SUCCESS",
        "timestamp": "2026-08-17T05:00:00Z",
        "config_changes": [
            {
                "key": "DB_POOL_SIZE",
                "old_value": "20",
                "new_value": "5",
                "component": "database",
            }
        ],
    },
]

_CONFIG_HISTORY: list[dict[str, Any]] = [
    {
        "timestamp": "2026-08-17T04:00:00Z",
        "config": {"DB_POOL_SIZE": 20, "DB_TIMEOUT_MS": 5000},
        "updated_by": "ci-runner",
    },
    {
        "timestamp": "2026-08-17T05:00:00Z",
        "config": {"DB_POOL_SIZE": 5, "DB_TIMEOUT_MS": 5000},
        "updated_by": "sre-deployer",
    },
]

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
    """Main business endpoint simulating payment checkout with pool sizing logic."""
    if _ERROR_MODE_ENABLED or _DB_POOL_SIZE <= 5:
        err_msg_1 = (
            f"[DB_POOL_EXHAUSTED] Database connection pool exhausted: "
            f"active_connections={_DB_POOL_SIZE}/{_DB_POOL_SIZE}, wait_queue=25, timeout={_DB_TIMEOUT_MS}ms. "
            f"Failed to acquire connection for transaction in /"
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
        "db_pool_size": _DB_POOL_SIZE,
        "error_mode": False,
    }


@app.post("/debug/error-mode/{enabled}", status_code=status.HTTP_200_OK, response_model=None)
async def set_error_mode(enabled: bool, request: Request) -> dict[str, Any] | Response:
    """Toggle deterministic error injection with optional X-Idempotency-Key deduplication."""
    global _ERROR_MODE_ENABLED
    idempotency_key = request.headers.get("x-idempotency-key")

    if idempotency_key and idempotency_key in _PROCESSED_IDEMPOTENCY_KEYS:
        logger.info(
            "Idempotent request received with key: %s, returning cached response", idempotency_key
        )
        return JSONResponse(
            content=_PROCESSED_IDEMPOTENCY_KEYS[idempotency_key],
            headers={"X-Cache": "HIT"},
        )

    _ERROR_MODE_ENABLED = enabled
    state_str = (
        "ENABLED (database connection pool exhaustion simulated)"
        if enabled
        else "DISABLED (healthy)"
    )
    logger.info("Fault injection mode updated: %s (idempotency_key=%s)", state_str, idempotency_key)

    response_payload: dict[str, Any] = {
        "status": "updated",
        "error_mode": _ERROR_MODE_ENABLED,
        "message": f"Error simulation set to {enabled}",
    }
    if idempotency_key:
        response_payload["idempotency_key"] = idempotency_key
        _PROCESSED_IDEMPOTENCY_KEYS[idempotency_key] = response_payload

    return response_payload


@app.get("/debug/error-mode", status_code=status.HTTP_200_OK)
async def get_error_mode() -> dict[str, Any]:
    """Inspect current error injection state and db pool size."""
    return {
        "error_mode": _ERROR_MODE_ENABLED,
        "db_pool_size": _DB_POOL_SIZE,
    }


# --- Deployment & Config Change Endpoints ---
class DeploymentCreateRequest(BaseModel):
    """Schema for registering a deployment in the demo service."""

    service: str = "demo-service"
    version: str = "1.0.2"
    commit_sha: str = "c7d8e9f0"
    deployed_by: str = "operator"
    environment: str = "production"
    config_changes: list[dict[str, Any]] = Field(default_factory=list)
    db_pool_size: int | None = None


@app.get("/deployments", status_code=status.HTTP_200_OK)
async def list_deployments(
    service: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List recorded deployments and configuration releases."""
    results = list(_DEPLOYMENTS)
    if service:
        results = [d for d in results if d.get("service") == service]

    def _parse_ts(ts_str: str) -> datetime:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)

    if start_time:
        try:
            st = _parse_ts(start_time)
            results = [d for d in results if _parse_ts(str(d["timestamp"])) >= st]
        except Exception:
            pass

    if end_time:
        try:
            et = _parse_ts(end_time)
            results = [d for d in results if _parse_ts(str(d["timestamp"])) <= et]
        except Exception:
            pass

    return results[:limit]


@app.post("/deployments", status_code=status.HTTP_201_CREATED)
async def create_deployment(payload: DeploymentCreateRequest) -> dict[str, Any]:
    """Register a new deployment and apply configuration changes."""
    global _DB_POOL_SIZE
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    dep_id = f"deploy-{uuid4().hex[:6]}"

    config_changes = list(payload.config_changes)
    if payload.db_pool_size is not None:
        old_val = str(_DB_POOL_SIZE)
        _DB_POOL_SIZE = payload.db_pool_size
        new_val = str(_DB_POOL_SIZE)
        config_changes.append(
            {
                "key": "DB_POOL_SIZE",
                "old_value": old_val,
                "new_value": new_val,
                "component": "database",
            }
        )

    # If payload.config_changes contains DB_POOL_SIZE
    for cfg in payload.config_changes:
        if cfg.get("key") == "DB_POOL_SIZE" and "new_value" in cfg:
            with contextlib.suppress(ValueError):
                _DB_POOL_SIZE = int(cfg["new_value"])

    record: dict[str, Any] = {
        "id": dep_id,
        "service": payload.service,
        "version": payload.version,
        "environment": payload.environment,
        "commit_sha": payload.commit_sha,
        "deployed_by": payload.deployed_by,
        "status": "SUCCESS",
        "timestamp": now_iso,
        "config_changes": config_changes,
    }
    _DEPLOYMENTS.append(record)

    _CONFIG_HISTORY.append(
        {
            "timestamp": now_iso,
            "config": {"DB_POOL_SIZE": _DB_POOL_SIZE, "DB_TIMEOUT_MS": _DB_TIMEOUT_MS},
            "updated_by": payload.deployed_by,
        }
    )

    logger.info("New deployment registered: %s (db_pool_size=%d)", dep_id, _DB_POOL_SIZE)
    return record


@app.get("/config/history", status_code=status.HTTP_200_OK)
async def get_config_history() -> list[dict[str, Any]]:
    """Inspect history of configuration changes."""
    return _CONFIG_HISTORY


@app.post("/config", status_code=status.HTTP_200_OK)
async def update_config(config_dict: dict[str, Any]) -> dict[str, Any]:
    """Update runtime configuration directly."""
    global _DB_POOL_SIZE, _DB_TIMEOUT_MS
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if "DB_POOL_SIZE" in config_dict:
        _DB_POOL_SIZE = int(config_dict["DB_POOL_SIZE"])
    if "DB_TIMEOUT_MS" in config_dict:
        _DB_TIMEOUT_MS = int(config_dict["DB_TIMEOUT_MS"])

    snapshot = {
        "timestamp": now_iso,
        "config": {"DB_POOL_SIZE": _DB_POOL_SIZE, "DB_TIMEOUT_MS": _DB_TIMEOUT_MS},
        "updated_by": "operator",
    }
    _CONFIG_HISTORY.append(snapshot)
    logger.info("Runtime configuration updated: %s", snapshot)
    return snapshot


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Prometheus metrics scrape target."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
