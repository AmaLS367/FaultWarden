"""Main FastAPI application entrypoint."""

import time
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from faultwarden.api.router import api_router
from faultwarden.api.routes.health import router as health_router
from faultwarden.core.config import get_settings
from faultwarden.core.exceptions import (
    ActiveJobConflictError,
    FaultWardenError,
    IncidentMemoryNotFoundError,
    IncidentNotFoundError,
    InvalidAlertPayloadError,
    InvalidStateTransitionError,
    PostmortemNotFoundError,
    ProviderError,
    RemediationActionNotFoundError,
    RemediationApprovalStaleError,
    RemediationExecutionClaimError,
    RemediationNotAwaitingApprovalError,
    RemediationProposalNotFoundError,
    RemediationSafetyError,
)
from faultwarden.core.logging import get_logger, setup_logging
from faultwarden.db.session import init_db_models
from faultwarden.graph.checkpointer import close_checkpointer, init_checkpointer
from faultwarden.telemetry.setup import (
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
    prometheus_metrics_endpoint,
    setup_telemetry,
)

logger = get_logger("faultwarden.app")


def _get_normalized_path(request: Request) -> str:
    """Extract the parameterized route path or fall back to the URL path, avoiding label cardinality explosion."""
    route: Any = request.scope.get("route")
    if isinstance(route, APIRoute):
        return route.path
    return request.url.path


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifespan management."""
    settings = get_settings()
    setup_logging(log_level=settings.server.log_level, environment=settings.server.env)
    setup_telemetry()
    logger.info(
        "faultwarden_starting",
        env=settings.server.env,
        host=settings.server.host,
        port=settings.server.port,
    )

    # Initialize checkpointer (AsyncPostgresSaver on Postgres, InMemorySaver fallback on SQLite)
    await init_checkpointer(settings)

    # Initialize tables automatically when running with SQLite (e.g. dev/tests)
    if "sqlite" in settings.database.async_url:
        await init_db_models()

    yield

    # Cleanly close checkpointer connections on shutdown
    await close_checkpointer()
    logger.info("faultwarden_shutting_down")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title="FaultWarden API",
        description="Autonomous AI SRE / Incident Response Engineer platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.server.debug or settings.server.env != "production" else None,
        redoc_url="/redoc"
        if settings.server.debug or settings.server.env != "production"
        else None,
    )

    # --- CORS ---
    # Browsers reject "Access-Control-Allow-Credentials: true" combined with a
    # wildcard origin, so credentials are only enabled once explicit origins
    # are configured via FAULTWARDEN_CORS_ORIGINS.
    cors_origins = settings.cors_origins_list
    is_wildcard = cors_origins == ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=not is_wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Request Logging & Metrics Middleware ---
    @app.middleware("http")
    async def request_logging_middleware(
        request: Request, call_next: Callable[..., Any]
    ) -> Response:
        """Record per-request metrics and structured logs, tagging the response with a request ID."""
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        start_time = time.perf_counter()

        response: Response = await call_next(request)

        duration = time.perf_counter() - start_time
        status_code = response.status_code
        path = request.url.path

        # Record metrics (skip metrics endpoint itself)
        if path != "/metrics":
            normalized_path = _get_normalized_path(request)
            HTTP_REQUESTS_TOTAL.labels(
                method=request.method,
                endpoint=normalized_path,
                status=str(status_code),
            ).inc()
            HTTP_REQUEST_DURATION_SECONDS.labels(
                method=request.method,
                endpoint=normalized_path,
            ).observe(duration)

        logger.info(
            "http_request_completed",
            request_id=request_id,
            method=request.method,
            path=path,
            status_code=status_code,
            duration_ms=round(duration * 1000, 2),
        )

        response.headers["X-Request-ID"] = request_id
        return response

    # --- Exception Handlers ---
    @app.exception_handler(IncidentNotFoundError)
    async def incident_not_found_handler(
        _request: Request, exc: IncidentNotFoundError
    ) -> JSONResponse:
        """Map a missing-incident lookup to a 404 response."""
        logger.warning("incident_not_found", error=exc.message, incident_id=exc.incident_id)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(InvalidAlertPayloadError)
    async def invalid_alert_handler(
        _request: Request, exc: InvalidAlertPayloadError
    ) -> JSONResponse:
        """Map a malformed Alertmanager payload to a 422 response."""
        logger.warning("invalid_alert_payload", error=exc.message, details=exc.details)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Unprocessable Alert",
                "message": exc.message,
                "details": exc.details,
            },
        )

    @app.exception_handler(RemediationSafetyError)
    async def remediation_safety_handler(
        _request: Request, exc: RemediationSafetyError
    ) -> JSONResponse:
        """Map a remediation safety-tier violation to a 403 response."""
        logger.error("remediation_safety_violation", error=exc.message, details=exc.details)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "Safety Violation", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(RemediationActionNotFoundError)
    async def remediation_action_not_found_handler(
        _request: Request, exc: RemediationActionNotFoundError
    ) -> JSONResponse:
        """Map a missing remediation action lookup to a 404 response."""
        logger.warning("remediation_action_not_found", error=exc.message, action_id=exc.action_id)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(RemediationProposalNotFoundError)
    async def remediation_proposal_not_found_handler(
        _request: Request, exc: RemediationProposalNotFoundError
    ) -> JSONResponse:
        """Map a missing remediation proposal lookup to a 404 response."""
        logger.warning(
            "remediation_proposal_not_found", error=exc.message, proposal_id=exc.proposal_id
        )
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(PostmortemNotFoundError)
    async def postmortem_not_found_handler(
        _request: Request, exc: PostmortemNotFoundError
    ) -> JSONResponse:
        """Map a missing postmortem lookup to a 404 response."""
        logger.warning("postmortem_not_found", error=exc.message, incident_id=exc.incident_id)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(IncidentMemoryNotFoundError)
    async def incident_memory_not_found_handler(
        _request: Request, exc: IncidentMemoryNotFoundError
    ) -> JSONResponse:
        """Map a missing incident memory lookup to a 404 response."""
        logger.warning("incident_memory_not_found", error=exc.message, incident_id=exc.incident_id)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(RemediationNotAwaitingApprovalError)
    async def remediation_not_awaiting_approval_handler(
        _request: Request, exc: RemediationNotAwaitingApprovalError
    ) -> JSONResponse:
        """Map an approve/reject conflict (already decided, or not paused) to a 409 response."""
        logger.warning(
            "remediation_not_awaiting_approval",
            error=exc.message,
            incident_id=exc.incident_id,
            current_status=exc.current_status,
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(RemediationApprovalStaleError)
    async def remediation_approval_stale_handler(
        _request: Request, exc: RemediationApprovalStaleError
    ) -> JSONResponse:
        """Map an approval decision arriving after the timeout window to a 409 response."""
        logger.warning("remediation_approval_stale", error=exc.message, action_id=exc.action_id)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(ActiveJobConflictError)
    async def active_job_conflict_handler(
        _request: Request, exc: ActiveJobConflictError
    ) -> JSONResponse:
        """Map an active investigation job conflict to a 409 response."""
        logger.warning(
            "active_job_conflict",
            error=exc.message,
            incident_id=exc.incident_id,
            job_id=exc.job_id,
            job_status=exc.job_status,
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(InvalidStateTransitionError)
    async def invalid_state_transition_handler(
        _request: Request, exc: InvalidStateTransitionError
    ) -> JSONResponse:
        """Map an invalid entity lifecycle state transition to a 409 response."""
        logger.warning(
            "invalid_state_transition",
            error=exc.message,
            entity=exc.entity,
            current_status=exc.current_status,
            target_status=exc.target_status,
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(RemediationExecutionClaimError)
    async def remediation_execution_claim_handler(
        _request: Request, exc: RemediationExecutionClaimError
    ) -> JSONResponse:
        """Map an action execution claim failure to a 409 response."""
        logger.warning(
            "remediation_claim_error",
            error=exc.message,
            action_id=exc.action_id,
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(ProviderError)
    async def provider_error_handler(_request: Request, exc: ProviderError) -> JSONResponse:
        """Map an upstream integration failure (Prometheus, Loki, LLM) to a 502 response."""
        logger.error("provider_error", provider=exc.provider_name, error=exc.message)
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": "Upstream Provider Error",
                "message": exc.message,
                "details": exc.details,
            },
        )

    @app.exception_handler(FaultWardenError)
    async def faultwarden_generic_handler(_request: Request, exc: FaultWardenError) -> JSONResponse:
        """Catch-all mapping for any unhandled domain error to a 500 response."""
        logger.error("faultwarden_error", error=exc.message, details=exc.details)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "message": exc.message,
                "details": exc.details,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Map a FastAPI/Pydantic request validation failure to a 422 response."""
        logger.warning("request_validation_failed", errors=exc.errors())
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "Validation Error", "details": exc.errors()},
        )

    # --- Routers ---
    # Direct top-level health & metrics endpoints
    app.include_router(health_router)
    if settings.telemetry.enable_metrics:
        app.add_api_route(
            "/metrics", prometheus_metrics_endpoint, methods=["GET"], include_in_schema=False
        )

    # - API v1 routes
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()
