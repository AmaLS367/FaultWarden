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

from faultwarden.api.router import api_router
from faultwarden.api.routes.health import router as health_router
from faultwarden.core.config import get_settings
from faultwarden.core.exceptions import (
    FaultWardenError,
    IncidentNotFoundError,
    InvalidAlertPayloadError,
    ProviderError,
    RemediationSafetyError,
)
from faultwarden.core.logging import get_logger, setup_logging
from faultwarden.db.session import init_db_models
from faultwarden.telemetry.setup import (
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
    prometheus_metrics_endpoint,
    setup_telemetry,
)

logger = get_logger("faultwarden.app")


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

    # Initialize tables automatically when running with SQLite (e.g. dev/tests)
    if "sqlite" in settings.database.async_url:
        await init_db_models()

    yield

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

    # CORS
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

    # Request Logging & Metrics Middleware
    @app.middleware("http")
    async def request_logging_middleware(
        request: Request, call_next: Callable[..., Any]
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        start_time = time.perf_counter()

        response: Response = await call_next(request)

        duration = time.perf_counter() - start_time
        status_code = response.status_code
        path = request.url.path

        # Record metrics (skip metrics endpoint itself)
        if path != "/metrics":
            HTTP_REQUESTS_TOTAL.labels(
                method=request.method,
                endpoint=path,
                status=str(status_code),
            ).inc()
            HTTP_REQUEST_DURATION_SECONDS.labels(
                method=request.method,
                endpoint=path,
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

    # Exception Handlers
    @app.exception_handler(IncidentNotFoundError)
    async def incident_not_found_handler(
        _request: Request, exc: IncidentNotFoundError
    ) -> JSONResponse:
        logger.warning("incident_not_found", error=exc.message, incident_id=exc.incident_id)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(InvalidAlertPayloadError)
    async def invalid_alert_handler(
        _request: Request, exc: InvalidAlertPayloadError
    ) -> JSONResponse:
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
        logger.error("remediation_safety_violation", error=exc.message, details=exc.details)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "Safety Violation", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(ProviderError)
    async def provider_error_handler(_request: Request, exc: ProviderError) -> JSONResponse:
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
        logger.warning("request_validation_failed", errors=exc.errors())
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "Validation Error", "details": exc.errors()},
        )

    # Direct top-level health & metrics endpoints
    app.include_router(health_router)
    app.add_api_route(
        "/metrics", prometheus_metrics_endpoint, methods=["GET"], include_in_schema=False
    )

    # API v1 routes
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()
