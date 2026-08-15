"""Liveness and readiness health check endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from faultwarden.api.dependencies import get_db

router = APIRouter(tags=["Health"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def health() -> dict[str, str]:
    """Basic liveness probe."""
    return {"status": "ok", "service": "faultwarden"}


@router.get("/ready", status_code=status.HTTP_200_OK)
async def readiness(db: AsyncSession = Depends(get_db)) -> Any:
    """Readiness probe checking database connectivity."""
    checks: dict[str, str] = {}
    is_ready = True

    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "healthy"
    except Exception as exc:
        checks["database"] = f"unhealthy: {exc}"
        is_ready = False

    resp_body = {
        "status": "ready" if is_ready else "not_ready",
        "service": "faultwarden",
        "checks": checks,
    }

    if not is_ready:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=resp_body)

    return resp_body
