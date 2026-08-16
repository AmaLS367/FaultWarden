"""API router aggregation."""

from fastapi import APIRouter

from faultwarden.api.routes.alerts import router as alerts_router
from faultwarden.api.routes.health import router as health_router
from faultwarden.api.routes.incidents import router as incidents_router
from faultwarden.api.routes.remediations import router as remediations_router

# --- Sub-Router Aggregation ---
api_router = APIRouter()

# Health endpoints available at both /health and /api/v1/health
api_router.include_router(health_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(remediations_router)
