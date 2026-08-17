"""API routes for Incident Memory semantic search and retrieval."""

from fastapi import APIRouter, Depends

from faultwarden.api.dependencies import get_memory_service
from faultwarden.schemas.memory import MemorySearchQuery, MemorySearchResponse
from faultwarden.services.memory_service import MemoryService

router = APIRouter(prefix="/memory", tags=["Incident Memory"])


@router.post(
    "/search",
    response_model=MemorySearchResponse,
    summary="Search Similar Incident Memories",
    description="Search long-term incident memory for historically similar resolved incidents using semantic vector similarity.",
)
async def search_memories(
    query_data: MemorySearchQuery,
    memory_service: MemoryService = Depends(get_memory_service),
) -> MemorySearchResponse:
    """Perform semantic search across stored incident memories."""
    results = await memory_service.search_similar(
        query=query_data.query,
        service=query_data.service,
        classification=query_data.classification,
        limit=query_data.limit,
        min_similarity=query_data.min_similarity,
    )
    return MemorySearchResponse(
        results=results,
        total_found=len(results),
    )
