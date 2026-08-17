"""Protocol definition for read-only Change Intelligence providers."""

from datetime import datetime
from typing import Protocol, runtime_checkable

from faultwarden.schemas.change import OperationalChange


# --- Change Provider Protocol ---
@runtime_checkable
class ChangeProvider(Protocol):
    """Abstract read-only interface for retrieving recent operational changes."""

    async def list_changes(
        self,
        service: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 50,
    ) -> list[OperationalChange]:
        """Fetch operational changes occurring within the specified time window for a target service."""
        ...
