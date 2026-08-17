"""Composite Change Provider aggregating multiple change sources."""

import asyncio
from datetime import datetime

from faultwarden.core.logging import get_logger
from faultwarden.integrations.change.base import ChangeProvider
from faultwarden.schemas.change import OperationalChange

logger = get_logger("faultwarden.integrations.change.composite")


# --- Composite Provider Implementation ---
class CompositeChangeProvider:
    """Aggregates Git, deployment, and environment change providers into a unified stream."""

    def __init__(self, providers: list[ChangeProvider]) -> None:
        self.providers = providers

    async def list_changes(
        self,
        service: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 50,
    ) -> list[OperationalChange]:
        """Query all registered change providers concurrently and return merged, deduplicated changes."""
        if not self.providers:
            return []

        tasks = [
            provider.list_changes(
                service=service,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
            )
            for provider in self.providers
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        combined: list[OperationalChange] = []
        seen_ids: set[str] = set()

        for idx, res in enumerate(results):
            if isinstance(res, BaseException):
                logger.warning(
                    "composite_change_provider_subtask_failed",
                    provider_index=idx,
                    error=str(res),
                )
                continue
            if isinstance(res, list):
                for change in res:
                    if change.id not in seen_ids:
                        seen_ids.add(change.id)
                        combined.append(change)

        # Sort chronologically by timestamp (most recent first)
        combined.sort(key=lambda c: c.timestamp, reverse=True)

        return combined[:limit]
