"""Read-only deployment and configuration change provider querying deployment history."""

from datetime import UTC, datetime

import httpx

from faultwarden.core.logging import get_logger
from faultwarden.schemas.change import (
    ChangeType,
    DeploymentRecord,
    OperationalChange,
)

logger = get_logger("faultwarden.integrations.change.deployment")

HTTP_TIMEOUT_SECONDS: float = 5.0


# --- Deployment Change Provider Implementation ---
class DeploymentChangeProvider:
    """Read-only provider querying deployment history and config diffs from environment registry."""

    def __init__(
        self,
        endpoint_url: str = "http://demo-service:8001/deployments",
        timeout_seconds: float = HTTP_TIMEOUT_SECONDS,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.timeout_seconds = timeout_seconds
        self._client = client
        self._transport = transport

    async def list_changes(
        self,
        service: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 50,
    ) -> list[OperationalChange]:
        """Fetch historical deployment and config change records from the deployment registry."""
        params: dict[str, str | int] = {
            "service": service,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "limit": limit,
        }

        try:
            if self._client is not None:
                resp = await self._client.get(self.endpoint_url, params=params)
            else:
                async with httpx.AsyncClient(
                    timeout=self.timeout_seconds, transport=self._transport
                ) as client:
                    resp = await client.get(self.endpoint_url, params=params)

            if resp.status_code != 200:
                logger.warning(
                    "deployment_provider_non_200_response",
                    endpoint=self.endpoint_url,
                    status_code=resp.status_code,
                )
                return []

            raw_items = resp.json()
            if not isinstance(raw_items, list):
                logger.warning(
                    "deployment_provider_invalid_response_format",
                    endpoint=self.endpoint_url,
                )
                return []

            changes: list[OperationalChange] = []
            for item in raw_items:
                record = DeploymentRecord.model_validate(item)

                # Normalize timestamp
                record_ts = record.completed_at or record.started_at

                # Check window boundaries
                # Convert to UTC or naive matching if needed
                ts_for_check = record_ts
                st_for_check = start_time
                et_for_check = end_time
                if ts_for_check.tzinfo is None and st_for_check.tzinfo is not None:
                    ts_for_check = ts_for_check.replace(tzinfo=UTC)

                if not (st_for_check <= ts_for_check <= et_for_check):
                    continue

                # Determine change type (DEPLOYMENT or CONFIGURATION)
                ch_type = (
                    ChangeType.CONFIGURATION
                    if record.config_changes and not record.commit_sha
                    else ChangeType.DEPLOYMENT
                )

                operational_change = OperationalChange(
                    id=f"deploy-{record.id}",
                    source="deployment_registry",
                    change_type=ch_type,
                    service=record.service,
                    timestamp=record_ts,
                    actor=record.metadata.get("actor", "ci/cd"),
                    version=record.version,
                    commit_sha=record.commit_sha,
                    deployment_id=record.id,
                    title=f"Deployment {record.id} ({record.version})",
                    description=record.metadata.get(
                        "description", f"Deployment of version {record.version}"
                    ),
                    metadata=record.metadata,
                    files_changed=record.metadata.get("files_changed", []),
                    config_changes=record.config_changes,
                    previous_version=record.metadata.get("previous_version"),
                    new_version=record.version,
                )
                changes.append(operational_change)

            logger.info(
                "deployment_changes_retrieved",
                service=service,
                count=len(changes),
                endpoint=self.endpoint_url,
            )
            return changes

        except httpx.ConnectError:
            logger.info(
                "deployment_provider_endpoint_unreachable_continuing",
                endpoint=self.endpoint_url,
            )
            return []
        except Exception as exc:
            logger.warning(
                "deployment_provider_query_failed",
                endpoint=self.endpoint_url,
                error=str(exc),
            )
            return []
