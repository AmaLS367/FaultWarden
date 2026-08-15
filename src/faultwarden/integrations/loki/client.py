"""Grafana Loki client and LogsProvider protocol."""

from datetime import datetime
from typing import Any, Protocol, runtime_checkable

import httpx

from faultwarden.core.config import LokiSettings, get_settings
from faultwarden.core.exceptions import LokiError
from faultwarden.core.logging import get_logger
from faultwarden.schemas.evidence import LogEntry

logger = get_logger("faultwarden.integrations.loki")


@runtime_checkable
class LogsProvider(Protocol):
    """Abstract interface for log querying."""

    async def query_range(
        self,
        query: str,
        start: datetime,
        end: datetime,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Execute a LogQL query over a time range."""
        ...

    async def check_health(self) -> bool:
        """Check Loki reachability."""
        ...


class LokiClient(LogsProvider):
    """Concrete Loki logs provider using httpx."""

    def __init__(self, settings: LokiSettings | None = None) -> None:
        self._settings = settings or get_settings().loki
        self._base_url = self._settings.url.rstrip("/")
        self._timeout = self._settings.timeout_seconds

    async def check_health(self) -> bool:
        """Check if Loki is ready."""
        try:
            async with httpx.AsyncClient(base_url=self._base_url, timeout=3.0) as client:
                resp = await client.get("/ready")
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("loki_health_check_failed", error=str(exc))
            return False

    async def query_range(
        self,
        query: str,
        start: datetime,
        end: datetime,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Query Loki using LogQL."""
        # Convert datetime to nanoseconds since Unix epoch
        start_ns = int(start.timestamp() * 1e9)
        end_ns = int(end.timestamp() * 1e9)

        params: dict[str, Any] = {
            "query": query,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(limit),
            "direction": "BACKWARD",
        }

        try:
            async with httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout) as client:
                resp = await client.get("/loki/api/v1/query_range", params=params)
                if resp.status_code != 200:
                    raise LokiError(f"HTTP {resp.status_code}: {resp.text}", resp.status_code)
                data = resp.json()
        except httpx.RequestError as exc:
            raise LokiError(f"Connection failed: {exc}") from exc

        return self._parse_result(data)

    def _parse_result(self, payload: dict[str, Any]) -> list[LogEntry]:
        """Flatten Loki's stream/values response shape into LogEntry objects."""
        entries: list[LogEntry] = []
        if payload.get("status") != "success":
            return entries

        data = payload.get("data", {})
        streams = data.get("result", [])

        for stream in streams:
            stream_labels = stream.get("stream", {})
            values = stream.get("values", [])
            for val in values:
                # val is [timestamp_ns_string, log_line]
                ts_ns = int(val[0])
                ts = datetime.fromtimestamp(ts_ns / 1e9)
                message = val[1]
                entries.append(
                    LogEntry(
                        timestamp=ts,
                        level=stream_labels.get("level", "INFO").upper(),
                        message=message,
                        labels=stream_labels,
                    )
                )

        return entries
