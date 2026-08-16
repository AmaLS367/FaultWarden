"""Grafana Loki client and LogsProvider protocol."""

from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

import httpx

from faultwarden.core.config import LokiSettings, get_settings
from faultwarden.core.exceptions import LokiError
from faultwarden.core.logging import get_logger
from faultwarden.schemas.evidence import LogEntry

logger = get_logger("faultwarden.integrations.loki")


# --- Provider Protocol ---
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

    async def get_service_logs(
        self,
        service_name: str,
        start: datetime,
        end: datetime,
        level: str | None = None,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Query logs for a given service with optional log level filtering."""
        ...


# --- Concrete Client Implementation ---
class LokiClient(LogsProvider):
    """Concrete Loki logs provider using httpx."""

    def __init__(self, settings: LokiSettings | None = None) -> None:
        self._settings = settings or get_settings().loki
        self._base_url = self._settings.url.rstrip("/")
        self._timeout = self._settings.timeout_seconds

    # --- Health Check ---
    async def check_health(self) -> bool:
        """Check if Loki is ready."""
        try:
            async with httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout) as client:
                resp = await client.get("/ready")
                return resp.status_code == 200
        except Exception as exc:
            logger.debug("loki_health_check_failed", error=str(exc))
            return False

    # --- Direct LogQL Range Query ---
    async def query_range(
        self,
        query: str,
        start: datetime,
        end: datetime,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Query Loki using LogQL with bounded time limits and volume caps."""
        # Enforce maximum query range of 2 hours to avoid unbounded scans
        max_duration = timedelta(hours=2)
        if (end - start) > max_duration:
            start = end - max_duration

        # Clamp limit to prevent excessive memory consumption
        clamped_limit = max(1, min(limit, 500))

        start_ns = int(start.timestamp() * 1e9)
        end_ns = int(end.timestamp() * 1e9)

        params: dict[str, Any] = {
            "query": query,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(clamped_limit),
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

    # --- Bounded Domain Query Helpers ---
    async def get_service_logs(
        self,
        service_name: str,
        start: datetime,
        end: datetime,
        level: str | None = None,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Query logs for a given service with optional log level filtering."""
        clean_service = service_name.replace('"', "").replace("'", "").strip()
        # Filter by the `level` stream label rather than a body text search (`|= "ERROR"`):
        # log producers (e.g. demo_service) attach level as a Loki stream label, and the log
        # body itself often does not contain the literal level name.
        level_selector = f', level="{level.lower().strip()}"' if level else ""
        query = f'{{service="{clean_service}"{level_selector}}}'

        try:
            return await self.query_range(query, start, end, limit=limit)
        except Exception:
            # Fallback to job label if service label yields nothing or fails
            job_query = f'{{job="{clean_service}"{level_selector}}}'
            return await self.query_range(job_query, start, end, limit=limit)

    # --- Result Parsing ---
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
                ts = datetime.fromtimestamp(ts_ns / 1e9, tz=UTC)
                message = val[1]
                level = stream_labels.get("level", "INFO").upper()
                if "ERROR" in message.upper() or "EXCEPTION" in message.upper():
                    level = "ERROR"
                elif "WARN" in message.upper():
                    level = "WARNING"

                entries.append(
                    LogEntry(
                        timestamp=ts,
                        level=level,
                        message=message,
                        labels=stream_labels,
                    )
                )

        return entries
