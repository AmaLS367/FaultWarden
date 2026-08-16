"""Prometheus client and MetricsProvider protocol."""

from datetime import datetime
from typing import Any, Protocol, runtime_checkable

import httpx

from faultwarden.core.config import PrometheusSettings, get_settings
from faultwarden.core.exceptions import PrometheusError
from faultwarden.core.logging import get_logger
from faultwarden.schemas.evidence import MetricData, MetricDataPoint

logger = get_logger("faultwarden.integrations.prometheus")


# --- Provider Protocol ---
@runtime_checkable
class MetricsProvider(Protocol):
    """Abstract interface for metrics querying."""

    async def query(self, expr: str, time: datetime | None = None) -> list[MetricData]:
        """Execute an instant PromQL query."""
        ...

    async def query_range(
        self,
        expr: str,
        start: datetime,
        end: datetime,
        step: str = "15s",
    ) -> list[MetricData]:
        """Execute a range PromQL query."""
        ...

    async def check_health(self) -> bool:
        """Check provider reachability."""
        ...


# --- Concrete Client Implementation ---
class PrometheusClient(MetricsProvider):
    """Concrete Prometheus metrics provider using httpx."""

    def __init__(self, settings: PrometheusSettings | None = None) -> None:
        self._settings = settings or get_settings().prometheus
        self._base_url = self._settings.url.rstrip("/")
        self._timeout = self._settings.timeout_seconds

    async def _get_client(self) -> httpx.AsyncClient:
        """Build an httpx client bound to the configured Prometheus base URL."""
        return httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout)

    async def check_health(self) -> bool:
        """Verify Prometheus HTTP API is accessible."""
        try:
            async with httpx.AsyncClient(base_url=self._base_url, timeout=3.0) as client:
                resp = await client.get("/-/healthy")
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("prometheus_health_check_failed", error=str(exc))
            return False

    async def query(self, expr: str, time: datetime | None = None) -> list[MetricData]:
        """Execute instant PromQL query."""
        params: dict[str, Any] = {"query": expr}
        if time:
            params["time"] = time.isoformat()

        try:
            async with await self._get_client() as client:
                resp = await client.get("/api/v1/query", params=params)
                if resp.status_code != 200:
                    raise PrometheusError(f"HTTP {resp.status_code}: {resp.text}", resp.status_code)
                data = resp.json()
        except httpx.RequestError as exc:
            raise PrometheusError(f"Connection failed: {exc}") from exc

        return self._parse_result(expr, data)

    async def query_range(
        self,
        expr: str,
        start: datetime,
        end: datetime,
        step: str = "15s",
    ) -> list[MetricData]:
        """Execute range PromQL query."""
        params: dict[str, str | float] = {
            "query": expr,
            "start": start.timestamp(),
            "end": end.timestamp(),
            "step": step,
        }

        try:
            async with await self._get_client() as client:
                resp = await client.get("/api/v1/query_range", params=params)
                if resp.status_code != 200:
                    raise PrometheusError(f"HTTP {resp.status_code}: {resp.text}", resp.status_code)
                data = resp.json()
        except httpx.RequestError as exc:
            raise PrometheusError(f"Connection failed: {exc}") from exc

        return self._parse_result(expr, data)

    def _parse_result(self, query: str, payload: dict[str, Any]) -> list[MetricData]:
        """Flatten Prometheus's vector/matrix response shape into MetricData objects."""
        results: list[MetricData] = []
        if payload.get("status") != "success":
            return results

        data = payload.get("data", {})
        result_type = data.get("resultType")
        raw_items = data.get("result", [])

        for item in raw_items:
            metric_labels = item.get("metric", {})
            values: list[MetricDataPoint] = []

            if result_type == "vector":
                val = item.get("value", [0, "0"])
                values.append(
                    MetricDataPoint(
                        timestamp=datetime.fromtimestamp(float(val[0])),
                        value=float(val[1]),
                    )
                )
            elif result_type == "matrix":
                for val in item.get("values", []):
                    values.append(
                        MetricDataPoint(
                            timestamp=datetime.fromtimestamp(float(val[0])),
                            value=float(val[1]),
                        )
                    )

            results.append(
                MetricData(
                    query=query,
                    labels=metric_labels,
                    values=values,
                    summary=f"Result for {query} with {len(values)} points",
                )
            )

        return results
