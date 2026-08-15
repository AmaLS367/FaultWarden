"""Pydantic schemas for Alertmanager webhook integration."""

from datetime import datetime

from pydantic import BaseModel, Field


class AlertItem(BaseModel):
    """Individual alert representation from Alertmanager."""

    status: str = Field(description="Alert status: 'firing' or 'resolved'")
    labels: dict[str, str] = Field(
        default_factory=dict, description="Prometheus label key-value pairs"
    )
    annotations: dict[str, str] = Field(
        default_factory=dict, description="Informative annotations (summary, description, runbook)"
    )
    startsAt: datetime | str = Field(description="Timestamp when the alert started firing")
    endsAt: datetime | str | None = Field(
        default=None, description="Timestamp when the alert resolved"
    )
    generatorURL: str | None = Field(
        default=None, description="Direct URL to Prometheus expression"
    )
    fingerprint: str | None = Field(
        default=None, description="Unique fingerprint for deduplication"
    )

    @property
    def alertname(self) -> str:
        """Return the `alertname` label, or a fallback if it is missing."""
        return self.labels.get("alertname", "UnknownAlert")

    @property
    def severity(self) -> str:
        """Return the `severity` label upper-cased, defaulting to medium."""
        return self.labels.get("severity", "medium").upper()

    @property
    def summary(self) -> str:
        """Return the summary annotation, falling back to description, then the alert name."""
        return self.annotations.get("summary", self.annotations.get("description", self.alertname))


class AlertmanagerPayload(BaseModel):
    """Standard Prometheus Alertmanager webhook payload schema."""

    version: str = Field(default="4", description="Alertmanager webhook protocol version")
    groupKey: str = Field(description="Key identifying the alert group")
    truncatedAlerts: int = Field(
        default=0, description="Count of truncated alerts if group is huge"
    )
    status: str = Field(description="Group status: 'firing' or 'resolved'")
    receiver: str = Field(description="Alertmanager receiver route name")
    groupLabels: dict[str, str] = Field(
        default_factory=dict, description="Labels grouping the alerts"
    )
    commonLabels: dict[str, str] = Field(
        default_factory=dict, description="Labels shared by all alerts"
    )
    commonAnnotations: dict[str, str] = Field(
        default_factory=dict, description="Annotations shared by all alerts"
    )
    externalURL: str = Field(default="", description="Base URL of Alertmanager instance")
    alerts: list[AlertItem] = Field(
        default_factory=list, description="List of alerts in this notification"
    )

    @property
    def primary_alertname(self) -> str:
        """Return the group's alert name, falling back to the first alert's, then a default."""
        if self.commonLabels.get("alertname"):
            return self.commonLabels["alertname"]
        if self.alerts:
            return self.alerts[0].alertname
        return "UnknownAlert"

    @property
    def primary_severity(self) -> str:
        """Return the group's severity, falling back to the first alert's, then a default."""
        if self.commonLabels.get("severity"):
            return self.commonLabels["severity"].upper()
        if self.alerts:
            return self.alerts[0].severity
        return "MEDIUM"


class AlertIngestResponse(BaseModel):
    """Response returned upon successful webhook ingestion."""

    status: str = "received"
    incident_id: str
    incident_title: str
    incident_status: str
    alerts_count: int
