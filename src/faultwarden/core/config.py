"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# --- Component Settings Models ---
class ServerSettings(BaseModel):
    """HTTP server and application runtime settings."""

    host: str = Field(default="0.0.0.0", description="Bind host for HTTP server")
    port: int = Field(default=8000, description="Bind port for HTTP server")
    env: Literal["development", "staging", "production", "test"] = Field(
        default="development", description="Environment stage"
    )
    debug: bool = Field(default=False, description="Debug mode flag")
    log_level: str = Field(
        default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )


class DatabaseSettings(BaseModel):
    """PostgreSQL async database connection settings."""

    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, description="Database port")
    user: str = Field(default="faultwarden", description="Database username")
    password: str = Field(default="faultwarden_secret", description="Database password")
    name: str = Field(default="faultwarden", description="Database name")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Max overflow connections")
    echo: bool = Field(default=False, description="SQLAlchemy query echo")
    url_override: str | None = Field(
        default=None, description="Explicit database URL override (e.g., for SQLite in tests)"
    )

    @property
    def async_url(self) -> str:
        """Return the fully formed async connection string."""
        if self.url_override:
            return self.url_override
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
        )

    @property
    def sync_url(self) -> str:
        """Return the sync connection string for Alembic migrations."""
        if self.url_override:
            # Replace async driver for sync alembic if needed
            return self.url_override.replace("+asyncpg", "").replace("+aiosqlite", "")
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class PrometheusSettings(BaseModel):
    """Prometheus integration settings."""

    url: str = Field(default="http://localhost:9090", description="Prometheus base URL")
    timeout_seconds: float = Field(default=10.0, description="HTTP request timeout in seconds")


class LokiSettings(BaseModel):
    """Grafana Loki log ingestion settings."""

    url: str = Field(default="http://localhost:3100", description="Loki base URL")
    timeout_seconds: float = Field(default=10.0, description="HTTP request timeout in seconds")


class LLMSettings(BaseModel):
    """LLM provider settings for investigation reasoning."""

    provider: str = Field(
        default="openai", description="LLM provider name (e.g. openai, anthropic, mock)"
    )
    model: str = Field(default="gpt-4o", description="Target model identifier")
    api_key: str = Field(default="", description="API key for LLM provider")
    base_url: str | None = Field(
        default=None, description="Custom base URL for OpenAI-compatible LLM endpoints"
    )
    temperature: float = Field(default=0.1, description="Sampling temperature")
    max_tokens: int = Field(default=4096, description="Max response tokens")


class InvestigationSettings(BaseModel):
    """LangGraph AI incident investigation settings."""

    max_iterations: int = Field(
        default=3, description="Maximum bounded loop iterations for evidence collection"
    )
    confidence_threshold: float = Field(
        default=0.75, description="Minimum confidence score required to verify root cause"
    )
    metrics_lookback_minutes: int = Field(
        default=15, description="Lookback window in minutes for metrics queries"
    )
    logs_lookback_minutes: int = Field(
        default=15, description="Lookback window in minutes for logs queries"
    )
    logs_limit: int = Field(default=100, description="Max log lines to fetch from Loki per query")


class RemediationSettings(BaseModel):
    """Deterministic policy and execution limits for the remediation engine (never LLM-controlled)."""

    enabled: bool = Field(default=True, description="Master switch for the remediation pipeline")
    auto_execute_max_safety_level: int = Field(
        default=1,
        ge=0,
        le=2,
        description="Actions at or below this RemediationSafetyLevel auto-execute; above require approval",
    )
    approval_timeout_seconds: int = Field(
        default=86400, description="How long a paused approval waits before going stale"
    )
    max_remediation_attempts_per_incident: int = Field(
        default=3, description="Hard cap on remediation attempts per incident"
    )
    max_auto_remediations_per_incident: int = Field(
        default=1, description="Hard cap on Level-1 auto-executions per incident"
    )
    execution_timeout_seconds: float = Field(default=15.0, description="Executor HTTP call timeout")
    validation_delay_seconds: float = Field(
        default=5.0, description="Stabilization wait before post-remediation validation"
    )
    validation_window_seconds: float = Field(
        default=30.0, description="Telemetry lookback window for validation checks"
    )
    min_root_cause_confidence: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score required for an incident to be eligible for remediation",
    )
    recovery_error_rate_threshold: float = Field(
        default=0.01,
        ge=0.0,
        description="Maximum 5xx error rate threshold (req/s) allowed for successful recovery validation",
    )
    job_lease_seconds: int = Field(
        default=120,
        ge=10,
        description="Lease timeout duration in seconds for running investigation jobs",
    )
    job_max_attempts: int = Field(
        default=3,
        ge=1,
        description="Maximum retry attempts for an investigation job before marking it FAILED",
    )
    worker_enabled: bool = Field(
        default=True,
        description="Whether to run the embedded durable job worker in the FastAPI process lifespan",
    )
    worker_poll_interval_seconds: float = Field(
        default=1.0,
        ge=0.1,
        description="Polling interval in seconds for the durable job worker",
    )
    demo_service_url: str = Field(
        default="http://demo-service:8001",
        description="Trusted, config-only target for demo-service executor calls",
    )


class TelemetrySettings(BaseModel):
    """OpenTelemetry and application monitoring settings."""

    service_name: str = Field(default="faultwarden", description="OpenTelemetry service name")
    otlp_endpoint: str = Field(
        default="http://localhost:4317", description="OTLP gRPC/HTTP collector endpoint"
    )
    enable_metrics: bool = Field(default=True, description="Enable Prometheus metrics endpoint")


# --- Root Application Settings ---
class Settings(BaseSettings):
    """Root configuration object loading from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="FAULTWARDEN_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    env: Literal["development", "staging", "production", "test"] = "development"
    debug: bool = False
    log_level: str = "INFO"

    # --- Database ---
    db_host: str = "localhost"
    db_port: int = 5432
    db_user: str = "faultwarden"
    db_password: str = "faultwarden_secret"
    db_name: str = "faultwarden"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False
    database_url: str | None = None

    # --- Prometheus ---
    prometheus_url: str = "http://localhost:9090"
    prometheus_timeout_seconds: float = 10.0

    # --- Loki ---
    loki_url: str = "http://localhost:3100"
    loki_timeout_seconds: float = 10.0

    # --- LLM ---
    llm_provider: str = "openai"
    llm_model: str = "gpt-4o"
    llm_api_key: str = ""
    llm_base_url: str | None = None
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096

    # --- Investigation ---
    investigation_max_iterations: int = 3
    investigation_confidence_threshold: float = 0.75
    investigation_metrics_lookback_minutes: int = 15
    investigation_logs_lookback_minutes: int = 15
    investigation_logs_limit: int = 100

    # --- Remediation ---
    remediation_enabled: bool = True
    remediation_auto_execute_max_safety_level: int = 1
    remediation_approval_timeout_seconds: int = 86400
    remediation_max_remediation_attempts_per_incident: int = 3
    remediation_max_auto_remediations_per_incident: int = 1
    remediation_execution_timeout_seconds: float = 15.0
    remediation_validation_delay_seconds: float = 5.0
    remediation_validation_window_seconds: float = 30.0
    remediation_min_root_cause_confidence: float = 0.75
    remediation_recovery_error_rate_threshold: float = 0.01
    remediation_job_lease_seconds: int = 120
    remediation_job_max_attempts: int = 3
    remediation_worker_enabled: bool = True
    remediation_worker_poll_interval_seconds: float = 1.0
    remediation_demo_service_url: str = "http://demo-service:8001"

    # --- Telemetry ---
    otel_service_name: str = "faultwarden"
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    enable_metrics: bool = True

    # --- CORS ---
    cors_origins: str = Field(
        default="*",
        description=(
            "Comma-separated list of allowed CORS origins, or '*' to allow all "
            "(dev only — credentials are disabled automatically when wildcarded, "
            "since browsers reject '*' combined with credentialed requests)."
        ),
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Return the configured CORS origins as a list."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def server(self) -> ServerSettings:
        """Return the grouped server/runtime settings."""
        return ServerSettings(
            host=self.host,
            port=self.port,
            env=self.env,
            debug=self.debug,
            log_level=self.log_level,
        )

    @property
    def database(self) -> DatabaseSettings:
        """Return the grouped database connection settings."""
        return DatabaseSettings(
            host=self.db_host,
            port=self.db_port,
            user=self.db_user,
            password=self.db_password,
            name=self.db_name,
            pool_size=self.db_pool_size,
            max_overflow=self.db_max_overflow,
            echo=self.db_echo,
            url_override=self.database_url,
        )

    @property
    def prometheus(self) -> PrometheusSettings:
        """Return the grouped Prometheus integration settings."""
        return PrometheusSettings(
            url=self.prometheus_url,
            timeout_seconds=self.prometheus_timeout_seconds,
        )

    @property
    def loki(self) -> LokiSettings:
        """Return the grouped Loki integration settings."""
        return LokiSettings(
            url=self.loki_url,
            timeout_seconds=self.loki_timeout_seconds,
        )

    @property
    def llm(self) -> LLMSettings:
        """Return the grouped LLM provider settings."""
        return LLMSettings(
            provider=self.llm_provider,
            model=self.llm_model,
            api_key=self.llm_api_key,
            base_url=self.llm_base_url,
            temperature=self.llm_temperature,
            max_tokens=self.llm_max_tokens,
        )

    @property
    def investigation(self) -> InvestigationSettings:
        """Return the grouped investigation settings."""
        return InvestigationSettings(
            max_iterations=self.investigation_max_iterations,
            confidence_threshold=self.investigation_confidence_threshold,
            metrics_lookback_minutes=self.investigation_metrics_lookback_minutes,
            logs_lookback_minutes=self.investigation_logs_lookback_minutes,
            logs_limit=self.investigation_logs_limit,
        )

    @property
    def remediation(self) -> RemediationSettings:
        """Return the grouped remediation engine settings."""
        return RemediationSettings(
            enabled=self.remediation_enabled,
            auto_execute_max_safety_level=self.remediation_auto_execute_max_safety_level,
            approval_timeout_seconds=self.remediation_approval_timeout_seconds,
            max_remediation_attempts_per_incident=self.remediation_max_remediation_attempts_per_incident,
            max_auto_remediations_per_incident=self.remediation_max_auto_remediations_per_incident,
            execution_timeout_seconds=self.remediation_execution_timeout_seconds,
            validation_delay_seconds=self.remediation_validation_delay_seconds,
            validation_window_seconds=self.remediation_validation_window_seconds,
            min_root_cause_confidence=self.remediation_min_root_cause_confidence,
            recovery_error_rate_threshold=self.remediation_recovery_error_rate_threshold,
            job_lease_seconds=self.remediation_job_lease_seconds,
            job_max_attempts=self.remediation_job_max_attempts,
            worker_enabled=self.remediation_worker_enabled,
            worker_poll_interval_seconds=self.remediation_worker_poll_interval_seconds,
            demo_service_url=self.remediation_demo_service_url,
        )

    @property
    def telemetry(self) -> TelemetrySettings:
        """Return the grouped telemetry/observability settings."""
        return TelemetrySettings(
            service_name=self.otel_service_name,
            otlp_endpoint=self.otel_exporter_otlp_endpoint,
            enable_metrics=self.enable_metrics,
        )


# --- Accessor Factory ---
@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
