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
    """LLM provider settings (for future investigation nodes)."""

    provider: str = Field(
        default="openai", description="LLM provider name (e.g. openai, anthropic)"
    )
    model: str = Field(default="gpt-4o", description="Target model identifier")
    api_key: str = Field(default="", description="API key for LLM provider")
    temperature: float = Field(default=0.1, description="Sampling temperature")
    max_tokens: int = Field(default=4096, description="Max response tokens")


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
    llm_model: str = "gpt-5.6"
    llm_api_key: str = ""
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096

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
            temperature=self.llm_temperature,
            max_tokens=self.llm_max_tokens,
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
