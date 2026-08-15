# AGENTS.md — Instructions for AI Coding Agents

Welcome to **FaultWarden**. This repository contains the scaffold and core implementation for an autonomous AI SRE / Incident Response Engineer.

When modifying this repository, you **MUST** strictly adhere to the rules, boundaries, and standards outlined below.

---

## 1. Non-Negotiable Invariants

1. **Observability detects; LLMs investigate**: Do not create continuous polling loops inside LLM agents. Telemetry systems (Prometheus, Loki, Alertmanager) trigger incident workflows.
2. **LangGraph orchestrates reasoning, not domain state**: LangGraph drives hypothesis testing and remediation proposal flows. Core CRUD, API contracts, and database persistence belong strictly in the Service and DB layers.
3. **LLM outputs are untrusted**: Validate all LLM and external provider responses using Pydantic models. Never execute unvalidated commands or parameters.
4. **No arbitrary shell execution**: FaultWarden never uses raw `subprocess` or unrestricted shell execution to remediate incidents. All actions must map to typed `RemediationAction` definitions.
5. **Enforce Remediation Safety Tiers**: Never execute Level 2 actions (rollbacks, database mutations, infrastructure modifications) without explicit operator approval (`AWAITING_APPROVAL` status).

---

## 2. Repository Layout

* `src/faultwarden/api/`: FastAPI routes, dependency injection, and router aggregation.
* `src/faultwarden/core/`: Configuration (`BaseSettings`), structured logging (`structlog`), and domain exception hierarchy.
* `src/faultwarden/db/`: SQLAlchemy 2 async engine, declarative base, and models (`IncidentModel`).
* `src/faultwarden/schemas/`: Pydantic v2 domain schemas (`AlertmanagerPayload`, `IncidentRead`, `EvidenceItem`, `Hypothesis`, `RemediationProposal`).
* `src/faultwarden/graph/`: LangGraph `StateGraph`, `IncidentInvestigationState`, and deterministic node definitions.
* `src/faultwarden/services/`: Business logic (`IncidentService`, `AlertService`).
* `src/faultwarden/integrations/`: Provider boundary protocols (`MetricsProvider`, `LogsProvider`, `LLMProvider`) and concrete clients.
* `src/faultwarden/telemetry/`: OpenTelemetry setup boundary and Prometheus `/metrics` registry.
* `demo_service/`: Standalone breakable FastAPI service exposing `/health`, `/debug/error-mode/{enabled}`, and `/metrics`.
* `observability/`: Prometheus, Alertmanager, Loki, Grafana, and OpenTelemetry collector configurations.
* `migrations/`: Alembic database migration scripts.

---

## 3. Development Commands

### Dependency Management & Environment
```bash
uv sync --all-extras --dev
```

### Formatting & Linting
```bash
# Run Ruff linting
uv run ruff check . --fix

# Run Ruff formatting check
uv run ruff format --check .
```

### Static Type Checking
```bash
# Strict Mypy type validation
uv run mypy src
```

### Running Test Suite
```bash
# Run full pytest suite
uv run pytest -v
```

### Docker Compose
```bash
# Verify configuration
docker compose config

# Start entire stack
docker compose up -d --build
```

---

## 4. Coding Conventions

* **Python Version**: Python 3.12+ features (e.g. `type[X]`, `X | None`, `StrEnum`, `IntEnum`).
* **Strict Typing**: All functions, methods, and classes must have explicit type annotations. Do not use unannotated `*args` or `**kwargs`.
* **Async I/O**: Network requests (httpx) and database queries (SQLAlchemy AsyncSession) must be asynchronous.
* **No Global Mutable State**: Inject database sessions and provider clients using FastAPI dependencies (`Depends(...)`).
* **Error Handling**: Raise domain exceptions (`IncidentNotFoundError`, `InvalidAlertPayloadError`, `ProviderError`) and let the global exception handlers format the HTTP response.
