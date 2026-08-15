# FaultWarden

[![CI](https://github.com/faultwarden/faultwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/faultwarden/faultwarden/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**FaultWarden** is an autonomous AI SRE / Incident Response Engineer platform. It connects with modern production observability infrastructure (Prometheus, Alertmanager, Loki, OpenTelemetry) to receive alerts, orchestrate stateful investigations via **LangGraph**, generate verified root-cause hypotheses, and propose tier-classified remediations.

---

## Current Status

> [!NOTE]
> **Scaffold Phase**: The core production architecture, domain models, database persistence, Alertmanager webhook pipeline, LangGraph state machine, provider boundaries, and complete observability stack are fully implemented and tested. Real LLM automated reasoning and auto-remediations are scheduled for upcoming milestones.

---

## v0.1 Target Milestone

The immediate end-to-end milestone target is:

```text
Broken FastAPI demo service (error injection)
              ↓
Prometheus detects elevated 5xx rate
              ↓
Alertmanager sends webhook to FaultWarden
              ↓
FaultWarden creates Incident (state: DETECTED)
              ↓
LangGraph investigation workflow starts
              ↓
Collects metrics, logs, and telemetry context
              ↓
Generates and verifies root-cause hypothesis
              ↓
Produces tier-classified remediation proposal
```

---

## Repository Architecture

```text
faultwarden/
├── src/
│   └── faultwarden/
│       ├── api/               # FastAPI routers, dependencies, endpoints (/health, /alerts, /incidents)
│       ├── core/              # Pydantic Settings, structlog logging, domain exceptions
│       ├── db/                # SQLAlchemy 2 async engine, sessionmaker, and ORM models
│       ├── schemas/           # Pydantic v2 domain schemas (Incidents, Alerts, Evidence, Hypotheses, Remediations)
│       ├── graph/             # LangGraph state machine, nodes, and workflow builder
│       ├── services/          # Business logic layer (IncidentService, AlertService)
│       ├── integrations/      # Provider boundaries & protocols (Prometheus, Loki, LLM)
│       └── telemetry/         # OpenTelemetry setup boundary & Prometheus metrics
│
├── demo_service/              # Breakable demo service with deterministic error simulation (/debug/error-mode)
├── observability/             # Configs for Prometheus, Alertmanager, Loki, Grafana, OpenTelemetry Collector
├── migrations/                # Alembic async database migrations
├── tests/                     # Unit and integration test suite (pytest + pytest-asyncio)
├── docs/                      # ARCHITECTURE.md (Deep dive into safety models and graph flow)
├── docker-compose.yml         # 8-service local development stack
├── pyproject.toml             # Dependencies and strict tool configuration (Ruff, Mypy, Pytest)
└── AGENTS.md                  # Development guidelines for AI coding agents
```

---

## Quick Start (Local Development)

### 1. Prerequisites

* Python 3.12+
* [uv](https://docs.astral.sh/uv/) for Python package and environment management
* Docker and Docker Compose (optional for full observability stack)

### 2. Setup Environment

```bash
# Clone the repository
git clone https://github.com/faultwarden/faultwarden.git
cd FaultWarden

# Create virtual environment and install dependencies
uv sync --all-extras --dev

# Copy example environment configuration
cp .env.example .env
```

### 3. Run Locally with SQLite (Fast dev mode)

```bash
# overrides the PostgreSQL default below and auto-creates tables on startup
export FAULTWARDEN_DATABASE_URL="sqlite+aiosqlite:///./faultwarden.db"
uv run uvicorn faultwarden.main:app --reload --port 8000
```

> [!NOTE]
> Without `FAULTWARDEN_DATABASE_URL`, FaultWarden defaults to PostgreSQL (matching
> the Docker Compose stack) and `/ready` will report the database as unhealthy
> until a PostgreSQL instance matching `FAULTWARDEN_DB_*` is reachable.

API Documentation will be available at: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Running with Docker Compose

Start the full 8-service observability stack (FaultWarden, Demo Service, PostgreSQL, Prometheus, Alertmanager, Loki, Grafana, OpenTelemetry Collector):

```bash
docker compose up -d --build
```

### Service Map

| Service                           | URL / Port                | Description                               |
| :-------------------------------- | :------------------------ | :---------------------------------------- |
| **FaultWarden API**         | `http://localhost:8000` | Incident response orchestrator            |
| **Demo Service**            | `http://localhost:8001` | Breakable sample microservice             |
| **Prometheus**              | `http://localhost:9090` | Metrics collection and alerting           |
| **Alertmanager**            | `http://localhost:9093` | Alert grouping and webhook routing        |
| **Loki**                    | `http://localhost:3100` | Log stream ingestion                      |
| **Grafana**                 | `http://localhost:3000` | Visual dashboards (`admin` / `admin`) |
| **OpenTelemetry Collector** | `http://localhost:4317` | OTLP gRPC telemetry endpoint              |
| **PostgreSQL**              | `localhost:5432`        | Incident storage database                 |

---

## Simulating an Incident

1. **Trigger Error Injection** in the demo service:

   ```bash
   curl -X POST http://localhost:8001/debug/error-mode/true
   ```
2. **Generate Traffic** to trigger 500 errors:

   ```bash
   for i in {1..20}; do curl -s http://localhost:8001/ ; sleep 0.5; done
   ```
3. **Prometheus & Alertmanager** will detect elevated 5xx errors and send a webhook to FaultWarden:

   ```bash
   # Check incidents in FaultWarden
   curl http://localhost:8000/api/v1/incidents
   ```
4. **Recover the Demo Service**:

   ```bash
   curl -X POST http://localhost:8001/debug/error-mode/false
   ```

---

## Testing & Code Quality

```bash
# Run Ruff lint check & autofix
uv run ruff check .

# Run Ruff code format check
uv run ruff format --check .

# Run Mypy strict type checking
uv run mypy src

# Run test suite with coverage
uv run pytest -v --cov=src
```

---

## Remediation Safety Model

FaultWarden enforces a strict 3-tier safety architecture:

* **Level 0 — Read Only (Autonomous)**: Inspect metrics, logs, traces, container stats.
* **Level 1 — Safe Automatic Remediation (Autonomous within bounds)**: Restart crashing workers, rerun idempotent tasks, clear caches, scale replicas.
* **Level 2 — Human Approval Required (Manual Gate)**: Rollback deployments, alter configs, restart databases, mutate persistent data.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full architectural specifications.
