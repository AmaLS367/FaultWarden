# FaultWarden

[![CI](https://github.com/AmaLS367/FaultWarden/actions/workflows/ci.yml/badge.svg)](https://github.com/AmaLS367/FaultWarden/actions/workflows/ci.yml)
[![Docker](https://github.com/AmaLS367/FaultWarden/actions/workflows/docker.yml/badge.svg)](https://github.com/AmaLS367/FaultWarden/actions/workflows/docker.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**FaultWarden** is an autonomous AI SRE / Incident Response Engineer platform. It connects with modern production observability infrastructure (Prometheus, Alertmanager, Loki, OpenTelemetry) to receive alerts, orchestrate stateful investigations via **LangGraph**, generate verified root-cause hypotheses, and propose tier-classified remediations.

---

## Current Status

> [!NOTE]
> **v0.3 Milestone — Remediation Engine**: On top of v0.1's detection pipeline and v0.2's
> LangGraph investigation, FaultWarden now proposes, deterministically classifies, optionally
> gates behind durable human approval (real LangGraph `interrupt()`/resume backed by PostgreSQL),
> executes through a tiny set of bounded capabilities, and independently validates whether an
> incident actually recovered before ever marking it resolved. See
> [docs/ARCHITECTURE.md §6](docs/ARCHITECTURE.md#6-remediation-engine-v03) for the full design —
> trust boundary, policy matrix, approval API, executors, validation semantics, and limits.

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
├── .github/workflows/         # CI/CD pipelines (ci.yml, docker.yml)
├── src/
│   └── faultwarden/
│       ├── api/               # FastAPI routers: /health, /alerts, /incidents, /incidents/{id}/remediations
│       ├── core/              # Pydantic Settings, structlog logging, domain exceptions, policy engine
│       ├── db/                # SQLAlchemy 2 async engine, sessionmaker, ORM models (Incident + Remediation*)
│       ├── schemas/           # Pydantic v2 domain schemas (Incidents, Alerts, Evidence, Hypotheses, Remediation)
│       ├── graph/             # LangGraph state machine, nodes, checkpointer, and workflow builder
│       ├── services/          # Business logic layer (IncidentService, AlertService, InvestigationService,
│       │                      #   RemediationAuditService)
│       ├── integrations/      # Provider boundaries & protocols (Prometheus, Loki, LLM, remediation executors)
│       └── telemetry/         # OpenTelemetry setup boundary & Prometheus metrics
│
├── demo_service/              # Breakable demo service with deterministic error simulation (/debug/error-mode)
├── observability/             # Configs for Prometheus, Alertmanager, Loki, Grafana, OpenTelemetry Collector
├── migrations/                # Alembic async database migrations
├── tests/                     # Unit and integration test suite (pytest + pytest-asyncio)
├── docs/                      # ARCHITECTURE.md (Deep dive into safety models and graph flow)
├── docker-compose.yml         # 9-service local development stack
├── Dockerfile                 # Multi-stage production container build
├── pyproject.toml             # Dependencies and strict tool configuration (Ruff, Mypy, Pytest)
├── LICENSE                    # Apache 2.0 License
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
git clone https://github.com/AmaLS367/FaultWarden.git
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

Start the full 9-service observability stack (FaultWarden, Demo Service, Traffic Generator, PostgreSQL, Prometheus, Alertmanager, Loki, Grafana, OpenTelemetry Collector):

```bash
docker compose up -d --build
```

### Service Map

| Service                           | URL / Port                | Description                               |
| :-------------------------------- | :------------------------ | :---------------------------------------- |
| **FaultWarden API**         | `http://localhost:8000` | Incident response orchestrator            |
| **Demo Service**            | `http://localhost:8001` | Breakable sample microservice             |
| **Traffic Generator**       | *(internal)*              | Automatic background traffic loop (1 req/s)|
| **Prometheus**              | `http://localhost:9090` | Metrics collection and alerting           |
| **Alertmanager**            | `http://localhost:9093` | Alert grouping and webhook routing        |
| **Loki**                    | `http://localhost:3100` | Log stream ingestion                      |
| **Grafana**                 | `http://localhost:3000` | Visual dashboards (`admin` / `admin`) |
| **OpenTelemetry Collector** | `http://localhost:4317` | OTLP gRPC telemetry endpoint              |
| **PostgreSQL**              | `localhost:5432`        | Incident storage database                 |

---

## End-to-End Demo Procedure

With the stack running (`docker compose up -d`), background traffic is automatically generated against `demo-service`.

1. **Check initial state (Healthy)**:

   ```bash
   curl http://localhost:8001/health
   # Returns: {"status": "ok", "service": "demo-service"}
   ```

2. **Trigger intentional failure** in the demo service:

   ```bash
   curl -X POST http://localhost:8001/debug/error-mode/true
   # Returns: {"status": "updated", "error_mode": true, ...}
   ```

3. **Observe automatic incident creation**:
   - Background requests begin returning HTTP 500.
   - Prometheus records elevated `http_requests_total{status="500"}`.
   - Prometheus rule `DemoServiceHighErrorRate` fires.
   - Alertmanager forwards the webhook to FaultWarden.
   - FaultWarden idempotently creates a persisted Incident in PostgreSQL.

   ```bash
   # Wait ~15-20s, then query incidents API:
   curl http://localhost:8000/api/v1/incidents
   ```

4. **Watch the investigation and remediation run automatically**:

   Background investigation auto-triggers on incident creation. Poll until the status stops
   changing:

   ```bash
   curl http://localhost:8000/api/v1/incidents/{incident_id}
   ```

   It lands on one of: `RESOLVED` (a Level 1 action auto-executed and validation confirmed
   recovery), `AWAITING_APPROVAL` (a Level 2 action is durably paused, waiting on you — see step 5),
   or `REMEDIATION_PROPOSED` (proposed but rejected by policy, or executed but validation didn't
   confirm recovery — nothing to approve, inspect `GET .../remediations` for why).

5. **If paused on `AWAITING_APPROVAL`, approve or reject it**:

   ```bash
   curl http://localhost:8000/api/v1/incidents/{incident_id}/remediations
   # find the remediation_id with status AWAITING_APPROVAL

   curl -X POST http://localhost:8000/api/v1/incidents/{incident_id}/remediations/{remediation_id}/approve \
     -H "Content-Type: application/json" -d '{"approved_by": "you@example.com"}'
   # resumes the paused LangGraph workflow, executes exactly once, validates, and (if recovery is
   # confirmed) transitions the incident to RESOLVED
   ```

   See [docs/ARCHITECTURE.md §8](docs/ARCHITECTURE.md#8-running-the-demos) for both the Level 1
   (auto-executed) and Level 2 (approval-gated) walkthroughs in full, including the rejection path.

6. **Disable error mode and observe recovery**:

   ```bash
   curl -X POST http://localhost:8001/debug/error-mode/false
   # Returns: {"status": "updated", "error_mode": false, ...}
   ```

   Prometheus resolves the alert condition, Alertmanager sends a resolved webhook, and FaultWarden updates `alert_status="resolved"`.


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

FaultWarden enforces a strict, deterministic safety architecture: the LLM only ever *proposes* —
normal code decides and executes. A closed two-action registry (`RESET_DEMO_FAILURE`,
`RESTART_REGISTERED_SERVICE`) is all that can ever run; everything else (shell, Docker, SQL,
arbitrary HTTP, dynamic code) is out of scope by construction, not by a denylist.

* **Level 0 — Read Only (Autonomous)**: metrics/logs/traces inspection — part of investigation, not remediation.
* **Level 1 — Safe Automatic Remediation**: may auto-execute, bounded by config
  (`auto_execute_max_safety_level`, remediation attempt/auto-execution limits).
* **Level 2 — Human Approval Required**: durably paused via a real LangGraph `interrupt()`
  (survives a process restart), resumed through the approval API.
* **Level 3 — Forbidden**: enforced by the closed action registry, not a runtime check.

Every remediation is independently validated after execution — an incident is only marked
`RESOLVED` once a deterministic re-check confirms actual recovery, never on the strength of "the
executor call returned 200" alone. Full audit trail: every proposal, policy decision (including
rejections), approval, and execution result is a queryable database row.

See [docs/ARCHITECTURE.md §6](docs/ARCHITECTURE.md#6-remediation-engine-v03) for the complete
architecture (trust boundary, policy matrix, approval API, executors, validation semantics) and
[§8](docs/ARCHITECTURE.md#8-running-the-demos) for runnable Level 1/Level 2 walkthroughs.

---

## License

FaultWarden is open-source software licensed under the [Apache 2.0 License](LICENSE).
