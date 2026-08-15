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

---

## 5. Comment Conventions

FaultWarden uses four distinct comment forms. Never mix them — each form signals something
different to the reader. See `src/faultwarden/main.py` for a reference implementation.

1. **Function docstrings** — a one-line summary in triple quotes directly under the
   `def`/`async def` line:

   ```python
   def create_engine(settings: DatabaseSettings) -> AsyncEngine:
       """SQLite URLs should produce an engine without pool sizing kwargs."""
   ```
   For non-trivial functions, extend the docstring with further explanatory sentences
   after the summary line.
2. **Zone markers** — three dashes on each side, marking a major logical section of a
   file (e.g. a group of related routes, middleware, or handlers):

   ```python
   # --- Exception Handlers ---
   ```
3. **Sub-zone markers** — a single leading dash, marking a subsection inside a zone. A
   sub-zone marker is only valid nested under a preceding `# --- ... ---` zone marker; it
   must never appear on its own without an enclosing zone. If a group of related lines
   deserves a label but has no enclosing zone, give it its own zone marker instead of a
   bare sub-zone marker:

   ```python
   # --- Routers ---
   # Direct top-level health & metrics endpoints
   app.include_router(health_router)
   ...

   # - API v1 routes
   app.include_router(api_router, prefix="/api/v1")
   ```
4. **Plain comments** — a short, single-line explanation of a specific line or block,
   with no dash decoration, used when neither a docstring nor a zone marker applies:

   ```python
   # Initialize tables automatically when running with SQLite (e.g. dev/tests)
   ```

### When to Add a Comment

* **A function contains two or more zones** — delimit each with a zone marker so the
  boundaries are visible at a glance (`main.py`'s `create_app()` is the reference: CORS,
  Middleware, Exception Handlers, Routers).
* **A decision is non-typical** — a workaround, a deliberate deviation from the "obvious"
  approach, a spec quirk (e.g. disabling CORS credentials on a wildcard origin): explain
  *why* right there. The next reader can't reconstruct that reasoning from the code alone.
* **A hidden constraint or invariant governs correctness** — must run before X, must stay
  sorted, can't exceed Y: call it out, since nothing in the code's shape signals it.
* **A workaround exists for something outside this codebase** — a library bug, a platform
  limitation, a third-party API quirk: note what is being worked around, so it doesn't get
  "cleaned up" later and the bug comes back.
* **Comments explain *why*, never *what*** — if a comment only restates what the code
  already says, delete it; a well-named function or variable already covers that.
* **Don't comment the obvious** — no comment beats one that just echoes the line below it.
