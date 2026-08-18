# FaultWarden Architecture Overview

**FaultWarden** is an autonomous AI SRE / Incident Response Engineer platform designed to bridge the gap between production telemetry detection and deterministic, safe remediation.

---

## 1. Core Architectural Invariants

1. **Observability systems detect incidents. LLMs do not continuously poll telemetry.**
2. **LangGraph orchestrates incident reasoning. It does not replace the domain/service layer.**
3. **The LLM is untrusted reasoning infrastructure.** Invariants, policy rules, and safety boundaries are strictly enforced in deterministic Python code.
4. **All external inputs are untrusted.** Logs, traces, Git commits, alert annotations, and tool outputs are sanitized and validated with Pydantic v2 schemas.
5. **No arbitrary shell execution capability exists or will exist.**
6. **No autonomous destructive actions.** High-risk mutations require human approval.
7. **Temporal proximity is not causation.** Operational changes are evaluated through multi-factor semantic alignment and deterministic causal gates.

---

## 2. Component Boundaries & Layering

```text
┌─────────────────────────────────────────────────────────────┐
│                      External Telemetry                     │
│  [Prometheus]  [Alertmanager]  [Loki]  [OpenTelemetry]      │
└──────────────────────────┬──────────────────────────────────┘
                           │ Webhook (POST /api/v1/alerts/alertmanager)
┌──────────────────────────▼──────────────────────────────────┐
│                         API Layer                           │
│  - /api/v1/alerts/alertmanager (Ingestion)                  │
│  - /api/v1/incidents           (Query & Lifecycle)          │
│  - /api/v1/incidents/{id}/remediations (Approval API)       │
│  - /api/v1/memory              (Semantic Search)            │
│  - /health, /ready, /metrics   (Observability)              │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                       Service Layer                         │
│  - AlertService (Webhook validation & incident mapping)     │
│  - IncidentService (CRUD & state transitions)               │
│  - InvestigationService (LangGraph execution & persistence) │
│  - RemediationAuditService (Proposals, decisions & locking) │
│  - MemoryService (pgvector indexing & similarity search)    │
│  - PostmortemService (structured postmortem generation)     │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
┌──────────────▼──────────────┐ ┌──────────────▼──────────────┐
│      Persistence Layer      │ │      LangGraph Workflow     │
│  - PostgreSQL / SQLAlchemy2 │ │  - IncidentInvestigationState│
│  - Alembic Migrations       │ │  - Classify -> Collect ->   │
│  - IncidentModel +          │ │    Recall Memory -> Collect │
│    Remediation* tables      │ │    Changes -> Correlate ->  │
│  - AsyncPostgresSaver       │ │    Hypothesize -> Verify -> │
│    (LangGraph checkpoints)  │ │    Propose -> Policy ->     │
│                              │ │    [Interrupt?] -> Execute  │
│                              │ │    -> Validate              │
└─────────────────────────────┘ └──────────────┬──────────────┘
                                               │
                                ┌──────────────▼──────────────┐
                                │    Integrations / Providers │
                                │  - MetricsProvider (PromQL) │
                                │  - LogsProvider (LogQL)     │
                                │  - LLMProvider (Reasoning)  │
                                │  - EmbeddingProvider        │
                                │    (incident memory vectors)│
                                │  - ChangeProvider (Git /    │
                                │    Deployment / Composite)  │
                                │  - Remediation Executors    │
                                │    (bounded capabilities)   │
                                └─────────────────────────────┘
```

---

## 3. Observability & Alert Flow

1. **Anomaly Detection**: Prometheus scrapes application metrics (e.g. `http_requests_total`) and evaluates alert rules.
2. **Alert Dispatch**: Prometheus sends firing alerts to Alertmanager.
3. **Webhook Ingestion**: Alertmanager dispatches a webhook to `POST /api/v1/alerts/alertmanager`.
4. **Validation & Mapping**: `AlertService` validates the payload, maps severity, and creates an `Incident` in state `DETECTED`.
5. **Workflow Trigger**: Background worker triggers the LangGraph investigation workflow.

---

## 4. Provider Boundary Abstractions

All external systems interact with FaultWarden through strictly-typed Python `Protocol` definitions:

* `MetricsProvider` (`integrations/prometheus/client.py`): Instant and range PromQL querying.
* `LogsProvider` (`integrations/loki/client.py`): LogQL querying over time intervals.
* `LLMProvider` (`integrations/llm/provider.py`): Structured reasoning operations with deterministic test fallbacks.
* `EmbeddingProvider` (`integrations/embedding/`): Vector embeddings for incident memory.
* `ChangeProvider` (`integrations/change/`): Git and deployment operational change collection.
* `Remediation Executors` (`integrations/executors/`): Bounded, typed capabilities (`DemoServiceExecutor`, `RegisteredServiceExecutor`).

---

## 5. Detailed Subsystem Documentation

For in-depth architectural specifications and implementation details, refer to the focused subsystem guides:

* **[Investigation Graph & Lifecycle](investigation_graph.md)**: State machine, LangGraph node workflow, `IncidentInvestigationState`, and durable PostgreSQL checkpointer.
* **[Remediation Safety Architecture](remediation_safety.md)**: Safety tiers (Level 0–3), deterministic policy matrix, human approval flow (`interrupt()`), bounded executors, and independent validation.
* **[Incident Memory & Postmortems](memory_and_postmortems.md)**: Semantic vector retrieval with pgvector, quality policy gates, and automated postmortem synthesis.
* **[Change Intelligence & Causal Gates](change_intelligence.md)**: Multi-factor correlation algorithm, secret redaction, and v0.5.1 deterministic causal verification gates.
* **[Demos & Walkthroughs](demos.md)**: Step-by-step guides for Level 1 auto-remediation, Level 2 approval gates, and CLI/API verification.
