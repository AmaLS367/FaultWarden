# FaultWarden Architecture Documentation

## 1. System Overview

**FaultWarden** is an autonomous AI SRE / Incident Response Engineer designed to bridge the gap between production telemetry detection and deterministic, safe remediation.

### Core Architectural Invariants
1. **Observability systems detect incidents. LLMs do not continuously monitor telemetry.**
2. **LangGraph orchestrates incident investigation. It does not replace the domain/service layer.**
3. **The LLM is untrusted reasoning infrastructure. Critical invariants and safety boundaries are enforced strictly in deterministic Python code.**
4. **Raw logs, traces, external text, Git commits, and tool responses are treated as untrusted input.**
5. **No arbitrary shell execution capability exists or will exist.**
6. **No autonomous destructive actions.**

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
│  - /health, /ready, /metrics   (Observability)              │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                       Service Layer                         │
│  - AlertService (Webhook validation & incident mapping)     │
│  - IncidentService (CRUD & state transitions)               │
│  - InvestigationService (LangGraph execution & persistence) │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
┌──────────────▼──────────────┐ ┌──────────────▼──────────────┐
│      Persistence Layer      │ │      LangGraph Workflow     │
│  - PostgreSQL / SQLAlchemy2 │ │  - IncidentInvestigationState│
│  - Alembic Migrations       │ │  - Classify -> Collect ->   │
│  - IncidentModel            │ │    Hypothesize -> Verify -> │
│                             │ │    Propose Remediation      │
└─────────────────────────────┘ └──────────────┬──────────────┘
                                               │
                                ┌──────────────▼──────────────┐
                                │    Integrations / Providers │
                                │  - MetricsProvider (PromQL) │
                                │  - LogsProvider (LogQL)     │
                                │  - LLMProvider (Reasoning)  │
                                └─────────────────────────────┘
```

---

## 3. Observability & Alert Flow

The end-to-end incident ingestion pipeline progresses through the following steps:

1. **Anomaly Detection**: Prometheus scrapes application metrics (e.g. `demo_http_requests_total`) and evaluates alerting rules (e.g. `High5xxRate`).
2. **Alert Dispatch**: Prometheus sends firing alerts to Alertmanager.
3. **Webhook Ingestion**: Alertmanager invokes the FaultWarden webhook:
   ```text
   POST http://faultwarden:8000/api/v1/alerts/alertmanager
   ```
4. **Validation & Normalization**: `AlertService` parses the payload with Pydantic v2 `AlertmanagerPayload` schema, maps severity levels, and creates an `Incident` in state `DETECTED`.
5. **Database Persistence**: The incident is committed into PostgreSQL using asynchronous SQLAlchemy 2 (`IncidentModel`).
6. **Workflow Dispatch**: The incident triggers the LangGraph stateful investigation workflow.

---

## 4. LangGraph Incident Investigation Workflow

The investigation graph is compiled using `langgraph.graph.StateGraph` with a strictly typed `IncidentInvestigationState`:

```text
[START]
   │
   ▼
[classify_incident]            Extracts alert labels, assigns severity, identifies target service.
   │
   ▼
[collect_initial_metrics]      Queries MetricsProvider (Prometheus) for the incident window.
   │
   ▼
[collect_initial_logs]         Queries LogsProvider (Loki) for the incident window.
   │
   ▼
[correlate_evidence]           Cross-references collected metrics and logs into unified evidence items.
   │
   ▼
[generate_hypotheses] ◄──────────────────────────────┐
   │                                                  │
   ▼                                                  │
[verify_hypothesis]                                   │
   │                                                   │
   ├─ root cause verified OR max iterations OR         │
   │  no missing queries ──────────────┐               │
   │                                   │               │
   └─ evidence insufficient            │               │
      │                                │               │
      ▼                                │               │
[collect_additional_telemetry] ────────┘ (loop back)   │
      └──────────────────────────────────────────────┘
                                        │
                                        ▼
                              [propose_remediation]     Generates tier-classified remediation actions
                                        │                (Safe vs. Approval Required).
                                        ▼
                              [finalize_investigation]  Compiles executive summary and final status.
                                        │
                                        ▼
                                      [END]
```

### LangGraph State Schema (`IncidentInvestigationState`)
* `incident_id`: Unique incident UUID
* `alert`: Raw and normalized alert payload
* `incident_context`: Lightweight incident context (title, severity, service) passed into the graph
* `classification`: `IncidentClassification` determined by `classify_incident`
* `evidence`: Accumulated evidence items (`MetricData`, `LogEntry`, `TraceSpan`, `DeploymentEvent`)
* `metrics`: Time-series query results
* `logs`: Log stream extractions
* `traces`: Distributed trace spans
* `recent_changes`: Deployment and config changes
* `hypotheses`: Candidate hypotheses list
* `selected_hypothesis`: Verified winning hypothesis
* `root_cause`: Final structured `RootCauseAnalysis`
* `remediation_proposals`: Remediation proposals with safety classification
* `iteration_count`: Cycle count
* `missing_evidence_queries`: Targeted PromQL/LogQL queries requested by the last verification pass
* `investigation_status`: Graph-level run status (`INVESTIGATING`, `COMPLETED`, `INCONCLUSIVE`, `FAILED`)
* `summary`: Executive summary compiled by `finalize_investigation`
* `errors`: Collected execution warnings / non-fatal errors

---

## 5. Incident Domain Lifecycle

Incidents transition through a deterministic lifecycle:

```text
DETECTED ──► TRIAGING ──► INVESTIGATING ──► ROOT_CAUSE_IDENTIFIED
                                                    │
                                                    ▼
RESOLVED ◄── VALIDATING ◄── REMEDIATING ◄── REMEDIATION_PROPOSED
    │                                               │
    ▼                                               ▼
 (Success)                                  AWAITING_APPROVAL
                                                    │
                                                    ▼
                                                 FAILED
```

---

## 6. Future Remediation Safety Model

Remediations in FaultWarden are governed by a strict 3-tier safety policy. Autonomous agents may **never** bypass human approval for actions classified above their authorization tier.

### Level 0 — Read Only (Autonomous)
Safe, non-mutating inspection operations.
* Inspect PromQL metrics and Grafana dashboards.
* Query Loki logs and OpenTelemetry traces.
* Inspect Kubernetes pod status, deployment history, container metrics.
* Check database connection pool statistics and replica lag.

### Level 1 — Safe Automatic Remediation (Autonomous within bounds)
Low-risk, idempotent, self-healing actions.
* Restart a crashing background worker or container.
* Re-trigger an idempotent failed batch task.
* Clear an explicitly configured disposable Redis/Memcached cache.
* Scale pod replica counts within predefined min/max boundaries.
* Toggle debug error simulation flags off in test/demo environments.

### Level 2 — Human Approval Required (Manual Gate)
High-impact, stateful, or disruptive operations requiring operator sign-off.
* Rollback production deployment to a previous container tag.
* Modify environment variables or infrastructure configuration.
* Restart primary database instance or failover cluster.
* Mutate persistent database records or execute schema migrations.
* Provision or deprovision infrastructure resources.
* Deploy unreviewed hotfix code.

---

## 7. Provider Boundary Abstractions

To prevent vendor lock-in and enable isolated unit testing, external systems are accessed via Python `Protocol` contracts:

* `MetricsProvider` (`integrations/prometheus/client.py`): Instant and range PromQL querying.
* `LogsProvider` (`integrations/loki/client.py`): LogQL querying over time intervals.
* `LLMProvider` (`integrations/llm/provider.py`): Structured and text reasoning operations with deterministic test fallbacks.
