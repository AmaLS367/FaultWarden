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
│  - IncidentModel +          │ │    Hypothesize -> Verify -> │
│    Remediation* tables      │ │    Propose -> Policy ->     │
│  - AsyncPostgresSaver       │ │    [Interrupt?] -> Execute  │
│    (LangGraph checkpoints)  │ │    -> Validate              │
└─────────────────────────────┘ └──────────────┬──────────────┘
                                               │
                                ┌──────────────▼──────────────┐
                                │    Integrations / Providers │
                                │  - MetricsProvider (PromQL) │
                                │  - LogsProvider (LogQL)     │
                                │  - LLMProvider (Reasoning)  │
                                │  - Remediation Executors    │
                                │    (bounded capabilities)   │
                                └─────────────────────────────┘
```

A dedicated `RemediationApi` surface (`/api/v1/incidents/{id}/remediations/...`) sits alongside the
ingestion/query API for listing and approving/rejecting paused remediations — see §6.4.

---

## 3. Observability & Alert Flow

The end-to-end incident ingestion pipeline progresses through the following steps:

1. **Anomaly Detection**: Prometheus scrapes application metrics (e.g. `http_requests_total`) and evaluates alerting rules (e.g. `DemoServiceHighErrorRate`).
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
                              [propose_remediation]     LLM proposes candidate action(s) — untrusted,
                                        │                validated into a closed ActionType registry.
                                        ▼
                        [evaluate_remediation_policy]   Deterministic policy decides ALLOWED /
                                        │                APPROVAL_REQUIRED / REJECTED. Pure — no I/O.
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
         REJECTED                   ALLOWED              APPROVAL_REQUIRED
              │                         │                         │
              │                         │                         ▼
              │                         │           [await_remediation_approval]
              │                         │              langgraph.types.interrupt() pauses the
              │                         │              graph durably; resumes on APPROVE/REJECT
              │                         │                         │
              │                         │              ┌──────────┴──────────┐
              │                         │           REJECT/CANCEL         APPROVE
              │                         │              │                     │
              │                         ▼              │                     ▼
              │              [execute_remediation] ◄────┘        [execute_remediation]
              │                         │
              │                         ▼
              │              [validate_remediation]     Independent, delayed, deterministic
              │                         │                 recovery re-check (not the executor's
              │                         │                 own immediate post-condition check).
              └─────────────────────────┼─────────────────────────┘
                                        ▼
                              [finalize_investigation]  Compiles executive summary and final status.
                                        │
                                        ▼
                                      [END]
```

See §6 for the full remediation engine (policy matrix, executors, approval API, validation semantics).

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
* `remediation_proposals`: All validated LLM proposals (accumulating) — recommendations only, most are never acted on
* `remediation_policy_result`: The deterministic policy's decision on the *primary* proposal (`AllowedAction` / `ApprovalRequiredAction` / `RejectedAction`)
* `remediation_approval_decision`: `ApprovalDecision` value, set only if the approval node ran
* `remediation_result`: `RemediationResult` from the bounded executor, if execution occurred
* `remediation_validation_passed`: `True`/`False`/`None` (`None` = nothing executed) from the independent post-remediation check
* `remediation_prior_attempt_count` / `remediation_prior_auto_execution_count`: Populated by the service layer from persisted history, never the LLM — feed the deterministic remediation limits
* `iteration_count`: Cycle count
* `missing_evidence_queries`: Targeted PromQL/LogQL queries requested by the last verification pass
* `investigation_status`: Graph-level run status (`INVESTIGATING`, `COMPLETED`, `INCONCLUSIVE`, `FAILED`)
* `summary`: Executive summary compiled by `finalize_investigation`
* `errors`: Collected execution warnings / non-fatal errors

---

## 5. Incident Domain Lifecycle

Incidents transition through the following states. `IncidentStatus` also defines `TRIAGING`,
`REMEDIATING`, and `VALIDATING` for future use, but no code path sets them today — a remediation's
execution/validation happens synchronously within one graph run, so the incident jumps straight
from `AWAITING_APPROVAL` (or directly from `INVESTIGATING`, for an auto-executed Level 1 action)
to its actual outcome rather than passing through separate persisted "in progress" states:

```text
DETECTED ──► INVESTIGATING ──┬──► ROOT_CAUSE_IDENTIFIED (no remediation proposal reached)
                              ├──► REMEDIATION_PROPOSED  (proposed, but rejected by policy/limits,
                              │                            or executed and failed validation)
                              ├──► AWAITING_APPROVAL      (Level 2 — durably paused on interrupt())
                              │           │
                              │           ├──► REMEDIATION_PROPOSED (rejected by operator, or
                              │           │                           approved but failed validation)
                              │           └──► RESOLVED             (approved, executed, validated)
                              │
                              ├──► RESOLVED               (Level 1 — auto-executed and validated
                              │                             in the same run, no approval needed)
                              └──► FAILED                 (investigation exception, or the
                                                            defensive "no output" fallback)
```

Only a **validated** recovery (`remediation_validation_passed is True`) reaches `RESOLVED` — see
§6.6.

---

## 6. Remediation Engine (v0.3)

FaultWarden evolves from "here is what I think you should do" to "I identified a remediation,
classified its risk, obtained approval if required, executed it through a bounded capability, and
verified whether the incident actually recovered." This section documents what is **actually
implemented**, not an aspirational target.

### 6.1 Trust boundary

```text
LLM (untrusted)
   │  produces RemediationActionCandidate: free-text action_type + params
   ▼
parse_remediation_proposal()            ← schemas/remediation.py
   │  validates against a CLOSED ActionType registry + per-action Pydantic parameter
   │  models (extra="forbid", Literal targets). Anything outside the registry is
   │  dropped here — it never becomes a typed RemediationProposal.
   ▼
RemediationProposal (typed, still pre-policy)
   │  proposed_risk / requires_approval on this object are the LLM's OWN suggestion —
   │  advisory only. Nothing downstream may treat them as authoritative.
   ▼
evaluate_policy()                       ← core/policy.py
   │  deterministic, pure Python. Looks up the STATIC POLICY_REGISTRY by ActionType,
   │  re-checks the target against an allow-list independent of the Pydantic Literal
   │  (defense in depth), and is total/safe against adversarially-constructed input
   │  (e.g. built via Pydantic's model_construct() to bypass normal validation).
   ▼
AllowedAction | ApprovalRequiredAction | RejectedAction
   │  policy_level / approval_required / executor are set HERE, by code, never by the LLM.
   ▼
bounded executor (capability method, not a generic command runner)
   │  target URL comes only from Settings (RemediationSettings.demo_service_url) —
   │  never from the LLM or from action parameters.
   ▼
independent validator (re-checks the target's own state, not the executor's self-report)
```

**A log line, alert annotation, or LLM hallucination saying "run shell command X" cannot become
executable authority at any point in this chain** — there is no code path that turns arbitrary
text into a callable. This is tested explicitly (`tests/unit/test_remediation_schemas.py`,
`tests/unit/test_policy_engine.py::test_llm_cannot_override_policy_risk_or_approval`,
`test_adversarial_unauthorized_target_rejected_safely`).

### 6.2 Risk levels

* **Level 0 — Read Only**: metrics/logs/traces inspection. Already part of investigation
  (`collect_initial_metrics`, `collect_initial_logs`, etc.) — not part of the remediation pipeline.
* **Level 1 — Safe Automatic**: may execute without approval, but only because it is on the closed
  `ActionType` allowlist *and* `RemediationSettings.auto_execute_max_safety_level` (default `1`)
  permits it — an operator can tighten this to `0` (nothing auto-executes) or loosen it to `2` via
  config, without touching code.
* **Level 2 — Human Approval Required**: pauses the graph via `langgraph.types.interrupt()` until
  an operator decides through the API (§6.4).
* **Level 3 — Forbidden**: not a runtime check — it's enforced by *absence*. `ActionType` is a
  closed two-member enum (`RESET_DEMO_FAILURE`, `RESTART_REGISTERED_SERVICE`). Nothing else can
  ever become a valid `RemediationProposal`, so there is no "reject list" to maintain or bypass.

### 6.3 Policy matrix (`core/policy.py::POLICY_REGISTRY`)

| ActionType                   | Policy Level | Auto-executes when...                          | Executor                                    |
| :---------------------------- | :----------: | :----------------------------------------------- | :------------------------------------------- |
| `RESET_DEMO_FAILURE`          | 1            | `auto_execute_max_safety_level >= 1` (default)  | `DemoServiceExecutor.reset_failure_mode()`  |
| `RESTART_REGISTERED_SERVICE`  | 2            | `auto_execute_max_safety_level >= 2` (non-default)| `RegisteredServiceExecutor.restart()`       |
| *(anything else)*             | —            | never — rejected before a policy level is even assigned | — |

A proposal is also **rejected regardless of type** when `RemediationSettings.enabled` is `False`,
when the target isn't in the action's `allowed_targets` set, or when the incident has already hit
`max_remediation_attempts_per_incident` / `max_auto_remediations_per_incident` (§6.7) — all
auditable via `RejectedAction.reason`, never silently dropped.

### 6.4 Approval flow & durability

* **Primary proposal selection**: an investigation run may produce several `RemediationProposal`s
  (e.g. the LLM proposing more than one candidate). v0.3 acts on exactly one — the
  highest-`proposed_risk` proposal — per run. The rest remain visible as recommendations only.
* **Interrupt**: `await_remediation_approval_node` builds a minimal `ApprovalContext` (incident,
  root cause, confidence, action type/parameters, risk level, expected effect, evidence IDs, why
  approval is required) and calls `interrupt(...)`. LangGraph's checkpointer persists the entire
  graph state at that point.
* **Checkpointer**: `AsyncPostgresSaver` (production, wired into `main.py`'s `lifespan()`) or
  `InMemorySaver` (automatic fallback when nothing has called `init_checkpointer()` — e.g. tests,
  or a SQLite-configured dev run — logged as a warning, never silent). A process restart while an
  approval is pending does not lose the paused workflow, because both the graph checkpoint *and*
  the audit-trail row (below) live in Postgres, correlated via `incidents.langgraph_thread_id`.
* **API** (`api/routes/remediations.py`, all under `/api/v1/incidents/{incident_id}/remediations`):

  | Method & Path                                   | Purpose                                                |
  | :------------------------------------------------ | :-------------------------------------------------------- |
  | `GET  /`                                          | List all remediation actions for an incident              |
  | `GET  /{remediation_id}`                          | One action, including its execution result if any         |
  | `POST /{remediation_id}/approve`                  | Approve — resumes the paused graph, executes exactly once  |
  | `POST /{remediation_id}/reject`                   | Reject — resumes the graph, nothing executes                |

  Approval approves **the exact validated action** — the request body accepts only an
  `approved_by` free-text identifier, never rewritten parameters. A double-approve, an
  approve-after-reject, or an approve on a nonexistent `remediation_id` all fail with a precise
  error (409 Conflict for state mismatches, 404 for not-found) rather than silently no-opping or
  double-executing. An approval arriving after `approval_timeout_seconds` (default 24h) is
  rejected as stale (`RemediationApprovalStaleError`) rather than acted on.
* **No authentication in v0.3** — `approved_by` is a free-text field, not a verified principal.
  This is called out explicitly in the route descriptions (visible at `/docs`). A production
  deployment must add real authenticated/authorized approvers before exposing these endpoints
  beyond a trusted network.

### 6.5 Executors — bounded capabilities, not command runners

```python
DemoServiceExecutor.reset_failure_mode(action)  # POST /debug/error-mode/false on demo-service
RegisteredServiceExecutor.restart(action)  # simulated — GET /health, honestly reported
# as a simulation (no real process control
# exists in v0.3's demo scope)
```

Both target only `RemediationSettings.demo_service_url` — trusted configuration, never LLM or
request-derived. Dispatch (`integrations/executors/__init__.py::execute_remediation_action`) is
`isinstance`-based over the typed `RemediationAction` union, not a string lookup — the `executor`
field on the persisted record is a descriptive audit label, never used for dynamic dispatch.
Bounded retries (2 additional attempts) apply only to transient connection/timeout errors; an
HTTP-level failure returns a `RemediationResult(status=FAILED, success=False)` rather than raising,
so an outcome is always recorded. **No shell execution, no Docker socket access, no arbitrary HTTP
target — these are explicitly out of scope, not "not yet implemented."**

### 6.6 Post-remediation validation

`validate_remediation_node` re-checks the target's own state independently of the executor's
immediate post-condition check, after a configurable stabilization delay
(`validation_delay_seconds`, default 5s):

* `RESET_DEMO_FAILURE` → re-queries `GET /debug/error-mode`, confirms `error_mode is False`.
* `RESTART_REGISTERED_SERVICE` → re-checks `GET /health` (its restart is a simulation, so
  "recovered" means the target is still reachable — there's no other real state to verify).

Only `remediation_validation_passed is True` resolves the incident. A remediation that executed
but failed validation leaves the incident at `REMEDIATION_PROPOSED` (active, not silently resolved
and not falsely marked terminally `FAILED`) with an explanatory `resolution` note — see
`InvestigationService._decide_terminal_status`.

### 6.7 Limits (never LLM-controlled)

| Setting                                    | Default | Effect when reached                                  |
| :------------------------------------------ | :-----: | :------------------------------------------------------ |
| `remediation_max_remediation_attempts_per_incident` | 3       | Any further proposal for that incident is `REJECTED`   |
| `remediation_max_auto_remediations_per_incident`    | 1       | Further otherwise-`ALLOWED` proposals become `REJECTED` (Level 2 approval flow is unaffected) |
| `remediation_approval_timeout_seconds`     | 86400   | A late approve/reject raises `RemediationApprovalStaleError` (409) |

Enforced in `evaluate_remediation_policy_node` from prior-attempt counts the service layer
computes from persisted history (§6.8) — the graph node itself stays pure (no DB access), reading
these counts from state rather than querying the database directly.

### 6.8 Audit trail

Three dedicated tables (migration `004_add_remediation_tables`), not a JSON blob — every proposal,
policy decision (including rejections), approval, and execution result is an addressable,
individually queryable row:

* `remediation_proposals` — immutable record of what the LLM proposed.
* `remediation_actions` — the policy decision + approval lifecycle (`decision`, `status`,
  `approved_by`, `approved_at`, `reason`). One row per `evaluate_policy()` call, for **all three**
  decision types, so rejections stay auditable rather than silently discarded.
* `remediation_results` — execution outcome (`status`, `success`, `summary`, `error`,
  `before_state`/`after_state`).

`incidents.langgraph_thread_id` correlates an incident with its LangGraph checkpoint thread for
resume.

### 6.9 Explicitly unsupported (Level 3 — forbidden, not "not yet built")

Arbitrary shell execution, arbitrary Docker/Kubernetes control, arbitrary SQL, dynamic code
execution, AI-generated scripts executed directly, automatic deployment, unrestricted HTTP
targets, secret management. These are architectural non-goals for FaultWarden generally, enforced
by the closed `ActionType` registry — not a denylist that could be bypassed by a sufficiently
clever prompt.

---

## 7. Provider Boundary Abstractions

To prevent vendor lock-in and enable isolated unit testing, external systems are accessed via Python `Protocol` contracts:

* `MetricsProvider` (`integrations/prometheus/client.py`): Instant and range PromQL querying.
* `LogsProvider` (`integrations/loki/client.py`): LogQL querying over time intervals.
* `LLMProvider` (`integrations/llm/provider.py`): Structured and text reasoning operations with deterministic test fallbacks.
* Remediation executors (`integrations/executors/`): `DemoServiceExecutor`, `RegisteredServiceExecutor` — capability-oriented methods only (§6.5), never a generic command interface.

All four are resolved via `graph/nodes/_context.py`'s config-injection pattern
(`get_metrics_provider`, `get_llm_provider_from_config`, `get_remediation_executor_from_config`,
`get_remediation_validator_from_config`): a node reads `config["configurable"][...]` if the caller
injected something (tests always do, with mocks), falling back to the real implementation
otherwise. This is also how a graph resume re-supplies providers — the checkpointer persists graph
*state*, not these live client objects, so `InvestigationService` reconstructs the same
`configurable` dict on every `ainvoke`/resume call.

---

## 8. Incident Memory & Structured Postmortems (v0.4)

### 8.1 Architectural Invariants & Trust Boundary

1. **Historical Incidents are Background Context, NEVER Current Telemetry Evidence**:
   - Historical similarity may suggest plausible candidate explanations or query patterns.
   - Historical memory cannot directly set `root_cause`, satisfy `supporting_evidence_ids` requirements, increase verified confidence by itself, bypass remediation eligibility gates, or bypass policy evaluation.
   - All hypotheses must be independently grounded in and verified by *current* telemetry evidence collected for the active incident.
   - The LLM trust boundary explicitly filters `supporting_evidence_ids` against `state["evidence"]`. Any historical incident ID returned by the model in `supporting_evidence_ids` is stripped and recorded exclusively in `historical_reference_ids`.
   - The `verify_hypothesis` node strictly enforces that a candidate cannot be verified without valid direct current evidence items.

### 8.2 Vector Memory & Indexing Quality Policy

- **Storage Engine**: PostgreSQL + pgvector extension (`Vector(384)` embeddings).
  - In unit tests / SQLite fallback, cosine similarity is computed directly in pure Python using canonical vector math without external dependencies.
- **Deterministic Quality Policy Gate (`is_eligible_for_memory`)**:
  - An incident is indexed into `incident_memories` if and only if:
    1. Incident status is strictly `RESOLVED`.
    2. Incident has at least 1 verified current evidence item.
    3. Incident has a verified `root_cause` with `confidence >= threshold`.
    4. Incident has an executed remediation action and a passed post-remediation validation.
  - Non-resolved, inconclusive, or failed incidents are rejected from long-term memory to prevent poisoning future investigations.
- **Idempotency**: Indexing the same incident repeatedly returns the existing memory row without duplicating vector records.

### 8.3 Structured Postmortems

- Automatically triggered upon transition to `IncidentStatus.RESOLVED`.
- Reconstructs a chronological, factual incident timeline from persisted database state:
  1. Incident detected & alert webhook received.
  2. Investigation started.
  3. Telemetry evidence collected (metrics/logs).
  4. Root cause verified.
  5. Remediation proposed & policy evaluated.
  6. Operator approval requested / granted (if Level 2).
  7. Remediation executed.
  8. Post-remediation telemetry validated.
  9. Incident marked resolved.
- Synthesizes executive summary, root cause explanation, contributing factors, what went well, what went wrong, prevention action items, and lessons learned using structured LLM generation with deterministic heuristic fallback.

---

## 9. Running the Demos

Both demos below were verified against the real Docker Compose stack (real PostgreSQL + pgvector, real
`AsyncPostgresSaver` checkpointer, real demo-service HTTP calls) — not just unit tests.

```bash
docker compose up -d --build
# wait for `faultwarden` and `demo-service` to report healthy: docker compose ps
```

### Level 1 — auto-executed remediation (no approval)

By default, the demo LLM (`MockLLMProvider`) always proposes both a Level 1 and a Level 2
candidate, and FaultWarden acts on the *higher-risk* one as primary (§6.4) — so a default run
naturally exercises the Level 2 path. To see Level 1 auto-execution specifically, either raise
`FAULTWARDEN_REMEDIATION_AUTO_EXECUTE_MAX_SAFETY_LEVEL=2` (so the Level-2-primary proposal itself
auto-executes, exercising the identical "no interrupt, straight to execute→validate→resolve" code
path) or use a real LLM provider that proposes only a Level 1 action for this scenario.

```bash
curl -X POST http://localhost:8001/debug/error-mode/true      # trigger the fault
# wait ~15-30s for Prometheus -> Alertmanager -> webhook -> Incident (DETECTED)
curl http://localhost:8000/api/v1/incidents
# background investigation auto-triggers; poll until status is RESOLVED:
curl http://localhost:8000/api/v1/incidents/{incident_id}
curl http://localhost:8000/api/v1/incidents/{incident_id}/remediations   # decision=ALLOWED, result.success=true
curl http://localhost:8000/api/v1/incidents/{incident_id}/postmortem     # structured postmortem with timeline
curl http://localhost:8000/api/v1/incidents/{incident_id}/memory         # compact indexed vector memory
```

### Level 2 — human approval required

```bash
curl -X POST http://localhost:8001/debug/error-mode/true
# ... incident reaches AWAITING_APPROVAL ...
curl http://localhost:8000/api/v1/incidents/{incident_id}/remediations
# {"decision": "APPROVAL_REQUIRED", "status": "AWAITING_APPROVAL", "result": null, ...}

# Approve:
curl -X POST http://localhost:8000/api/v1/incidents/{incident_id}/remediations/{remediation_id}/approve \
  -H "Content-Type: application/json" -d '{"approved_by": "you@example.com"}'
# -> resumes the paused graph, executes exactly once, validates, incident -> RESOLVED

# Or reject (separate run): result stays null, executor never runs, incident stays active.
curl -X POST http://localhost:8000/api/v1/incidents/{incident_id}/remediations/{remediation_id}/reject \
  -H "Content-Type: application/json" -d '{"approved_by": "you@example.com"}'
```

### Incident Memory Search & Similar Incidents

```bash
# Query similar historical incidents for active incident:
curl http://localhost:8000/api/v1/incidents/{incident_id}/similar

# Cross-incident semantic search across long-term memory:
curl -X POST http://localhost:8000/api/v1/memory/search \
  -H "Content-Type: application/json" \
  -d '{"query": "Database connection pool exhausted under spike", "service": "demo-service", "limit": 5}'
```

Reset the environment: `curl -X POST http://localhost:8001/debug/error-mode/false`.
