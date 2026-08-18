# LangGraph Investigation Workflow & Lifecycle

This document describes the stateful investigation engine in FaultWarden, orchestrated via LangGraph, its state machine transitions, and checkpointer persistence.

---

## 1. Investigation Workflow Architecture

The investigation graph is compiled using `langgraph.graph.StateGraph` with a strictly typed `IncidentInvestigationState`. It coordinates telemetry gathering, memory recall, change intelligence, hypothesis verification, remediation policy evaluation, and validation loops.

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
[retrieve_incident_memory]     Recalls similar historical incidents as background context —
   │                            never treated as current evidence.
   ▼
[collect_recent_changes]       Queries ChangeProvider (Git/Deployment) for operational changes
   │                            near the incident window.
   ▼
[correlate_evidence]           Cross-references collected metrics, logs, and recent changes into
   │                            unified evidence items and change-correlation scores.
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

---

## 2. State Schema (`IncidentInvestigationState`)

The graph state flows through all nodes and is persisted at interrupt points:

* `incident_id`: Unique incident UUID (`uuid.UUID`).
* `alert`: Raw and normalized alert payload (`AlertPayload`).
* `incident_context`: Lightweight incident context (title, severity, service) passed into the graph.
* `classification`: `IncidentClassification` determined by `classify_incident`.
* `evidence`: Accumulated evidence items (`MetricData`, `LogEntry`, `TraceSpan`, `DeploymentEvent`).
* `metrics`: Time-series query results.
* `logs`: Log stream extractions.
* `traces`: Distributed trace spans.
* `recent_changes`: Operational and configuration changes collected within the window.
* `hypotheses`: Candidate hypotheses list evaluated during the investigation.
* `selected_hypothesis`: Verified winning hypothesis.
* `root_cause`: Final structured `RootCauseAnalysis` containing verified causal factors.
* `remediation_proposals`: All validated LLM proposals (accumulating) — recommendations only.
* `remediation_policy_result`: Deterministic policy decision (`AllowedAction` / `ApprovalRequiredAction` / `RejectedAction`).
* `remediation_approval_decision`: `ApprovalDecision` value, set only if the approval node ran.
* `remediation_result`: `RemediationResult` from the bounded executor, if execution occurred.
* `remediation_validation_passed`: `True` / `False` / `None` (`None` = nothing executed) from the post-remediation check.
* `remediation_prior_attempt_count` / `remediation_prior_auto_execution_count`: Populated by the service layer from persisted database history to feed deterministic remediation limits.
* `iteration_count`: Cycle count for the hypothesis verification loop.
* `missing_evidence_queries`: Targeted PromQL/LogQL queries requested by verification passes.
* `investigation_status`: Graph-level run status (`INVESTIGATING`, `COMPLETED`, `INCONCLUSIVE`, `FAILED`).
* `summary`: Executive summary compiled by `finalize_investigation`.
* `errors`: Collected execution warnings / non-fatal errors.

---

## 3. Incident Domain Lifecycle

Incidents transition through strict domain states in PostgreSQL:

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

### State Definitions

1. **`DETECTED`**: Alert webhook validated and incident persisted in database.
2. **`INVESTIGATING`**: LangGraph workflow active and evaluating telemetry/hypotheses.
3. **`ROOT_CAUSE_IDENTIFIED`**: Investigation verified the root cause, but no remediation proposal was formulated.
4. **`AWAITING_APPROVAL`**: Level 2 remediation action evaluated; graph paused durably via `interrupt()`.
5. **`REMEDIATION_PROPOSED`**: Remediation proposed but rejected by policy/limits, rejected by operator, or executed but failed recovery validation.
6. **`RESOLVED`**: Remediation executed and **independently validated** as recovered (`remediation_validation_passed is True`). Triggers postmortem generation and vector memory indexing.
7. **`FAILED`**: Unrecoverable error in investigation pipeline.

---

## 4. Durable Checkpointing

* **Production**: `AsyncPostgresSaver` backed by PostgreSQL (`checkpoints` and `checkpoint_writes` tables). Durably preserves graph state during Level 2 approval pauses (`interrupt()`), surviving container restarts and worker crashes.
* **Development / Testing**: `InMemorySaver` automatic fallback when PostgreSQL checkpointer is uninitialized (e.g. SQLite test runs).
* **Correlation**: The graph checkpoint thread ID is persisted in `incidents.langgraph_thread_id` to reliably resume executions upon operator approval.
