# Remediation Engine & Safety Architecture

FaultWarden enforces a strict, deterministic safety model: the LLM only ever *proposes* remediations — typed Python code decides, approves, executes, and validates them.

---

## 1. Trust Boundary

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

> [!IMPORTANT]
> **A log line, alert annotation, or LLM hallucination saying "run shell command X" cannot become executable authority at any point in this chain.** There is no code path that executes arbitrary text or shell commands.

---

## 2. Safety Tiers & Risk Levels

* **Level 0 — Read Only (Autonomous)**: metrics/logs/traces inspection. Executed as part of the investigation phase (`collect_initial_metrics`, `collect_initial_logs`), not the remediation pipeline.
* **Level 1 — Safe Automatic**: may auto-execute without operator approval, bounded by config (`RemediationSettings.auto_execute_max_safety_level >= 1`, default `1`) and rate limits.
* **Level 2 — Human Approval Required**: pauses the graph via `langgraph.types.interrupt()` until an operator approves or rejects the action via the REST API.
* **Level 3 — Forbidden**: enforced by *absence* in the closed `ActionType` registry (`RESET_DEMO_FAILURE`, `RESTART_REGISTERED_SERVICE`).

---

## 3. Deterministic Policy Matrix (`POLICY_REGISTRY`)

| ActionType                   | Policy Level | Auto-executes when...                               | Executor                                    |
| :---------------------------- | :----------: | :-------------------------------------------------- | :------------------------------------------- |
| `RESET_DEMO_FAILURE`          | 1            | `auto_execute_max_safety_level >= 1` (default)       | `DemoServiceExecutor.reset_failure_mode()`  |
| `RESTART_REGISTERED_SERVICE`  | 2            | `auto_execute_max_safety_level >= 2` (non-default)   | `RegisteredServiceExecutor.restart()`       |
| *(anything else)*             | —            | never — rejected before a policy level is assigned   | — |

### Rejection Conditions
A proposal is rejected regardless of type when:
1. `RemediationSettings.enabled` is `False`.
2. The target service is not in the action's configured `allowed_targets` allowlist.
3. Incident has reached `remediation_max_remediation_attempts_per_incident` or `remediation_max_auto_remediations_per_incident`.

All rejections are recorded in the database audit log with an explicit `RejectedAction.reason`.

---

## 4. Approval Flow & Durability

1. **Primary Selection**: Exactly one primary proposal is selected per graph iteration according to risk priority.
2. **Durable Interrupt**: `await_remediation_approval_node` constructs an `ApprovalContext` and calls `interrupt()`. LangGraph's checkpointer saves the entire graph state into PostgreSQL.
3. **Approval API Surface**:

   | Method & Path                                              | Purpose                                                |
   | :--------------------------------------------------------- | :----------------------------------------------------- |
   | `GET  /api/v1/incidents/{id}/remediations`                 | List all remediation actions and audit history         |
   | `GET  /api/v1/incidents/{id}/remediations/{remediation_id}`| Retrieve single action with execution result           |
   | `POST /api/v1/incidents/{id}/remediations/{remediation_id}/approve` | Approve action and resume graph execution     |
   | `POST /api/v1/incidents/{id}/remediations/{remediation_id}/reject`  | Reject action and terminate remediation path |

4. **Idempotency & Claiming**:
   - Double approvals or approvals on finalized/rejected actions return `409 Conflict`.
   - Approvals received after `remediation_approval_timeout_seconds` (default 24h) raise `RemediationApprovalStaleError`.
   - Atomic state locking prevents double execution across parallel worker nodes.

---

## 5. Bounded Executors

Executors map strictly to typed capabilities:

```python
DemoServiceExecutor.reset_failure_mode(action)  # POST /debug/error-mode/false
RegisteredServiceExecutor.restart(action)  # Simulated capability
```

* **Zero Shell Execution**: No `subprocess.Popen`, no `/bin/sh`, no Docker socket binding.
* **Target Isolation**: URLs and endpoints originate strictly from strongly-typed server settings, never from LLM payloads.
* **Bounded Retries**: Maximum 2 retries on transient connection failures; HTTP errors return `RemediationResult(status=FAILED, success=False)`.

---

## 6. Post-Remediation Validation

After execution and an stabilization delay (`validation_delay_seconds`, default 5.0s), `validate_remediation_node` re-checks the target service independently of the executor's immediate response:

* `RESET_DEMO_FAILURE` → queries `GET /debug/error-mode`, verifies `error_mode is False`.
* `RESTART_REGISTERED_SERVICE` → queries `GET /health`, verifies service reachability.

> [!NOTE]
> An incident is marked `RESOLVED` **only** if independent validation passes (`remediation_validation_passed is True`). If execution succeeds but validation fails, the incident remains at `REMEDIATION_PROPOSED` for operator review.

---

## 7. Safety Limits

| Setting | Default | Effect when reached |
| :--- | :---: | :--- |
| `remediation_max_remediation_attempts_per_incident` | `3` | All further proposals rejected |
| `remediation_max_auto_remediations_per_incident` | `1` | Further `ALLOWED` proposals become `REJECTED` (Level 2 approvals unaffected) |
| `remediation_approval_timeout_seconds` | `86400` (24h) | Stale approvals fail with `RemediationApprovalStaleError` |

---

## 8. Audit Trail Persistence

Every step of the remediation lifecycle is persisted as dedicated SQL rows (migration `004_add_remediation_tables`):

* `remediation_proposals`: Immutable log of raw LLM candidate proposals.
* `remediation_actions`: Policy decisions (`ALLOWED`, `APPROVAL_REQUIRED`, `REJECTED`), approval timestamps, operator identities, and reasons.
* `remediation_results`: Execution outcomes, error messages, before/after state captures, and durations.
