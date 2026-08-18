# End-to-End Demos & Walkthroughs

This document provides step-by-step walkthroughs for running end-to-end incident response scenarios against the live FaultWarden stack.

---

## 1. Prerequisites & Environment Setup

Start the 9-service observability and simulation stack:

```bash
docker compose up -d --build
# Verify all services are healthy:
docker compose ps
```

> [!NOTE]
> When running via Docker Compose, FaultWarden API is published on host port **`8010`** (mapped to container port `8000`). If running standalone locally with `uvicorn faultwarden.main:app --port 8000`, use port **`8000`**.

---

## 2. Level 1 — Auto-Executed Remediation

In Level 1 scenarios, FaultWarden detects the incident, verifies the root cause, automatically executes the bounded remediation, independently verifies recovery, and transitions the incident to `RESOLVED`.

To see Level 1 auto-execution with the default mock provider, set `FAULTWARDEN_REMEDIATION_AUTO_EXECUTE_MAX_SAFETY_LEVEL=2` in `.env`, or use an LLM provider that proposes a Level 1 action.

```bash
# 1. Trigger error injection in the demo service:
curl -X POST http://localhost:8001/debug/error-mode/true

# 2. Wait ~15-30s for Prometheus -> Alertmanager -> webhook -> Incident (DETECTED)
curl http://localhost:8010/api/v1/incidents

# 3. Poll incident until status is RESOLVED:
curl http://localhost:8010/api/v1/incidents/{incident_id}

# 4. Verify remediation execution and independent validation:
curl http://localhost:8010/api/v1/incidents/{incident_id}/remediations

# 5. Inspect structured postmortem generated on resolution:
curl http://localhost:8010/api/v1/incidents/{incident_id}/postmortem

# 6. Inspect indexed vector memory:
curl http://localhost:8010/api/v1/incidents/{incident_id}/memory
```

---

## 3. Level 2 — Human Approval Gate

Level 2 actions (e.g. service restarts, rollbacks) require explicit operator authorization. The LangGraph workflow pauses durably using `interrupt()`.

```bash
# 1. Trigger error injection:
curl -X POST http://localhost:8001/debug/error-mode/true

# 2. Wait until incident reaches AWAITING_APPROVAL:
curl http://localhost:8010/api/v1/incidents/{incident_id}

# 3. Inspect the pending remediation action:
curl http://localhost:8010/api/v1/incidents/{incident_id}/remediations
# Response: {"decision": "APPROVAL_REQUIRED", "status": "AWAITING_APPROVAL", "result": null, ...}

# 4. Option A: Approve the remediation:
curl -X POST http://localhost:8010/api/v1/incidents/{incident_id}/remediations/{remediation_id}/approve \
  -H "Content-Type: application/json" \
  -d '{"approved_by": "sre-engineer@example.com"}'
# Resumes the paused workflow, executes action, validates recovery, transitions to RESOLVED

# 4. Option B: Reject the remediation (alternative path):
curl -X POST http://localhost:8010/api/v1/incidents/{incident_id}/remediations/{remediation_id}/reject \
  -H "Content-Type: application/json" \
  -d '{"approved_by": "sre-engineer@example.com"}'
# Resumes workflow, skips execution, transitions incident to REMEDIATION_PROPOSED
```

---

## 4. Incident Memory & Semantic Search

```bash
# Query similar historical incidents for active incident:
curl http://localhost:8010/api/v1/incidents/{incident_id}/similar

# Perform cross-incident semantic vector search across memory:
curl -X POST http://localhost:8010/api/v1/memory/search \
  -H "Content-Type: application/json" \
  -d '{"query": "Database connection pool exhausted under traffic spike", "service": "demo-service", "limit": 5}'
```

---

## 5. Change Intelligence Inspection

```bash
# Inspect all operational changes collected in the incident window:
curl http://localhost:8010/api/v1/incidents/{incident_id}/changes

# Inspect strictly verified causal changes:
curl http://localhost:8010/api/v1/incidents/{incident_id}/causal-changes
```

---

## 6. Resetting Environment

To reset the error injection state manually:

```bash
curl -X POST http://localhost:8001/debug/error-mode/false
```
