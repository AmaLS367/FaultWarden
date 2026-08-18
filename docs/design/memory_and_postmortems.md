# Incident Memory & Structured Postmortems

This document details FaultWarden's semantic incident memory (backed by pgvector) and the automatic generation of structured, factual postmortems.

---

## 1. Architectural Invariants & Trust Boundary

1. **Historical Memory is Background Context, Never Direct Telemetry Evidence**:
   - Historical similarity suggests candidate hypotheses or relevant diagnostic queries.
   - Historical memory cannot set `root_cause`, satisfy `supporting_evidence_ids`, bypass causality verification gates, or bypass remediation policy checks.
   - Every active incident hypothesis must be independently grounded in *current* telemetry collected during the incident window.
2. **Untrusted LLM Output Sanitization**:
   - The verification node strictly checks `supporting_evidence_ids` against current `state["evidence"]`. Any historical memory IDs returned by the model are stripped and placed exclusively in `historical_reference_ids`.
3. **Memory Poisoning Prevention**:
   - Only incidents meeting strict quality criteria are indexed into long-term memory.

---

## 2. Vector Memory & Quality Policy Gate

### Storage Engine
* **Production**: PostgreSQL with `pgvector` extension (`Vector(384)` embeddings via `pgvector.sqlalchemy`).
* **Test / SQLite Fallback**: Pure Python cosine similarity computation without native C extensions.

### Deterministic Quality Policy (`is_eligible_for_memory`)

An incident is indexed into `incident_memories` if and only if all 4 conditions hold:

1. **Terminal Status**: Incident status is strictly `RESOLVED`.
2. **Current Evidence**: Incident has at least 1 verified current `EvidenceItem`.
3. **Verified Root Cause**: Incident has a verified `root_cause` with `confidence >= confidence_threshold`.
4. **Validated Remediation**: Incident has an executed remediation action that passed independent recovery validation (`validation_passed == True`).

Non-resolved, inconclusive, or failed investigations are rejected from persistent memory to keep the index clean.

### Idempotency
Repeated indexing calls on the same incident ID safely return the existing memory record without creating duplicate vector rows.

---

## 3. Structured Postmortems

Postmortems are automatically generated upon transition to `IncidentStatus.RESOLVED`.

### Timeline Reconstruction
The timeline is compiled deterministically from database audit records:
1. Incident detection and alert webhook ingestion.
2. Investigation lifecycle start.
3. Telemetry evidence collection (metrics and logs).
4. Operational changes collected and correlated.
5. Root-cause hypothesis verification and causal change identification.
6. Remediation proposal formulation and policy evaluation.
7. Operator approval requested / granted (if Level 2).
8. Remediation execution and target state capture.
9. Post-remediation independent validation.
10. Incident marked resolved.

### Content Generation
`PostmortemService` synthesizes:
* **Executive Summary**: High-level incident narrative for leadership.
* **Root Cause & Contributing Factors**: Technical breakdown linking causal changes.
* **What Went Well / What Went Wrong**: Factual assessment of response efficiency.
* **Action Items**: Preventative improvements with assigned owners and priorities.
* **Lessons Learned**: Generalizable operational takeaways.

If the LLM provider fails or is unreachable, the system falls back to a deterministic heuristic postmortem builder.
