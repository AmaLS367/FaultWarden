# Change Intelligence & Causal Verification

Change Intelligence enables FaultWarden to correlate operational incidents with recent Git commits, deployments, and configuration changes.

---

## 1. Core Invariants & Safety

1. **Temporal Proximity is Not Causation**: A recent commit or deployment is never assumed to be the root cause based on timing alone. Operational changes must demonstrate multi-factor semantic alignment (modified files, parameters, error symptoms).
2. **Read-Only Ingestion**: Change providers (`GitChangeProvider`, `DeploymentChangeProvider`) execute read-only queries with strict timeouts and output truncation.
3. **Deterministic Secret Masking**: Sensitive variables (passwords, tokens, API keys) are masked to `[REDACTED]` before entering prompt contexts or database storage.

---

## 2. Multi-Factor Correlation Algorithm

Each operational change is evaluated using a composite scoring function:

$$\text{Relevance Score} = 0.35 \times \text{Temporal} + 0.45 \times \text{SymptomMatch} + 0.20 \times \text{EvidenceLinks}$$

### Component Breakdown
* **Temporal Score ($0.0 \dots 1.0$)**: Decays linearly with time elapsed between change and incident onset. Penalizes changes deployed *after* incident onset (capped at 0.20).
* **Component Match**: Evaluates service name and component alignment.
* **Symptom Match ($0.0 \dots 1.0$)**: Matches change diffs and parameters against domain symptom keyword clusters (`db_pool`, `timeout`, `memory`, `cpu`, `error_rate`, `concurrency`).
* **Candidate Promotion Gate**:
  $$\text{Relevance Score} \ge 0.60 \land \text{ComponentMatch} \land \text{SymptomMatch} \land \text{Temporal} \ge 0.30$$

If symptom matching fails, relevance score is capped at `0.35` and `is_causal_candidate` is set to `False`.

---

## 3. Deterministic Causal Verification Gates (v0.5.1)

To eliminate LLM hallucination and same-service attribution bias, FaultWarden v0.5.1 enforces a deterministic promotion gate (`core/causality.py::verify_causal_change_association`):

### Promotion Criteria
An operational change is promoted to `RootCauseAnalysis.causal_change_ids` **only** if all 8 checks pass:

1. **Existence**: Change ID exists in `state["recent_changes"]`.
2. **Candidate Status**: `ChangeCorrelation` exists and `is_causal_candidate == True`.
3. **Component Alignment**: `component_match == True` and matches `hypothesis.affected_component`.
4. **Symptom Alignment**: `symptom_match == True` (diff or parameters align with observed failure modes).
5. **Threshold Compliance**: `relevance_score >= correlation_threshold`.
6. **Active Evidence Grounding**: `evidence_links` contains at least 1 `EvidenceItem` present in current telemetry inventory.
7. **Temporal Ordering**: Change occurred prior to incident onset (`temporal_score >= 0.30`).
8. **Hypothesis Reference**: The verified hypothesis explicitly references the change in `related_change_ids`.

---

## 4. Separation of Concepts & API Surface

| Concept | Definition | REST Endpoint |
| :--- | :--- | :--- |
| **`recent_changes`** | All changes within the incident lookback window | `GET /api/v1/incidents/{id}/changes` |
| **`candidate_causal_changes`** | Changes passing initial correlation scoring | Filtered in changes payload |
| **`causal_changes`** | Strictly **VERIFIED** causal changes that passed all causal gates | `GET /api/v1/incidents/{id}/causal-changes` |

* **Postmortems**: Verified causal changes are documented under root cause; unverified candidates remain in the operational timeline.
* **Memory**: Incident memory indexes `causal_change_summary` and `causal_change_type` only when verified causal changes exist.
