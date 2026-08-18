# Security Policy

FaultWarden takes the security of autonomous operations, infrastructure remediation, and AI-driven incident management seriously. This document outlines our security policies, supported versions, and how to report vulnerabilities.

---

## Supported Versions

Security updates and patches are applied to the following versions:

| Version | Supported          |
| :---    | :---:              |
| 0.5.x   | :white_check_mark: |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

---

## Security Architecture & Invariants

FaultWarden implements multi-layered defensive controls by design:

1. **LLM Output Untrusted**: All model outputs are strictly parsed and validated through strongly-typed Pydantic v2 schemas. Unvalidated parameters or unrecognised action types are rejected deterministically before reaching any service layer.
2. **No Arbitrary Shell Execution**: FaultWarden never uses raw subprocesses or unrestricted shell execution. All actions map to bounded `RemediationAction` definitions with parameter whitelisting.
3. **Remediation Safety Tiers**: Level 2 actions (rollbacks, database mutations, infrastructure modifications) require explicit operator approval before execution and cannot be auto-executed.
4. **Memory Trust Boundaries**: Historical incident memory is strictly context for hypothesis ranking and is never treated as direct verification evidence for root cause determination.
5. **Idempotency & Claiming**: All mutation actions are locked with atomic execution claims and propagate idempotent transaction keys (`X-Idempotency-Key`) to prevent double execution.

---

## Reporting a Vulnerability

If you discover a security vulnerability in FaultWarden, please do **NOT** open a public issue.

### Preferred Reporting Method
- Please report vulnerabilities privately via **GitHub Security Advisories** on the repository page:
  `Security` -> `Advisories` -> `Report a vulnerability`.

### Alternative Contact
- If GitHub Advisories are unavailable, email the maintainers directly with details:
  - Subject: `[SECURITY] FaultWarden Vulnerability Report`
  - Include:
    - Detailed description of the vulnerability
    - Steps to reproduce or proof-of-concept (PoC)
    - Affected versions and components
    - Potential impact (e.g. privilege escalation, unauthorized action execution, prompt injection)

### Response SLA
- **Acknowledgment**: Within 48 hours.
- **Assessment & Triage**: Within 5 business days.
- **Fix & Advisory Release**: Coordinated with the reporter before public disclosure.

---

## Disclosure Policy

When a vulnerability is verified:
1. We will develop a fix in a private branch.
2. We will release a patched version and publish a GitHub Security Advisory detailing the issue, severity (CVSS), and mitigation steps.
3. Credit will be given to the security researcher / reporter (unless anonymity is requested).
