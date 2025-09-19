# Medusa Roadmap

The roadmap tracks phased delivery for the automated pentest and binary analysis platform. Each phase builds on the previous one while preserving deterministic scan fidelity, auditability, and agent modularity.

## Phase 1 – Foundations (Weeks 0–2)
**Objective:** Ship the baseline local experience that exercises the end-to-end Recon → Scan → Report loop with nuclei.

- ✅ Repository skeleton with controller, workers, frontend, docs, and infra directories.
- ✅ Developer environment using Docker Compose (Postgres, Redis, MinIO, Qdrant).
  - _Note:_ Keep `docs/DOCKER.md` in sync as additional services (e.g., enrichment workers) join the stack.
- ✅ FastAPI controller exposing `/scan`, `/targets`, `/findings` endpoints with scope validation.
- ✅ Redis-backed nuclei worker returning normalized JSON findings.
- ✅ Postgres schema (targets, scans, findings, audit_log) and Alembic migrations.
- ✅ Minimal Next.js dashboard listing scans, drill-down for findings, manual scan trigger.
  - _Follow-up:_ Polish loading states, RBAC indicators, and pagination on `/scans` and `/findings` now that the manual nuclei launch flow is live.
- ☐ Baseline RBAC model (admin vs. analyst), API key issuance, and audit logging.
  - _Follow-up:_ Extend the controller's auth layer with role checks and API key lifecycle management, then document rotation procedures in `docs/CONTRIBUTING.md`.

> Exit Criteria: The Docker Compose stack reliably stands up controller, worker, Postgres, Redis, MinIO, and Qdrant; analysts trigger nuclei scans from the UI and observe stored findings; baseline RBAC (admin vs. analyst) with audit logging is enforced across the controller APIs.

## Phase 2 – Enrichment (Weeks 3–4)
- NVD + CIRCL CVE lookups with deterministic confidence scoring.
- Controller `/enrich` endpoint queues CVE enrichment jobs onto a dedicated worker channel.
- Qdrant vector ingestion of scanner fingerprints and advisories.
- Enrichment Agent attaches CVE metadata, exploitability hints, and remediation summaries.
- UI highlights enriched findings and displays provenance of enrichment data.

## Phase 3 – Binary Support (Weeks 5–6)
- Preprocess agent (file type detection, triage rules, scope enforcement).
- ✅ Static analyzers (checksec, bandit) with JSON adapters.
- Fuzzing harness using AFL/libFuzzer container jobs with artifact collection in MinIO.
- Binary findings schema aligned with web findings for unified reporting.

## Phase 4 – Multi-Scanner + Validator (Weeks 7–8)
- Integrate ZAP and SQLMap workers with scope guardrails.
- Validator agent performs targeted retests before findings are promoted.
- Consolidated JSON schema and severity scoring rules.
- Notification hooks (Slack, email) for critical findings after validation.

## Phase 5 – Kubernetes Orchestration (Weeks 9–10)
- Helm chart for controller, workers, and dependencies.
- K8s Job templates with resource constraints, network policies, and PodSecurityStandards.
- Prometheus/Grafana dashboards with per-scan metrics and audit events.
- Secrets management via External Secrets or SOPS integration.

## Phase 6 – Reporting & Frontend (Weeks 11–12)
- Next.js dashboards with filtering, tagging, and timeline view.
- PDF/HTML export pipeline with evidence snapshots and CVSS calculations.
- Ticketing integrations (Jira, GitHub) gated by RBAC and scope validation.
- Analyst workflow (assign, comment, resolve) with immutable audit trail.

## Phase 7 – Hardening (Weeks 13+)
- OIDC/OAuth2 auth flows with granular RBAC policies.
- Rate limiting, anomaly detection, and continuous scope compliance checks.
- CI/CD pipelines with IaC validation, security scanning, and supply-chain attestation.
- Disaster recovery playbooks and tabletop exercise documentation.

---
**Tracking:** Each phase should map to GitHub milestones. Create issues for deliverables, tag them by agent/service, and update documentation in tandem with implementation changes.
