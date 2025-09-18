
---

# 🛣 ROADMAP.md

```markdown
# Roadmap

## Phase 1 – Foundations (Weeks 0–2)
- Repo skeleton, docs
- FastAPI controller (accept /scan jobs)
- Redis queue + nuclei worker (local Docker)
- Postgres schema + minimal Next.js UI

## Phase 2 – Enrichment (Weeks 3–4)
- NVD API lookup + CIRCL fallback
- Vector store ingestion (Qdrant)
- Enrichment Agent attaches CVE data

## Phase 3 – Binary Support (Weeks 5–6)
- Preprocess agent (file/arch detection)
- Static analyzer (checksec, bandit)
- Fuzzing job (AFL/libFuzzer)

## Phase 4 – Multi-Scanner + Validator (Weeks 7–8)
- Add ZAP, SQLMap
- Validator agent retests critical hits
- Normalized JSON schema

## Phase 5 – Kubernetes Orchestration (Weeks 9–10)
- K8s Job templates for scanners
- Helm chart (controller + workers + storage)
- Prometheus/Grafana observability

## Phase 6 – Reporting & Frontend (Weeks 11–12)
- Next.js dashboards, filters, export
- PDF/HTML report generation
- Jira/GitHub ticket integration

## Phase 7 – Hardening (Weeks 13+)
- AuthN/AuthZ (OIDC/JWT)
- Rate limiting, scope enforcement
- CI/CD pipelines, RBAC
