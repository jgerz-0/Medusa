# Copilot Instructions for Medusa

## Project Overview
Medusa is an agentic AI-driven Cyber Reasoning System for automated pentesting and binary analysis. It orchestrates web and binary scanners, CVE enrichment, and reporting in a Kubernetes-native environment.

## Architecture
- **Agentic Pipeline**: The workflow is Recon → Scan → Validate → Enrich → Report. Each phase is modular and may be handled by different workers/services.
- **Major Components**:
  - `controller/`: FastAPI service orchestrating jobs and API endpoints.
  - `workers/`: Contains scanner and analysis workers (web, binary, enrichment).
  - `helm/`, `k8s/`: Kubernetes manifests and Helm charts for deployment and scaling.
  - `docs/`: Architecture, deployment, and integration documentation.

## Developer Workflows
- **Local Development**:
  - Start dependencies: `docker compose up -d` (Postgres, Redis, Minio)
  - Run API: `cd controller && uvicorn main:app --reload`
- **Kubernetes Deployment**:
  - Use manifests in `k8s/` or charts in `helm/` for job orchestration and scaling.
- **Testing**:
  - Tests are typically located in each component's directory. Use standard Python test runners (pytest) unless otherwise noted in docs.

## Conventions & Patterns
- **Agentic Design**: Each phase in the pipeline is a discrete agent/service. Communication is via API calls, message queues, or shared DBs.
- **Multi-Scanner Orchestration**: Workers are designed to run scanners (Nuclei, ZAP, SQLMap, fuzzers) in isolated jobs, often as K8s pods.
- **CVE Enrichment**: Integrates with NVD, CIRCL, and vector stores. See enrichment worker for retrieval and verification logic.
- **Reporting**: Results are aggregated into dashboards and PDFs. Look for reporting logic in controller and workers.

## Integration Points
- **External Tools**: Nuclei, ZAP, SQLMap, fuzzers, symbolic execution engines.
- **Data Stores**: Postgres (main DB), Redis (queue/cache), Minio (object storage).
- **Vector Store**: Used for CVE mapping and enrichment.

## Examples
- To add a new scanner, create a worker in `workers/` and update the controller orchestration logic.
- For new enrichment sources, extend the enrichment worker and update vector store integration.

## Key Files & Directories
- `controller/main.py`: API entrypoint and orchestration logic.
- `workers/`: All agent/worker implementations.
- `docs/ARCHITECTURE.md`: High-level system design.
- `k8s/`, `helm/`: Deployment and scaling configs.

---
For more details, see `docs/ARCHITECTURE.md` and `README.md`. Update this file as new conventions or workflows emerge.
