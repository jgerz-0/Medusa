# Copilot Instructions for Medusa

## Project Overview
Medusa is an agentic AI-driven Cyber Reasoning System for automated pentesting and binary analysis. It orchestrates web and binary scanners, CVE enrichment, and reporting in a Kubernetes-native environment.

## Architecture

- **Agentic Pipeline**: Recon → Scan → Validate → Enrich → Report. Each phase is a modular agent/service, typically running in its own container. Agents can be passive (scan/analyze) or active (execute exploits, e.g., XSS, SQLi, RCE) and report findings with evidence.
- **Dynamic Agent Orchestration**: For each scan, the controller spins up a dedicated container for the required agent (e.g., XSS tester, SQLi validator), which is destroyed after job completion and result submission. This enables horizontal scaling and isolation.
- **Major Components**:
  - `controller/`: FastAPI service orchestrating jobs, agent lifecycle, and API endpoints.
  - `workers/`: Containerized agents for scanning, exploit testing, enrichment, and reporting. Add new agents here for each exploit type or analysis method.
  - `helm/`, `k8s/`: Kubernetes manifests and Helm charts for dynamic job orchestration, scaling, and security controls.
  - `docs/`: Architecture, deployment, agent interface, and integration documentation.

## Developer Workflows
- **Local Development**:
  - Start dependencies: `docker compose up -d` (Postgres, Redis, Minio)
  - Run API: `cd controller && uvicorn main:app --reload`
- **Kubernetes Deployment**:
  - Use manifests in `k8s/` or charts in `helm/` for job orchestration and scaling.
- **Testing**:
  - Tests are typically located in each component's directory. Use standard Python test runners (pytest) unless otherwise noted in docs.

## Conventions & Patterns

- **Agentic Design**: Each agent is a containerized service responsible for a specific exploit or analysis (e.g., XSS, SQLi, fuzzing, enrichment). Agents communicate via API calls, message queues, or shared DBs.
- **Exploit Testing Agents**: Agents can actively execute exploits (XSS, SQLi, CSRF, RCE, etc.) against target domains. Each agent should:
  - Discover relevant input fields (by id, class, tag, etc.)
  - Inject payloads and monitor for execution/evidence
  - Report success/failure and field attributes
  - Collect evidence (screenshots, logs, payloads) for reporting
- **Multi-Scanner Orchestration**: Workers/agents run scanners and exploit tests in isolated containers, orchestrated as Kubernetes jobs for scale and security.
- **Extensibility**: To add a new exploit or analysis, create a new agent in `workers/` and register its JSON schema in `docs/interfaces/`. Update controller orchestration logic as needed.
- **CVE Enrichment**: Integrates with NVD, CIRCL, and vector stores. See enrichment agent for retrieval and verification logic.
- **Reporting**: Results are aggregated into dashboards and PDFs. Agents should submit structured findings and evidence for client-facing reports.

## Integration Points
- **External Tools**: Nuclei, ZAP, SQLMap, fuzzers, symbolic execution engines.
- **Data Stores**: Postgres (main DB), Redis (queue/cache), Minio (object storage).
- **Vector Store**: Used for CVE mapping and enrichment.

## Examples

- To add a new exploit-testing agent (e.g., XSS, SQLi):
  1. Create a worker in `workers/` that executes the exploit, collects evidence, and reports results with field attributes.
  2. Register its JSON schema in `docs/interfaces/`.
  3. Update the controller to orchestrate the agent as a containerized job.
- For new enrichment sources, extend the enrichment agent and update vector store integration.

## Key Files & Directories

- `controller/main.py`: API entrypoint, agent orchestration, and job lifecycle logic.
- `workers/`: All agent/worker implementations (scanners, exploit testers, enrichment, reporting).
- `docs/ARCHITECTURE.md`: High-level system design and agent interface contracts.
- `k8s/`, `helm/`: Kubernetes manifests and Helm charts for dynamic agent orchestration and scaling.

---
For more details, see `docs/ARCHITECTURE.md` and `README.md`. Update this file as new conventions or workflows emerge.
