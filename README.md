# Automated Pentest & Binary Analysis Platform

This project is an **agentic AI-driven Cyber Reasoning System** that performs:
- Web application scanning (Nuclei, ZAP, SQLMap)
- Binary analysis (fuzzing, symbolic execution, static analysis)
- CVE enrichment (NVD, CIRCL, vector store retrieval)
- Automated reporting (dashboard + PDF)

## Features
- **Agentic pipeline**: Recon → Scan → Validate → Enrich → Report
- **Multi-scanner support**: web and binary tools orchestrated in K8s
- **Vector-assisted CVE mapping** with deterministic verification
- **Kubernetes native**: jobs scale horizontally, autoscaling, observability

## Quickstart (local dev)
```bash
# spin up postgres, redis, minio
docker compose up -d

# run controller (FastAPI)
cd controller
uvicorn main:app --reload
