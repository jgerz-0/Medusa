# Architecture

## Components
- **Controller**: FastAPI REST service, schedules jobs, stores results
- **Queue**: Redis / RabbitMQ for job dispatch
- **Workers**:
  - Web scanners (nuclei, zap, sqlmap)
  - Binary scanners (afl, angr, checksec)
- **Agents**:
  - Recon, Preprocess, Validator, Enrichment, Reporter
- **Storage**:
  - Postgres (structured results)
  - MinIO/S3 (artifacts)
- **Frontend**: Next.js dashboard, PDF exports
- **Vector Store**: Qdrant/Weaviate for CVE/advisory recall

## Dataflow
1. API `/scan` → validate → push job to queue
2. K8s Job → run scanner worker → save results to MinIO
3. Enrichment Agent → fetch NVD/CIRCL + vector store → add metadata
4. Validator Agent → optional targeted probes
5. Reporter Agent → save final record to DB → trigger UI/ticket
