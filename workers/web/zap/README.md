# Medusa ZAP Worker

The ZAP worker wraps the OWASP ZAP baseline crawler in a hardened queue
consumer. Jobs originate from the controller and are delivered over Redis with
sanitized parameters. Findings are normalized into the common Medusa callback
schema before being persisted by the controller.

## Environment Variables

- `ZAP_QUEUE_KEY` – Redis list from which jobs are consumed.
- `ZAP_DEAD_LETTER_KEY` – List used for failed jobs that exceed retry limits.
- `ZAP_CALLBACK_TOKEN` – Shared secret used to authenticate with the controller.
- `ZAP_BINARY` – Path to the ZAP wrapper binary (defaults to `/zap/zap-baseline.py`).
- `ZAP_WORK_DIR` – Directory for transient reports.

## Running Locally

```bash
docker build -t medusa-zap-worker .
docker run --rm medusa-zap-worker
```
