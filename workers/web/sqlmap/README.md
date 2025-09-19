# Medusa SQLMap Worker

The SQLMap worker executes the sqlmap engine with a hardened set of flags. The
controller is responsible for scope validation and for providing sanitized
parameters. Results are normalized into the common Medusa callback schema so the
UI and enrichment services can operate on consistent data.

## Environment Variables

- `SQLMAP_QUEUE_KEY` – Redis list from which jobs are consumed.
- `SQLMAP_DEAD_LETTER_KEY` – Redis list used for jobs that exceed retries.
- `SQLMAP_CALLBACK_TOKEN` – Shared secret used to authenticate callbacks.
- `SQLMAP_BINARY` – Path to the sqlmap binary (defaults to `/usr/bin/sqlmap`).
- `SQLMAP_WORK_DIR` – Directory for transient sqlmap output.

## Running Locally

```bash
docker build -t medusa-sqlmap-worker .
docker run --rm medusa-sqlmap-worker
```
