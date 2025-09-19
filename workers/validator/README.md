# Medusa Validator Worker


The validator worker performs targeted retests for web findings before they are
promoted in the controller. Jobs originate from the controller callback flow and
are delivered over Redis. Each job contains the finding metadata, the original
evidence hash, and optional HTTP verification steps. The worker executes the
steps deterministically and reports the outcome back to the controller.

## Environment Variables

- `VALIDATOR_QUEUE_KEY` – Redis list from which jobs are consumed.
- `VALIDATOR_DEAD_LETTER_KEY` – Redis list used to store jobs that exhausted retries.
- `VALIDATOR_CALLBACK_TOKEN` – Shared secret used when posting results to the controller.
- `VALIDATOR_MAX_RETRIES` – Number of retries before a job is dead-lettered (default: 3).
- `VALIDATOR_POLL_TIMEOUT` – Blocking pop timeout when waiting for jobs (default: 5 seconds).
- `VALIDATOR_HTTP_TIMEOUT` – Timeout applied to outbound verification requests (default: 10 seconds).

## Local Execution

```bash
docker build -t medusa-validator-worker .
docker run --rm -e VALIDATOR_CALLBACK_TOKEN=dev-token medusa-validator-worker
```
poetry install
poetry run python workers/validator/worker.py
```

The worker assumes that the controller has already authenticated the finding
scope. Verification requests only support HTTP(S) URLs defined in the job's
verification block. Results are posted back to the controller using the
`/internal/validator/callback` endpoint.
