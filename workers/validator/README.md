# Medusa Validator Worker

The validator worker performs lightweight retests of high-impact findings
before they are promoted to analysts. Jobs are delivered via Redis and include
pre-normalized evidence and metadata assembled by the controller. The worker is
expected to run in a hardened container with limited network access and uses
shared-secret authentication for callbacks.

## Environment Variables

- `VALIDATOR_QUEUE_KEY` – Redis list containing pending validation jobs.
- `VALIDATOR_DEAD_LETTER_KEY` – Redis list used for jobs that exceeded retry limits.
- `VALIDATOR_CALLBACK_TOKEN` – Shared secret for authenticating with the controller.
- `VALIDATOR_HTTP_TIMEOUT` – Optional timeout (seconds) for callback requests.

## Local Execution

```bash
docker build -t medusa-validator-worker .
docker run --rm -e VALIDATOR_CALLBACK_TOKEN=dev-token medusa-validator-worker
```
