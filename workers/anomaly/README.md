# Anomaly Detection Worker

This worker inspects the controller audit log for indicators of abuse (excessive access denials,
rate limits, scope mismatches) and raises authenticated callbacks to `/internal/anomalies`.
It is designed to run both locally with Docker Compose and in production via the Helm chart.

## Responsibilities
- Poll the controller database for fresh audit events.
- Track cursor state in Redis to avoid re-processing events after crashes.
- Enforce heuristic thresholds to avoid alert fatigue while keeping latency low.
- Submit anomalies back to the controller using the `X-Callback-Token` header for
  authentication and attribution.

## Runtime Configuration
All knobs are exposed as environment variables so operators can tune behaviour without
rebuilding the container:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy connection string pointing at the controller database (Postgres in production, SQLite for tests). |
| `REDIS_URL` | Optional Redis instance used to persist the `ANOMALY_STATE_KEY` cursor. Set to the controller's Redis for real deployments. |
| `ANOMALY_CALLBACK_URL` | Endpoint that will receive anomaly batches. Defaults to the controller service DNS. |
| `ANOMALY_CALLBACK_TOKEN` | Shared secret presented via `X-Callback-Token` so the controller can authenticate the worker. |
| `ANOMALY_POLL_INTERVAL` | Seconds to sleep between polling loops. Increase to reduce load, decrease for faster detections. |
| `ANOMALY_BATCH_SIZE` | Maximum number of audit rows retrieved per loop. Keeps queries bounded. |
| `ANOMALY_HTTP_TIMEOUT` | Upper bound (seconds) for posting anomaly payloads. |
| `ANOMALY_STATE_KEY` | Redis key storing the ISO8601 timestamp of the last processed audit row. |
| `ANOMALY_SOURCE` | Attribution string stored with persisted `anomaly_event` records. |
| `ANOMALY_ACCESS_DENIED_THRESHOLD` / `ANOMALY_ACCESS_DENIED_WINDOW_SECONDS` | Trigger excessive access-denied anomalies once the threshold is met inside the window. |
| `ANOMALY_RATE_LIMIT_THRESHOLD` / `ANOMALY_RATE_LIMIT_WINDOW_SECONDS` | Trigger rate-limit anomalies once the threshold is met inside the window. |
| `ANOMALY_SCOPE_MISMATCH_THRESHOLD` / `ANOMALY_SCOPE_MISMATCH_WINDOW_SECONDS` | Trigger scope mismatch anomalies once the threshold is met inside the window. |
| `ANOMALY_DETECTOR_COOLDOWN_SECONDS` | Suppresses duplicate alerts for the same actor/action pattern across poll cycles. |

## Local Development
1. Populate `.env` with `ANOMALY_CALLBACK_TOKEN` so Docker Compose boots the worker with an
   authenticated token.
2. Run `docker compose up anomaly-worker` from `infra/docker`. The container executes
   `python -m workers.anomaly.worker` and will begin polling.
3. Use the controller API to generate audit noise (failed logins, blocked scopes) and inspect
   `/internal/anomalies` for persisted events.

## Kubernetes Deployment
The Helm chart exposes an `anomaly` worker block under `.Values.workers`. Override values such as
`env.values.ANOMALY_POLL_INTERVAL` or provide a different secret for
`env.secretRefs.ANOMALY_CALLBACK_TOKEN` to match your environment. NetworkPolicies automatically
allow the worker to reach Postgres and Redis when the component label `anomaly-worker` is added to
`networkPolicies.workers.allowedComponents`.

## Security Notes
- Rotate the callback token regularly and store it in a Kubernetes secret (`MEDUSA_ANOMALY_CALLBACK_TOKEN`).
- Restrict network egress so the worker can only talk to internal services; MinIO, Postgres, Redis, and the controller are sufficient.
- Audit anomaly payloads stored in Postgres to ensure operators can trace detector decisions.
