# Resilience & Chaos Engineering Guide

The Medusa platform assumes scanners, queues, and storage tiers will fail under
pressure. This guide documents the automated coverage we added for crash
recovery and the operational workflows required to keep the system reliable.

## Integration Tests

The nuclei worker now has integration coverage that deliberately kills the
subprocess executing a scan. The tests assert that:

- Jobs are requeued with an incremented `attempts` counter when the scanner
  crashes mid-run.
- Payloads that exceed the configured `NUCLEI_MAX_RETRIES` value are serialized
  into `queues:nuclei:dead` with a `dead_lettered_at` timestamp and the failure
  reason for operators to triage.

Run the targeted suite locally with:

```bash
pytest tests/workers/test_worker_resilience_integration.py
```

These tests use an in-memory queue façade so they do not require a live Redis
instance. They model the same retry semantics enforced in production.

## Docker Chaos Exercise

`infra/docker/chaos-test.sh` pauses Redis and MinIO to simulate transient
infrastructure outages, then verifies the controller can recover:

1. API keys and demo targets are seeded automatically inside the controller
   container.
2. Redis and MinIO containers are paused for a configurable window (default
   eight seconds) and then resumed.
3. The script retries a `POST /scan` request (using the admin API key) until the
   controller accepts the job and returns a scan identifier.
4. The `audit_log` table is inspected to confirm the new scan produced audit
   entries—if none are found, the chaos run fails.

Execute the chaos probe after launching `docker compose` locally:

```bash
cd infra/docker
./chaos-test.sh
```

## Operational Expectations

- **Queue monitoring** – Track `queues:*:dead` keys and alert when they grow.
  Exhausted retries indicate either persistent scanner faults or downstream
  outages that require manual intervention.
- **Audit assurance** – Every scan enqueue path must emit `audit_log` entries.
  The chaos script verifies this automatically; operators should also spot-check
  audit trails after scheduled chaos exercises.
- **Service restarts** – If Redis or MinIO are restarted manually, rerun the
  chaos script and watch the controller logs for `queue enqueue` warnings. The
  retry backoff should smooth transient blips; persistent failures warrant
  investigation of the underlying service health.
- **Documentation cadence** – Capture lessons learned from chaos runs in the
  runbooks (for example, adding detection rules when new dead-letter patterns
  appear).

Embedding these drills into CI ensures regressions in queue handling or audit
logging are caught before reaching production.
