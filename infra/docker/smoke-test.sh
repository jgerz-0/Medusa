#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if [[ ! -f .env ]]; then
  echo "[!] Missing .env file in infra/docker. Copy .env.example before running the smoke test." >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env
set +a

COMPOSE_BIN=${COMPOSE_BIN:-docker compose}
QUEUE_KEY=${NUCLEI_QUEUE_KEY:-queues:nuclei:jobs}
TEMPLATE_PATH=${SMOKE_TEST_TEMPLATE_PATH:-/app/templates/smoke-test.yaml}
TARGET_URL=${SMOKE_TEST_TARGET_URL:-http://controller:8000}
CALLBACK_URL=${SMOKE_TEST_CALLBACK_URL:-http://controller:8000/internal/nuclei/callback}

echo "[+] Fetching generated principal API keys"
PRINCIPAL_ENV=$(${COMPOSE_BIN} exec -T controller sh -c 'if [ -f /var/lib/medusa/principal_credentials.env ]; then cat /var/lib/medusa/principal_credentials.env; fi')
ADMIN_KEY=$(printf '%s\n' "$PRINCIPAL_ENV" | awk -F'=' '/MEDUSA_ADMIN_API_KEY/ {print $2}' | tail -n1)
ANALYST_KEY=$(printf '%s\n' "$PRINCIPAL_ENV" | awk -F'=' '/MEDUSA_ANALYST_API_KEY/ {print $2}' | tail -n1)
if [[ -n "$ADMIN_KEY" ]]; then
  echo "    admin: ${ADMIN_KEY}"
else
  echo "    admin: [missing]" >&2
fi
if [[ -n "$ANALYST_KEY" ]]; then
  echo "    analyst: ${ANALYST_KEY}"
else
  echo "    analyst: [missing]" >&2
fi

echo "[+] Running database migrations"
${COMPOSE_BIN} exec -T controller poetry run alembic upgrade head

echo "[+] Seeding demo targets"
${COMPOSE_BIN} exec -T controller poetry run python scripts/seed_targets.py

echo "[+] Creating a nuclei scan record for the smoke test"
SCAN_ID=$(${COMPOSE_BIN} exec -T controller poetry run python - <<'PY'
import uuid
from controller.db.session import session_scope
from controller.db import models

def ensure_target(session):
    target = session.query(models.Target).order_by(models.Target.created_at).first()
    if target is None:
        target = models.Target(
            name="Smoke Test Target",
            scope="controller.medusa.local",
            is_authorized=True,
        )
        session.add(target)
        session.flush()
    return target

with session_scope() as session:
    target = ensure_target(session)
    scan = models.Scan(
        id=str(uuid.uuid4()),
        target_id=target.id,
        scanner="nuclei",
        initiated_by="smoke-test",
        status="queued",
        parameters={"templates": ["${TEMPLATE_PATH}"]},
    )
    session.add(scan)
    session.flush()
    print(scan.id, end="")
PY
)
SCAN_ID="${SCAN_ID//$'\r'/}"

if [[ -z "${SCAN_ID}" ]]; then
  echo "[!] Failed to create scan record" >&2
  exit 1
fi

echo "[+] Enqueueing nuclei job ${SCAN_ID} on ${QUEUE_KEY}"
JOB_PAYLOAD=$(SCAN_ID="${SCAN_ID}" TEMPLATE_PATH="${TEMPLATE_PATH}" TARGET_URL="${TARGET_URL}" CALLBACK_URL="${CALLBACK_URL}" python - <<'PY'
import json, os, uuid
scan_id = os.environ.get("SCAN_ID")
template_path = os.environ.get("TEMPLATE_PATH")
target_url = os.environ.get("TARGET_URL")
callback_url = os.environ.get("CALLBACK_URL")
job = {
    "job_id": str(uuid.uuid4()),
    "target": target_url,
    "templates": [template_path],
    "callback_url": callback_url,
    "metadata": {
        "scan_id": scan_id,
        "initiated_by": "smoke-test",
    },
    "tags": ["smoke", "local"],
}
print(json.dumps(job))
PY
)
${COMPOSE_BIN} exec -T redis redis-cli rpush "${QUEUE_KEY}" "${JOB_PAYLOAD}"

echo "[+] Waiting for worker callback"
ATTEMPTS=30
SLEEP_SECONDS=2
for ((i=1; i<=ATTEMPTS; i++)); do
  STATUS=$(${COMPOSE_BIN} exec -T controller poetry run python - <<'PY'
from controller.db.session import session_scope
from controller.db import models
scan_id = "${SCAN_ID}"
with session_scope() as session:
    scan = session.get(models.Scan, scan_id)
    if scan is None:
        print("missing", end="")
    else:
        print(scan.status, end="")
PY
  )
  STATUS="${STATUS//$'\r'/}"
  if [[ "${STATUS}" == "completed" ]]; then
    echo "[+] Worker callback confirmed. Scan ${SCAN_ID} marked completed."
    exit 0
  fi
  if [[ "${STATUS}" == "failed" ]]; then
    echo "[!] Worker reported failure for scan ${SCAN_ID}" >&2
    exit 1
  fi
  sleep "${SLEEP_SECONDS}"
done

echo "[!] Timed out waiting for nuclei worker callback" >&2
exit 1
