#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if [[ ! -f .env ]]; then
  echo "[!] Missing .env file in infra/docker. Copy .env.example before running the chaos test." >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env
set +a

COMPOSE_BIN=${COMPOSE_BIN:-docker compose}
CHAOS_PAUSE_SECONDS=${CHAOS_PAUSE_SECONDS:-8}
DATABASE_URL=${MEDUSA_DATABASE_URL:-postgresql+psycopg://medusa:medusa@postgres:5432/medusa}

if ! ${COMPOSE_BIN} ps controller >/dev/null 2>&1; then
  echo "[!] Controller stack is not running. Start docker-compose before invoking chaos-test.sh." >&2
  exit 1
fi

echo "[+] Fetching generated principal API keys"
PRINCIPAL_ENV=$(${COMPOSE_BIN} exec -T controller sh -c 'if [ -f /var/lib/medusa/principal_credentials.env ]; then cat /var/lib/medusa/principal_credentials.env; fi')
ADMIN_KEY=$(printf '%s\n' "$PRINCIPAL_ENV" | awk -F'=' '/MEDUSA_ADMIN_API_KEY/ {print $2}' | tail -n1)
if [[ -z "$ADMIN_KEY" ]]; then
  echo "[!] Unable to resolve MEDUSA_ADMIN_API_KEY from /var/lib/medusa/principal_credentials.env" >&2
  exit 1
fi

echo "[+] Ensuring baseline targets exist"
${COMPOSE_BIN} exec -T controller poetry run python scripts/seed_targets.py >/dev/null

echo "[+] Resolving target id for chaos scan"
TARGET_ID=$(${COMPOSE_BIN} exec -T controller env DATABASE_URL="$DATABASE_URL" python - <<'PY'
from controller.db.session import session_scope
from controller.db import models

with session_scope() as session:
    target = session.query(models.Target).order_by(models.Target.created_at).first()
    if target is None:
        raise SystemExit("no targets available; seed_targets.py should have created one")
    print(target.id, end="")
PY
)
TARGET_ID="${TARGET_ID//$'\r'/}"

if [[ -z "$TARGET_ID" ]]; then
  echo "[!] Failed to determine a target id for the chaos scan" >&2
  exit 1
fi

echo "[+] Capturing initial audit log count"
AUDIT_COUNT_BEFORE=$(${COMPOSE_BIN} exec -T controller env DATABASE_URL="$DATABASE_URL" python - <<'PY'
from controller.db.session import session_scope
from controller.db import models

with session_scope() as session:
    count = session.query(models.AuditLog).count()
    print(count, end="")
PY
)
AUDIT_COUNT_BEFORE="${AUDIT_COUNT_BEFORE//$'\r'/}"

printf '[+] Pausing redis and minio containers for %ss\n' "$CHAOS_PAUSE_SECONDS"
${COMPOSE_BIN} pause redis minio
sleep "$CHAOS_PAUSE_SECONDS"
${COMPOSE_BIN} unpause redis minio

echo "[+] Attempting to enqueue nuclei scan after service disruption"
SCAN_ID=$(${COMPOSE_BIN} exec -T controller env ADMIN_KEY="$ADMIN_KEY" TARGET_ID="$TARGET_ID" python - <<'PY'
import json
import os
import sys
import time

import requests

admin_key = os.environ.get("ADMIN_KEY")
target_id = os.environ.get("TARGET_ID")

if not admin_key or not target_id:
    print("missing ADMIN_KEY or TARGET_ID", file=sys.stderr)
    raise SystemExit(1)

payload = {
    "target_id": target_id,
    "scanner": "nuclei",
    "parameters": {"profile": "baseline"},
}

session = requests.Session()
for attempt in range(1, 8):
    try:
        response = session.post(
            "http://localhost:8000/scan",
            json=payload,
            headers={"X-API-Key": admin_key},
            timeout=10,
        )
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - bubble up detailed chaos diagnostics
        if attempt == 7:
            print(f"enqueue failed after {attempt} attempts: {exc}", file=sys.stderr)
            raise
        backoff = min(5 * attempt, 20)
        print(f"[chaos] enqueue attempt {attempt} failed: {exc}; retrying in {backoff}s", file=sys.stderr)
        time.sleep(backoff)
    else:
        data = response.json()
        scan_id = data.get("id")
        if not scan_id:
            print("controller response missing scan id", file=sys.stderr)
            raise SystemExit(1)
        print(scan_id, end="")
        break
PY
)
SCAN_ID="${SCAN_ID//$'\r'/}"

if [[ -z "$SCAN_ID" ]]; then
  echo "[!] Controller did not return a scan identifier after chaos enqueue" >&2
  exit 1
fi

echo "[+] Verifying audit log recorded post-chaos activity"
AUDIT_COUNT_AFTER=$(${COMPOSE_BIN} exec -T controller env DATABASE_URL="$DATABASE_URL" CHAOS_SCAN_ID="$SCAN_ID" python - <<'PY'
from controller.db.session import session_scope
from controller.db import models
import os

scan_id = os.environ.get("CHAOS_SCAN_ID")

with session_scope() as session:
    total = session.query(models.AuditLog).count()
    scan_events = session.query(models.AuditLog).filter(models.AuditLog.scan_id == scan_id).count()
    if scan_events == 0:
        raise SystemExit("no audit events recorded for chaos scan")
    print(total, end="")
PY
)
AUDIT_COUNT_AFTER="${AUDIT_COUNT_AFTER//$'\r'/}"

if [[ -z "$AUDIT_COUNT_AFTER" ]]; then
  echo "[!] Failed to compute post-chaos audit log count" >&2
  exit 1
fi

if (( AUDIT_COUNT_AFTER <= AUDIT_COUNT_BEFORE )); then
  echo "[!] Audit log count did not increase after chaos run" >&2
  exit 1
fi

echo "[+] Chaos validation succeeded. Scan ${SCAN_ID} enqueued and audited after Redis/MinIO pause."
