# Anomaly Worker Callback Schema

The anomaly worker inspects the controller's immutable `audit_log` table and
pushes structured detections back to the controller. Callbacks are delivered to
`POST /internal/anomalies` and **must** include the `X-Callback-Token`
header populated with the shared secret configured in
`Settings.anomaly_callback_token`.

## Request Envelope

```jsonc
{
  "source": "worker:anomaly",          // identifier for the reporting worker
  "detected_at": "2024-04-05T12:00:00Z",  // when heuristics executed
  "anomalies": [
    {
      "anomaly_type": "excessive_access_denied", // detector slug
      "actor": "svc-gateway",                    // principal observed in audit log
      "first_seen": "2024-04-05T11:55:00Z",     // earliest audit event in window
      "last_seen": "2024-04-05T11:59:58Z",      // most recent audit event
      "count": 7,                                 // number of audit entries considered
      "window_seconds": 600,                      // rolling window evaluated
      "metadata": {                               // detector-specific context
        "reason_counts": {"missing_required_roles": 7},
        "client_hosts": {"10.10.10.5": 4, "10.10.10.9": 3}
      }
    }
  ]
}
```

## Field Reference

| Field | Type | Notes |
| ----- | ---- | ----- |
| `source` | string | Friendly identifier for the worker instance emitting the anomaly. Used for alerting context. |
| `detected_at` | RFC 3339 timestamp | UTC timestamp when heuristics were evaluated. |
| `anomalies` | array | One or more anomaly observations. Requests without entries are rejected. |
| `anomaly_type` | string | Detector slug. Current worker emits `excessive_access_denied`, `repeated_rate_limit`, or `scope_assertion_failures`. |
| `actor` | string | `Principal.subject` attributed to the suspicious activity. |
| `first_seen`, `last_seen` | RFC 3339 timestamp | Bounding window for the correlated audit events. Must be timezone-aware. |
| `count` | integer | Number of audit log records contributing to the anomaly. Must be ≥ 1. |
| `window_seconds` | integer | Duration of the sliding window used when evaluating the detector. |
| `metadata` | object | Detector-specific context used for triage (reason tallies, client hosts, sample identifiers, etc.). |

## Controller Behaviour

* Events are persisted in the `anomaly_events` table for long-term forensic
  review. The JSON metadata is stored verbatim for reproducibility.
* Each anomaly triggers the `NotificationService.notify_anomaly` hook, allowing
  Slack/email dispatch alongside existing critical finding alerts.
* The controller writes structured application logs summarising the submission,
  but the anomaly audit entries themselves are **not** re-analysed by the
  detector, preventing feedback loops.

## Security Considerations

* The worker authenticates via the `X-Callback-Token` header and the controller
  records every accepted payload for forensic review.
* Only deterministic heuristics (audit event counts, rolling windows) are used
  to avoid speculative alerting. Adjust thresholds inside
  `workers/anomaly/detector.py` if your environment demands tighter or looser
  sensitivity.
