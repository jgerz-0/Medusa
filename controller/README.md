# Medusa Controller

This service will orchestrate worker agents, enforce scan scope, and persist deterministic
vulnerability findings. Future FastAPI routes will expose RBAC-guarded JSON interfaces for
coordinating recon, scan, enrich, and report phases.

## Nuclei Worker Callback Contract

Nuclei workers report results back to the controller using a protected callback endpoint. The
controller validates the payload, persists findings and artifacts, updates scan state, and emits
an immutable audit event for each invocation.

### Endpoint

```
POST /internal/nuclei/callback
Header: X-Callback-Token: <shared secret configured via `MEDUSA_NUCLEI_CALLBACK_TOKEN`>
```

### Request Schema

```json
{
  "scan_id": 42,
  "status": "completed",          // one of: completed, failed
  "completed_at": "2024-04-01T12:00:00Z", // optional override for completion time
  "worker_metadata": {"templates": 12},    // optional structured metadata for audit/reporting
  "error": null,                   // optional error description when status="failed"
  "findings": [
    {
      "title": "Cross-Site Scripting",
      "severity": "high",                     // critical|high|medium|low|info
      "description": "Reflected XSS in search",
      "cve_id": "CVE-2024-9999",
      "metadata": {"template": "nuclei/xss/basic"},
      "evidence": {"request": "GET /?q=%3Cscript%3E"},
      "artifacts": [
        {
          "name": "http-request",
          "artifact_type": "http",
          "content_type": "text/plain",
          "data": "GET /?q=%3Cscript%3E HTTP/1.1\nHost: target",  // base64 or plaintext evidence
          "metadata": {"direction": "request"}
        }
      ]
    }
  ]
}
```

### Persistence Guarantees

- Findings are only accepted for scans that are not already finalized. Replays result in `409`.
- Evidence payloads, metadata, and artifacts are hashed and written once; attempts to mutate them
  later will raise database errors, preserving forensic integrity.
- Every callback emits an `audit_event` row summarizing the worker status and finding count.
