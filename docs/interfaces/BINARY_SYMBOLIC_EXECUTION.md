# Binary Symbolic Execution Interface

The angr symbolic execution worker emits callback payloads to
`POST /internal/binary/symbolic-execution/callback`. Payloads are strict JSON
objects matching the schema below.

## Callback Request

```jsonc
{
  "job_id": "job-angr-123",
  "scan_id": "uuid",
  "sample_id": "uuid",
  "status": "completed",
  "processed_at": "2025-04-15T12:00:00Z",
  "findings": [
    {
      "tool": "angr",
      "severity": "high",
      "title": "Reachable strcpy",
      "description": "User controlled path to strcpy",
      "metadata": {
        "sink": "strcpy",
        "analysis_depth": 256
      },
      "evidence": {
        "input": "41414141",
        "trace": ["0x401000", "0x401234"]
      },
      "artifact_bucket": "analysis",
      "artifact_key": "analysis/symbolic/sample-1/path.json",
      "executed_at": "2025-04-15T11:59:58Z"
    }
  ],
  "artifacts": [
    {
      "tool": "angr",
      "bucket": "analysis",
      "key": "analysis/symbolic/sample-1/path.json"
    }
  ],
  "reports": [
    {
      "tool": "angr",
      "status": "completed",
      "exit_code": 0,
      "stdout": "{...}",
      "stderr": "",
      "raw_output": {
        "metadata": {"paths": 1},
        "status": "completed"
      },
      "executed_at": "2025-04-15T11:59:58Z",
      "duration_seconds": 2.48
    }
  ],
  "metadata": {
    "paths": 1,
    "analysis_depth": 256
  },
  "error": null
}
```

### Field semantics

- `status` &mdash; `completed` when angr exited cleanly, `failed` when the harness
  returned a non-zero exit code or emitted a failure status.
- `findings` &mdash; normalized evidence persisted to
  `binary_symbolic_execution_findings`. `metadata` and `evidence` objects must be
  deterministic JSON.
- `artifacts` &mdash; references to JSON reports stored in object storage (usually
  MinIO). Workers should use the prefix returned by `BINARY_SYMBOLIC_EXECUTION_PREFIX`.
- `reports` &mdash; execution metadata per harness run, including stdout/stderr for
  forensic review.
- `metadata` &mdash; high-level run details (paths explored, solver statistics).
- `error` &mdash; optional human-readable string when `status` is `failed`.

All timestamps must be RFC3339 strings with timezone offsets. Severity values
must align with `info`, `low`, `medium`, `high`, or `critical`.
