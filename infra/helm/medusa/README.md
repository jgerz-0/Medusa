# Medusa Helm Chart

This chart deploys the Medusa controller, stateful dependencies, and asynchronous workers used by the automated penetration testing pipeline. The defaults aim for a production-grade posture. Development-friendly overrides live in `values-dev.yaml`.

## Worker Service Accounts and RBAC

Each worker can now declare a dedicated service account and tightly scoped namespace RBAC objects. This keeps long-running jobs isolated and ready for IRSA-style credential wiring.

```yaml
workers:
  nuclei:
    serviceAccount:
      create: true
      name: ""                     # Optional override. Defaults to <release>-medusa-worker-nuclei-sa
      automountServiceAccountToken: false
      annotations:
        eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/medusa-nuclei
    rbac:
      create: true
      roleName: ""                 # Optional override. Defaults to <release>-medusa-worker-nuclei-role
      roleBindingName: ""          # Optional override. Defaults to <release>-medusa-worker-nuclei-rolebinding
      roleAnnotations: {}
      roleBindingAnnotations: {}
      additionalSubjects: []        # Add extra RoleBinding subjects (e.g., automation identities)
      rules:
        - apiGroups: [""]
          resources: ["pods", "pods/log"]
          verbs: ["get", "list", "watch"]
```

Key behaviors:

- When `serviceAccount.create` is `true`, the chart renders a dedicated `ServiceAccount` and wires `serviceAccountName` plus `automountServiceAccountToken` on the worker Job.
- `serviceAccount.annotations` are rendered verbatim, enabling IAM roles for service accounts (IRSA) or other identity bindings.
- `rbac.create` gates creation of a namespace-scoped `Role` and `RoleBinding` that attach to the worker service account. These resources are also gated by the chart-wide `.Values.rbac.create` toggle.
- Provide explicit `rules` to define the allowed verbs/resources; leaving the list empty will create an empty Role for auditing without permissions.
- Use `additionalSubjects` to append extra principals to the RoleBinding without losing the automatically managed service account subject.

Keep the `rbac` scope tight—workers should only receive the Kubernetes permissions they need to fetch secrets, configmaps, or other workload-specific resources.

## Binary Static Analysis worker configuration

The binary static analysis worker streams jobs from Redis, executes containerized tooling (checksec and Bandit today), and writes reports back to S3. Wire the queue keys, runtime images, callback token, and artifact storage credentials through `.Values.workers.binaryStaticAnalysis` so the Job can authenticate deterministically.

```yaml
workers:
  binaryStaticAnalysis:
    env:
      secretRefs:
        REDIS_URL: MEDUSA_REDIS_URL
        BINARY_STATIC_ANALYSIS_QUEUE_KEY: MEDUSA_BINARY_STATIC_ANALYSIS_QUEUE_CHANNEL
        BINARY_STATIC_ANALYSIS_DEAD_LETTER_KEY: BINARY_STATIC_ANALYSIS_DEAD_LETTER_KEY
        BINARY_ANALYSIS_BUCKET: BINARY_ANALYSIS_BUCKET
        BINARY_ANALYSIS_PREFIX: BINARY_ANALYSIS_PREFIX
        BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN: MEDUSA_BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN
        S3_ACCESS_KEY_ID: S3_ACCESS_KEY_ID
        S3_SECRET_ACCESS_KEY: S3_SECRET_ACCESS_KEY
      values:
        S3_ENDPOINT_URL: "{{ printf \"http://%s-minio:%d\" (include \"medusa.fullname\" $) $.Values.minio.service.apiPort }}"
        AWS_DEFAULT_REGION: "us-east-1"
        BINARY_STATIC_ANALYSIS_POLL_TIMEOUT: "5"
        BINARY_STATIC_ANALYSIS_MAX_ATTEMPTS: "3"
        BINARY_STATIC_ANALYSIS_RUNTIME: "docker"
        BINARY_STATIC_ANALYSIS_RUNTIME_FLAGS: ""
        BINARY_STATIC_ANALYSIS_CHECKSEC_IMAGE: "docker.io/medusa/checksec:latest"
        BINARY_STATIC_ANALYSIS_BANDIT_IMAGE: "docker.io/medusa/bandit:latest"
        BINARY_STATIC_ANALYSIS_ENABLE_CHECKSEC: "1"
        BINARY_STATIC_ANALYSIS_ENABLE_BANDIT: "1"
        BINARY_STATIC_ANALYSIS_TOOL_TIMEOUT: "120"
```

Populate the matching secret keys—`MEDUSA_BINARY_STATIC_ANALYSIS_QUEUE_CHANNEL`, `BINARY_STATIC_ANALYSIS_DEAD_LETTER_KEY`, `BINARY_ANALYSIS_BUCKET`, `BINARY_ANALYSIS_PREFIX`, and `MEDUSA_BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN`—through your selected secrets strategy (`inline`, `ExternalSecret`, or `SealedSecret`). These credentials gate which jobs the worker can dequeue and where findings are stored, so rotate them alongside Redis credentials during routine maintenance. Development overrides in `values-dev.yaml` mirror the same wiring with shorter poll timeouts for faster feedback.

## Pod Disruption Budgets

Medusa components can now opt in to `PodDisruptionBudget` (PDB) objects so voluntary disruptions do not take down critical services during node drain events.

- The controller defaults to `minAvailable: 1` because the chart runs two replicas by default.
- Stateful dependencies (PostgreSQL, Redis, MinIO, Qdrant) expose the same toggle but remain disabled until you run them with multiple replicas.
- Set exactly one of `minAvailable` or `maxUnavailable` per component. Leave the unused field `null` to keep the rendered manifest valid.

Example hardening posture when running HA data services:

```yaml
controller:
  pdb:
    enabled: true
    minAvailable: 1

postgresql:
  pdb:
    enabled: true
    minAvailable: 1

redis:
  pdb:
    enabled: true
    maxUnavailable: 1
    minAvailable: null

minio:
  pdb:
    enabled: true
    minAvailable: 2

qdrant:
  pdb:
    enabled: true
    minAvailable: 1
```

Tune these numbers to match the replica topology in your cluster. Keeping explicit budgets ensures planned maintenance cannot silently evict the only running pod for a security-critical subsystem.

## Rendering validation

Always render the chart after editing Job templates or environment variables so malformed YAML (e.g., dangling keys within `env` lists) is caught before review. The development values file exercises the worker Jobs and replicates the Redis secret wiring that previously regressed.

```bash
helm template infra/helm/medusa -f infra/helm/medusa/values-dev.yaml
```

If the command fails, address the template error before opening a pull request. Pair this with your preferred schema linter (such as `kubeconform`) to keep worker manifests deterministic and auditable.
