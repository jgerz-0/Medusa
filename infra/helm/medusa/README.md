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
