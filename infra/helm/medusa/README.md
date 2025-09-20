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

## Network Policies

Stateful dependencies (PostgreSQL, Redis, MinIO, Qdrant) are isolated behind a namespace-local `NetworkPolicy`. Controllers and workers must be explicitly admitted to reach those services. Extend the `.Values.networkPolicies.workers.allowedComponents` list whenever you add a new worker Job so the data-plane policy keeps pace with the workloads you deploy.

```yaml
networkPolicies:
  workers:
    allowedComponents:
      - nuclei-worker
      - binary-preprocess-worker
      - binary-fuzzing-worker
      - binary-static-analysis-worker
      - cve-enrichment-worker
```

Each entry must match the `app.kubernetes.io/component` label set on the worker pod template. Keeping the list explicit preserves the zero-trust default while still letting operators onboard additional analysis agents without editing templates.
