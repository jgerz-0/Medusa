# Kubernetes Deployment Guide

This guide describes how to run the Medusa automated penetration testing platform on a local Kubernetes cluster. It mirrors the Docker Compose topology while adding production controls such as Pod Security Standards, network policies, and secret management.

## Prerequisites

- Kubernetes v1.26 or newer (Kind, k3d, or Minikube are good local options).
- [Helm 3.14+](https://helm.sh/docs/intro/install/).
- (Optional) [kubeconform](https://github.com/yannh/kubeconform) for manifest validation.
- Docker registry credentials if you push bespoke controller/worker images.

## Clone and build local images (optional)

If you rely on locally built images, mirror the Docker Compose builds:

```bash
# Controller
DOCKER_BUILDKIT=1 docker build -t medusa/controller -f infra/docker/controller.Dockerfile .

# Nuclei worker
DOCKER_BUILDKIT=1 docker build -t medusa/worker-nuclei -f workers/web/nuclei/Dockerfile .

# Binary preprocess worker
DOCKER_BUILDKIT=1 docker build -t medusa/worker-binary-preprocess -f workers/binary/preprocess/Dockerfile .

# Binary fuzzing worker
DOCKER_BUILDKIT=1 docker build -t medusa/worker-binary-fuzzing -f workers/binary/fuzzing/Dockerfile .

# Frontend (only required if you expose it through the cluster)
DOCKER_BUILDKIT=1 docker build -t medusa/frontend -f infra/docker/frontend.Dockerfile .
```

Push the images to a registry reachable by the cluster or load them directly into Kind/Minikube.

## Create a namespace with Pod Security Standards

The chart applies the Kubernetes Pod Security Standards (`baseline` enforce / `restricted` audit by default). Create the namespace first to avoid clashes if it already exists:

```bash
kubectl create namespace medusa || true
kubectl label namespace medusa \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=baseline --overwrite
```

## Deploy External Secrets (optional)

Production clusters should source credentials from a hardened store instead of inline manifests. The Terraform module now manages the [External Secrets Operator](https://external-secrets.io) via `infra/terraform/modules/external-secrets`:

1. Provision an IAM role for service accounts (IRSA) that grants `secretsmanager:GetSecretValue` on the required AWS Secrets Manager keys.
2. Set the following variables in your environment `.tfvars` file:

   ```hcl
   enable_external_secrets_operator   = true
   external_secrets_irsa_role_arn     = "arn:aws:iam::123456789012:role/external-secrets-operator"
   external_secrets_secret_store_name = "medusa-prod-cluster-secrets"
   ```

3. Run `terraform apply` from `infra/terraform/envs/<env>` to install the operator, create a `ClusterSecretStore`, and wire the service account annotations.

When the operator is enabled, the Medusa release automatically switches `secrets.strategy` to `externalSecret` and renders an `ExternalSecret` that:

- Pulls the controller database credentials from Secrets Manager using the store above.
- Templatizes the connection string and Medusa callback tokens generated during `terraform apply`.
- Refreshes on the cadence configured by `external_secrets_medusa_refresh_interval` (defaults to five minutes).

Clusters without AWS access or IRSA bindings can continue to use inline secrets that mirror `infra/docker/docker-compose.yml`.

For day-two operations—including diagnosing controller sync errors, resolving `SecretStore` permission issues, and validating rotation events—follow the [External Secrets runbook](runbooks/EXTERNAL_SECRETS.md).

## Provision the AWS Load Balancer Controller

Production clusters expose Medusa via an Application Load Balancer managed by
the [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/).
The Terraform module at `infra/terraform/modules/aws_lb_controller` automates
the IAM role, IRSA wiring, and Helm deployment with hardened defaults
(non-root controller pods, default ingress class, and TLS 1.2/1.3 policies).

1. Populate the following variables in `infra/terraform/envs/<env>/terraform.tfvars`:

   ```hcl
   enable_aws_lb_controller = true
   aws_lb_controller_scheme = "internal" # or "internet-facing" when exposing Medusa publicly
   aws_lb_controller_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/your-cert"
   aws_lb_controller_additional_annotations = {
     "alb.ingress.kubernetes.io/listen-ports" = "[{\"HTTPS\":443}]"
     "alb.ingress.kubernetes.io/ssl-redirect" = "443"
   }

   medusa_controller_ingress_enabled = true
   medusa_controller_ingress_hosts = [
     {
       host = "medusa.dev.example.com"
       paths = [
         {
           path      = "/"
           path_type = "Prefix"
         }
       ]
     }
   ]
   medusa_controller_ingress_tls = [
     {
       hosts       = ["medusa.dev.example.com"]
       secret_name = "medusa-dev-tls"
     }
   ]
   ```

2. Run `terraform apply` inside `infra/terraform/envs/<env>`.

   Terraform will:

   - Create an IAM role that trusts the EKS OIDC provider and attaches the
     `AmazonEKSLoadBalancerControllerPolicy` managed policy.
   - Deploy the upstream Helm chart with the IRSA annotation, Pod Security
     settings, and the default ingress class/parameters bound to your private or
     public subnets.
   - Inject ALB annotations (scheme, certificate ARN, SSL policy, additional
     listener attributes) into the Medusa controller ingress via
     `extra_values`, so the ALB stands up automatically during the Helm
     release.

3. Optionally tune advanced settings via the Terraform variables:

   - `aws_lb_controller_enable_shield_advanced` to toggle Shield Advanced on
     every controller-managed ALB.
   - `aws_lb_controller_waf_web_acl_arn` to associate a regional WAF ACL with
     new ALBs and `aws_lb_controller_ssl_policy` to lock TLS to the latest
     AWS-managed security policy.
   - `aws_lb_controller_security_group_ids` to pin ALBs to precreated security
     groups.
   - `aws_lb_controller_additional_tags` to enforce cost/audit tagging on ALB
     resources.
   - `medusa_controller_ingress_additional_annotations` to append workload-
     specific rules while keeping the Terraform-managed defaults intact.
   - `medusa_controller_shield_enabled`, `medusa_controller_waf_enabled`,
     `medusa_controller_waf_acl_arn`, and
     `medusa_controller_waf_fail_open` to layer per-ingress overrides on top of
     the global controller settings when you deploy multiple ingress classes.

### Harden the ingress with AWS Shield and WAF

AWS Shield Advanced and AWS WAF should front any public Medusa deployment. The
Helm chart now exposes explicit toggles so the associated ALB annotations are
rendered deterministically:

```hcl
# terraform.tfvars
aws_lb_controller_enable_shield_advanced = true
aws_lb_controller_waf_web_acl_arn        = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/medusa-prod/abcd1234-5678-90ab-cdef-EXAMPLE"
aws_lb_controller_ssl_policy             = "ELBSecurityPolicy-TLS13-1-2-2021-06"
medusa_controller_shield_enabled         = true
medusa_controller_waf_enabled            = true
medusa_controller_waf_acl_arn            = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/medusa-prod/abcd1234-5678-90ab-cdef-EXAMPLE"
medusa_controller_waf_fail_open          = false
```

The module maps these variables to the Helm values under
`controller.ingress.aws`. If you manage Helm directly, mirror the same
configuration in `values.yaml`:

```yaml
controller:
  ingress:
    aws:
      shield:
        enabled: true
      waf:
        enabled: true
        webAclArn: arn:aws:wafv2:us-east-1:123456789012:regional/webacl/medusa-prod/abcd1234-5678-90ab-cdef-EXAMPLE
        failOpen: false
```

Use AWS Firewall Manager or Terraform to provision the WebACL with managed rule
groups that match your threat model (e.g., AWSManagedRulesCommonRuleSet and
AWSManagedRulesKnownBadInputsRuleSet). Keep `failOpen` set to `false` so the ALB
fails closed if WAF becomes unavailable, and ensure the Shield Advanced
subscription is enabled on the target account before flipping the toggle.

After Terraform converges, confirm the annotations landed on the ingress class
and workloads:

```bash
kubectl get ingressclassparams -n kube-system aws-load-balancer-controller -o yaml | grep -A5 waf
kubectl describe ingress -n medusa medusa-controller | grep -E "shield-advanced|waf-acl"
```

## Install Medusa via Helm

```bash
helm upgrade --install medusa infra/helm/medusa \
  --namespace medusa \
  --create-namespace \
  -f infra/helm/medusa/values-dev.yaml
```

Key defaults provided by `values-dev.yaml`:

- Controller, Redis, Postgres, MinIO, and Qdrant run with the same credentials as Docker Compose.
- Inline secrets seed the same JWT secret, callback tokens, and MinIO credentials.
- Persistent volumes are disabled to favour fast iteration; data disappears when pods are deleted.
- The nuclei, binary preprocess, and binary fuzzing workers run as `Job` resources wired to their respective Redis queues.

The fuzzing worker requires access to a container runtime capable of launching the
target harness images. In development clusters you can mount the host Docker
socket by setting `workers.binaryFuzzing.extraVolumeMounts` and
`workers.binaryFuzzing.extraVolumes` in your values file. Production deployments
should instead point `BINARY_FUZZING_RUNTIME` at a remote runner or leverage a
dedicated fuzzing node pool with strict RBAC.

## Scope drift monitoring and anomaly routing

The Helm chart now deploys a `scope-monitor` worker that inspects recent
findings for targets that fall outside the authorized scope and posts
`scope_drift_detected` anomalies back to the controller. Tune its sensitivity and
dispatch cadence with the `workers.scopeMonitor.env.values` block:

```yaml
workers:
  scopeMonitor:
    env:
      values:
        SCOPE_MONITOR_POLL_INTERVAL: "15"            # seconds between queries
        SCOPE_MONITOR_BATCH_SIZE: "100"              # findings processed per cycle
        SCOPE_MONITOR_LOOKBACK_SECONDS: "604800"     # one-week window for regressions
        SCOPE_MONITOR_SOURCE: "worker:scope-monitor" # label applied to anomaly events
        SCOPE_MONITOR_ACTOR: "worker:scope-monitor"  # audit actor written to Postgres
```

Worker pods authenticate to the anomaly callback using the
`MEDUSA_ANOMALY_CALLBACK_TOKEN` secret. When running with External Secrets or
AWS IRSA bindings, ensure the backing IAM role can read the secret material and
that the Helm release maps it to the `medusa-secrets` entry. The chart ships a
dedicated service account and namespace-scoped Role that grants `get` access to
the secret so the kubelet can project the token into the pod environment.

NetworkPolicies automatically whitelist every enabled worker component based on
`values.yaml`. Use `networkPolicies.workers.allowedComponents` to append
third-party agents (for example, externally managed scoring pipelines) without
losing the hardened defaults.

## Network policy egress matrix

Every Medusa worker now renders a dedicated `NetworkPolicy` that restricts
egress to the data-plane services it genuinely needs. DNS lookups against
`kube-dns` remain permitted unless `workers.<name>.networkPolicy.allowDNS` is set
to `false`. Scanner traffic is confined to explicit CIDR ranges by populating
`workers.<name>.networkPolicy.targetCIDRs`; the defaults block external
destinations until you declare the authorized scope. The matrix below lists the
baseline egress permissions:

| Worker | Redis | Controller callbacks | MinIO (artifacts) | PostgreSQL | Qdrant | Target CIDRs |
| --- | --- | --- | --- | --- | --- | --- |
| nuclei | Allowed | Allowed | Allowed | Blocked | Blocked | `[]` (blocked until set) |
| zap *(disabled by default)* | Allowed | Allowed | Blocked | Blocked | Blocked | `[]` (blocked until set) |
| sqlmap *(disabled by default)* | Allowed | Allowed | Blocked | Blocked | Blocked | `[]` (blocked until set) |
| ticketing | Blocked | Blocked | Blocked | Allowed | Blocked | `[]` (blocked until set) |
| anomaly | Allowed | Allowed | Blocked | Allowed | Blocked | `[]` (blocked until set) |
| recon | Allowed | Allowed | Blocked | Blocked | Blocked | `[]` (blocked until set) |
| validator | Allowed | Allowed | Blocked | Blocked | Blocked | `[]` (blocked until set) |
| binaryPreprocess | Allowed | Blocked | Allowed | Allowed | Blocked | `[]` (blocked until set) |
| binaryStaticAnalysis | Allowed | Allowed | Allowed | Blocked | Blocked | `[]` (blocked until set) |
| binarySymbolicExecution | Allowed | Allowed | Allowed | Blocked | Blocked | `[]` (blocked until set) |
| binaryFuzzing | Allowed | Allowed | Allowed | Blocked | Blocked | `[]` (blocked until set) |
| cveEnrichment | Blocked | Allowed | Blocked | Blocked | Allowed | `[]` (blocked until set) |
| scopeMonitor | Allowed | Allowed | Blocked | Allowed | Blocked | `[]` (blocked until set) |

Tune the per-worker policy in `infra/helm/medusa/values.yaml` before each
engagement so scanners cannot leave the approved CIDR ranges. If a worker needs
additional downstream systems (for example a third-party ticketing API), add
bespoke `ipBlock` entries under `targetCIDRs` instead of widening namespace
access.

## Verify the deployment

```bash
kubectl get pods -n medusa
kubectl logs deployment/medusa-medusa-controller -n medusa
```

Create a port-forward for local access:

```bash
# Controller API
kubectl port-forward -n medusa svc/medusa-medusa-controller 8000:8000

# MinIO console (optional)
kubectl port-forward -n medusa svc/medusa-medusa-minio 9001:9001
```

If you enabled the optional Prometheus/Grafana subcharts, expose them via `kubectl port-forward` or Ingress according to your ingress controller’s requirements.

## Metrics stack (optional)

Set the following overrides to deploy Prometheus and Grafana along with Medusa:

```bash
helm upgrade --install medusa infra/helm/medusa \
  --namespace medusa \
  -f infra/helm/medusa/values-dev.yaml \
  --set metrics.prometheus.enabled=true \
  --set metrics.prometheus.serviceMonitor.enabled=true \
  --set metrics.grafana.enabled=true \
  --set grafana.adminPassword="change-me"
```

Prometheus scrapes the controller service on `/metrics` using the optional
`ServiceMonitor`. Disable the `serviceMonitor` flag if your cluster does not
ship the Prometheus Operator CRDs. The controller exports latency and
throughput metrics (`medusa_controller_http_requests_total`,
`medusa_controller_http_request_duration_seconds`) alongside domain counters
for audit events, job scheduling, and worker callbacks. Grafana automatically
mounts the provided “Medusa Controller Observability” dashboard via the chart’s
ConfigMap; set `metrics.grafana.dashboards.folder` to control the folder name
and rotate the `grafana.adminPassword` value before exposing the UI. A default
Grafana datasource points at `http://<release-name>-prometheus-server`; set
`metrics.grafana.datasources.url` when you front a managed Prometheus endpoint.

## Validating manifests locally

Run the same static checks used in CI before deploying:

```bash
helm dependency update infra/helm/medusa
helm lint infra/helm/medusa
helm template medusa infra/helm/medusa | kubeconform -strict -ignore-missing-schemas -skip SealedSecret,ExternalSecret
helm template medusa infra/helm/medusa -f infra/helm/medusa/values-dev.yaml | kubeconform -strict -ignore-missing-schemas -skip SealedSecret,ExternalSecret
```

## Cleaning up

```bash
helm uninstall medusa -n medusa
kubectl delete namespace medusa
```

## Production hardening checklist

- Switch `secrets.strategy` to `externalSecret` or `sealedSecret` and reference your Vault/KMS.
- Enable persistence for Postgres/Redis/MinIO/Qdrant with production storage classes.
- Replace inline callback tokens, JWT secrets, and API keys with randomised secrets.
- Tighten network policies by constraining allowed namespaces and adding explicit egress lists per component.
- Wire Prometheus/Grafana to enterprise monitoring and enforce RBAC on their services.

