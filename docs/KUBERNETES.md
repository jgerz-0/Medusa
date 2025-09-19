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

For production, connect the chart to [External Secrets Operator](https://external-secrets.io) or Bitnami Sealed Secrets. The chart renders `ExternalSecret` or `SealedSecret` resources based on `values.yaml`.

For local development we stick with inline secrets that replicate `infra/docker/docker-compose.yml`.

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

