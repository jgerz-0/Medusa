# Kubernetes Deployment

This document outlines how we operate Medusa on Kubernetes starting in Phase 5. Earlier phases can reference it for future planning.

## Prerequisites
- Kubernetes cluster (kind, k3d, minikube, or managed cloud)
- `kubectl` and `helm`
- Namespace: `pentest`
- Container registry with RBAC-enabled robot accounts

## Components
- **Controller** – Deployment with HorizontalPodAutoscaler and PodDisruptionBudget
- **Workers** – Helm templates for nuclei, ZAP, SQLMap, AFL, angr jobs
- **Postgres/Redis/MinIO/Qdrant** – StatefulSets with persistent volumes
- **Prometheus/Grafana** – Observability stack with network and job dashboards
- **External Secrets** – Synchronize secrets from Vault or cloud secret manager

## Deployment Steps
```bash
kubectl create namespace pentest
helm repo add medusa ./infra/helm
helm upgrade --install medusa medusa/medusa \
  --namespace pentest \
  --values infra/helm/values.dev.yaml
```

## Security Hardening
- Apply `NetworkPolicy` manifests restricting worker egress to approved CIDR ranges.
- Use `PodSecurityStandards` `restricted` profile for scanners; drop root, enforce read-only filesystems.
- Enable `runtimeClassName: gvisor` (or similar) for untrusted binaries when supported.
- Configure Kubernetes audit logging to forward events to the security SIEM.

## Operations Checklist
- Monitor job completions via `kubectl get jobs -n pentest` and Grafana dashboards.
- Rotate API keys and Helm chart secrets quarterly or after incident response actions.
- Validate CRDs and Helm values via CI before applying to production clusters.
