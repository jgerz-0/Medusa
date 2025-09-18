
---

# ☸ docs/KUBERNETES.md

```markdown
# Kubernetes Deployment

## Prerequisites
- k8s cluster (kind, minikube, or cloud)
- kubectl & helm
- namespace: `pentest`

## Components
- **Controller**: Deployment + Service
- **Redis/Postgres/MinIO/Qdrant**: StatefulSets
- **Scanners**: Jobs spawned per scan
- **Prometheus/Grafana**: monitoring

## Deploy
```bash
kubectl create ns pentest
helm install pentest ./helm
