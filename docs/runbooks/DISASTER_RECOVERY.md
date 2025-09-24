# Disaster Recovery Runbook

Medusa assumes adversarial failure modes. This runbook codifies the recovery objectives, backup restoration paths, and cross-region failover procedures for the production deployment managed through `infra/terraform`. Operators must execute these steps with change control and retain audit logs for every drill.

## Audience & Scope
- **Audience:** Platform SREs, database administrators, incident commanders, and security engineering leadership.
- **Systems covered:** Controller/worker services on Kubernetes, Postgres (RDS), MinIO/S3 object storage, and auxiliary services deployed through Terraform modules in `infra/terraform/modules`.
- **Environments:** Applies to staging and production; adapt resource names with the relevant `terraform.tfvars` in `infra/terraform/envs/<env>/`.

## Recovery Objectives

### RPO/RTO Targets
| Component | Terraform module | Recovery Point Objective (RPO) | Recovery Time Objective (RTO) | Notes |
| --- | --- | --- | --- | --- |
| Postgres (AWS Aurora/RDS) | [`infra/terraform/modules/rds`](../../infra/terraform/modules/rds) | ≤ 15 minutes using automated snapshots + binlog shipping. | ≤ 60 minutes to promote restored cluster and re-point services. | Continuous backups enabled via Terraform `backup_window` and `copy_tags_to_snapshot` settings. |
| Object storage (S3/MinIO buckets) | [`infra/terraform/modules/s3`](../../infra/terraform/modules/s3) | ≤ 30 minutes leveraging versioned buckets and MinIO replication. | ≤ 90 minutes to restore critical artifacts and validate worker writes. | Enable bucket versioning and replication in Terraform (`enable_replication = true`). |
| Kubernetes control plane + workloads | [`infra/terraform/modules/eks`](../../infra/terraform/modules/eks), [`infra/terraform/modules/medusa`](../../infra/terraform/modules/medusa) | ≤ 15 minutes by reapplying manifests from Git and secrets from External Secrets. | ≤ 45 minutes to scale workloads in alternate region/cluster. | Controllers/workers are stateless; rely on Terraform + Helm releases. |

### Backup Sources
- **Terraform state:** Remote backend (e.g., S3 + DynamoDB) storing infrastructure configuration.
- **Database snapshots:** Automated daily snapshots + manual on-demand snapshots tagged by change tickets.
- **Object storage replication:** Versioned S3 buckets with replication to a secondary region; MinIO deployments replicate to backup MinIO or S3 via mc mirror jobs.
- **Kubernetes manifests:** Git repositories + Helm release history captured in `infra/terraform/modules/medusa` outputs.

## Required Access & Tooling
- AWS CLI with credentials scoped to the Medusa production account and permissions for RDS, S3, EKS, and IAM.
- `kubectl` configured via `aws eks update-kubeconfig` or workload identity.
- Terraform 1.4+ with access to the environment's remote state backend.
- MinIO client (`mc`) for local or disaster recovery object storage operations.
- Incident tracking system (e.g., Jira) ticket to log all actions.

## Database Restoration (Postgres via RDS Module)
1. **Identify the failure window.** Consult alerting telemetry and the audit log table (`controller` database) to determine the last known good timestamp.
2. **Enumerate available snapshots.**
   ```bash
   ENV=prod
   terraform -chdir=infra/terraform/envs/$ENV output -raw rds_cluster_identifier
   aws rds describe-db-cluster-snapshots \
     --db-cluster-identifier "$(terraform -chdir=infra/terraform/envs/$ENV output -raw rds_cluster_identifier)" \
     --query 'DBClusterSnapshots[*].{Identifier:DBClusterSnapshotIdentifier,CreatedAt:SnapshotCreateTime}'
   ```
3. **Restore to point-in-time.** Use the snapshot closest to the failure while respecting the 15-minute RPO.
   ```bash
   SNAPSHOT_ID="medusa-prod-2024-restore"
   aws rds restore-db-cluster-to-point-in-time \
     --db-cluster-identifier medusa-prod-restored \
     --source-db-cluster-identifier "$(terraform -chdir=infra/terraform/envs/$ENV output -raw rds_cluster_identifier)" \
     --restore-to-time "2024-06-01T12:25:00Z" \
     --use-latest-restorable-time
   ```
4. **Promote and reconfigure.** Update Terraform variables:
   - Set `rds_restore_from_snapshot_id = "medusa-prod-restored"` in `infra/terraform/envs/$ENV/terraform.tfvars`.
   - Apply: `terraform -chdir=infra/terraform/envs/$ENV apply -target=module.rds` to update endpoints and security groups.
5. **Validate schema & data.**
   ```bash
   kubectl run db-check --restart=Never --image=ghcr.io/medusa/controller-migrations:latest \
     --env="DATABASE_URL=$(terraform -chdir=infra/terraform/envs/$ENV output -raw controller_database_url)" \
     -- python controller/scripts/check_migrations.py
   kubectl logs job/db-check
   ```
6. **Return services to steady state.** Patch secrets or connection strings if endpoints changed, then restart workloads:
   ```bash
   kubectl rollout restart deployment medusa-controller medusa-worker-nuclei
   kubectl get pods --selector=app.kubernetes.io/part-of=medusa --watch
   ```
7. **Document recovery.** Record timestamps, snapshot IDs, and validation evidence in the Exercise Log section below.

## Object Storage Restoration (S3 + MinIO)
1. **Assess impact.** Determine which buckets are affected using AWS CloudTrail and MinIO audit logs.
2. **Restore versioned objects.**
   ```bash
   BUCKET="medusa-artifacts-prod"
   aws s3api list-object-versions --bucket "$BUCKET" --prefix critical/ --query 'Versions[?IsLatest==`false`].{Key:Key,VersionId:VersionId}'
   aws s3api copy-object --bucket "$BUCKET" --key critical/report.json \
     --copy-source "$BUCKET/critical/report.json?versionId=<VersionId>"
   ```
3. **Rehydrate replicated region.** If the primary region is unavailable, promote the replica bucket created by [`modules/s3`](../../infra/terraform/modules/s3) by updating DNS/endpoint configuration in Terraform (`enable_replica_read_access = true`).
4. **MinIO-specific recovery.** For self-hosted MinIO (Docker or Kubernetes):
   ```bash
   docker compose exec minio mc mirror local/binary-uploads backup/binary-uploads --overwrite
   docker compose exec minio mc mirror backup/binary-uploads local/binary-uploads --overwrite
   ```
5. **Validate worker write access.**
   ```bash
   kubectl create job s3-write-check \
     --image=ghcr.io/medusa/worker-nuclei:latest \
     -- bash -lc 'python workers/web/nuclei/scripts/write_artifact.py'
   kubectl logs job/s3-write-check
   kubectl delete job s3-write-check
   ```
6. **Update runbook log.** Capture restored object keys, commands executed, and validation output hashes.

## Cross-Region Failover Procedure
1. **Trigger criteria:** Regional AWS outage, EKS control-plane instability > 30 minutes, or AWS notification of degraded availability zones.
2. **Prepare secondary region configuration.**
   - Duplicate `infra/terraform/envs/prod/terraform.tfvars` to `prod-secondary` with new `aws_region`, VPC CIDRs, and `eks_cluster_name`.
   - Ensure `modules/s3` replication and `modules/rds` cross-region read replica flags (`create_global_cluster = true`) are enabled pre-incident.
3. **Promote secondary database.**
   ```bash
   aws rds failover-db-cluster --db-cluster-identifier medusa-global-cluster --target-db-cluster-identifier medusa-prod-secondary
   terraform -chdir=infra/terraform/envs/prod-secondary apply -target=module.rds
   ```
4. **Stand up Kubernetes and workloads.**
   ```bash
   terraform -chdir=infra/terraform/envs/prod-secondary apply \
     -target=module.eks -target=module.medusa -target=module.external-secrets
   aws eks update-kubeconfig --name "$(terraform -chdir=infra/terraform/envs/prod-secondary output -raw eks_cluster_name)" --region <secondary-region>
   kubectl get nodes
   kubectl get pods --namespace medusa
   ```
5. **Synchronize secrets and configmaps.** The External Secrets Operator (provisioned via [`modules/external-secrets`](../../infra/terraform/modules/external-secrets)) pulls AWS Secrets Manager data automatically; confirm sync:
   ```bash
   kubectl get secret medusa-controller -n medusa -o yaml
   ```
6. **Cut over ingress.** Update Route53/ALB DNS records to point to the secondary region using outputs from [`modules/aws_lb_controller`](../../infra/terraform/modules/aws_lb_controller).
7. **Validate workloads.** Execute the failover validation commands below, then communicate the new endpoints to stakeholders.
8. **Post-failover cleanup.** After primary region recovery, reverse replication direction, rebuild read replicas, and plan an orderly failback using Terraform plans reviewed via pull requests.

## Validation Commands & Automation
| Scenario | Command(s) | Frequency | Evidence |
| --- | --- | --- | --- |
| Database backup restore drill | `./scripts/ci/restore-rds-snapshot.sh --env prod` (invoke via GitHub Actions nightly dry run) | Quarterly manual + CI smoke test | Attach AWS CLI output + `kubectl logs job/db-check` to runbook log. |
| Object storage restore drill | `aws s3api copy-object ...` (see above) plus `kubectl create job s3-write-check` | Quarterly | Store command transcript and SHA256 of restored artifacts. |
| Kubernetes failover simulation | `kubectl drain <node> --ignore-daemonsets --delete-emptydir-data` followed by `kubectl get pods -n medusa` | Monthly | Upload `kubectl` output to incident tracking ticket. |
| Region failover game day | `terraform -chdir=infra/terraform/envs/prod-secondary apply`, `aws rds failover-db-cluster ...`, `kubectl get pods` | Semi-annually | Capture Terraform plan/apply logs + monitoring screenshots. |

> **Recording:** CI jobs must push logs to the central observability bucket (`medusa-drills-logs`) provisioned via `modules/s3`. Manual exercises append summaries to the Exercise Log table below and link to the Jira ticket or CI run URL.

## Tabletop Exercise Schedule & Checklist

### Cadence
| Quarter | Scenario | Lead Role | Supporting Roles | Injects | Success Criteria |
| --- | --- | --- | --- | --- | --- |
| Q1 | Postgres point-in-time recovery | Incident Commander (Platform Lead) | DB Admin, Security Liaison | Surprise data corruption alarm requiring restore within RPO. | Restored cluster within 60 minutes; validation script passes; comms sent to stakeholders. |
| Q2 | Object storage deletion + ransomware simulation | Security Liaison | Platform SRE, MinIO Operator | Inject: encrypted artifacts discovered; bucket versioning tested. | Recovery of latest clean artifacts; malicious versions quarantined; audit trail documented. |
| Q3 | Regional EKS outage | Platform SRE | Network Engineer, Incident Commander | Inject: AWS health event forcing cross-region failover. | Secondary region handles traffic within 45 minutes; DNS updated; rollback plan documented. |
| Q4 | Full-stack blackout (DB + storage + control plane) | Incident Commander (Security Engineering Director) | Platform SRE, DB Admin, Communications | Inject: simultaneous DB outage and storage inconsistency requiring coordinated restore. | All services operational in secondary region; post-mortem completed; lessons learned fed into Terraform modules. |

### Roles & Responsibilities
- **Incident Commander:** Owns timeline, approves failover, coordinates communications.
- **Platform SRE:** Executes Terraform/Kubernetes steps, validates workloads, ensures RBAC compliance.
- **Database Administrator:** Manages RDS snapshots, restores, and schema validation.
- **Security Liaison:** Confirms forensics requirements, ensures no data tampering during recovery.
- **Communications Lead:** Provides status updates to leadership and customers.

### Checklist (per exercise)
- [ ] Confirm exercise scope and success criteria with leadership.
- [ ] Create Jira ticket and reference this runbook.
- [ ] Capture Terraform plan and apply outputs.
- [ ] Capture `aws rds`/`aws s3api` command outputs.
- [ ] Run `kubectl` validation commands and save logs.
- [ ] Validate application health checks (`/healthz` endpoint) and smoke tests.
- [ ] Conduct hotwash session; update docs/terraform defaults if gaps identified.
- [ ] Append summary to Exercise Log with links to evidence.

## Exercise Log Template
| Date | Scenario | RPO Achieved? | RTO Achieved? | Lead | Evidence Links | Follow-up Actions |
| --- | --- | --- | --- | --- | --- | --- |
| _YYYY-MM-DD_ | _e.g., Q3 regional failover_ | _Yes/No_ | _Yes/No_ | _Name_ | _Jira ticket, CI run URL, S3 log path_ | _Backlog issue IDs_ |

---
**Change management:** Update this runbook whenever Terraform modules change recovery parameters (endpoints, replication flags, backup retention). Submit updates via pull request with security review.
