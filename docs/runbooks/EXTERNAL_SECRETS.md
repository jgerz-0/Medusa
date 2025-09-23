# External Secrets Runbook

This runbook documents how Medusa operators deploy, monitor, and remediate the External Secrets Operator (ESO) that bridges our secret stores (AWS Secrets Manager by default) and Kubernetes. Treat every action as production-impacting; always capture evidence in the incident ticket before applying fixes.

## Scope and Architecture

- **Components**: `external-secrets` controller deployment, `SecretStore` or `ClusterSecretStore` custom resources, and Medusa `ExternalSecret` manifests rendered by Terraform/Helm.
- **Data flow**: Terraform wires IAM Roles for Service Accounts (IRSA) and provisions the target secrets. The ESO reconciler authenticates via the annotated service account, fetches the secret payload, and projects it into a namespace-local `Secret` consumed by Medusa pods.
- **Change management**: All configuration lives in `infra/terraform`. Manual edits with `kubectl` must be followed by a Terraform update or documented drift exception.

## Common Outages and Recovery

### 1. Controller Sync Errors

**Symptoms**

- `ExternalSecret` resources remain in `Error` or `NotReady` state.
- `kubectl describe externalsecret medusa-secrets -n medusa` shows reconciliation errors (e.g., JSON parse failures, invalid template keys).
- ESO controller logs highlight `reconciler` failures or template rendering exceptions.

**Diagnostic Commands**

```bash
kubectl get pods -n external-secrets
kubectl logs deployment/external-secrets -n external-secrets --tail=200
kubectl describe externalsecret medusa-secrets -n medusa
kubectl get secret medusa-secrets -n medusa -o yaml
```

**Response Playbook**

1. Capture the failing template block from `kubectl describe` and compare it with the Terraform module output (`infra/terraform/modules/medusa/templates/external_secret.tpl`).
2. If the error references missing data keys, inspect the source secret using AWS CLI:
   ```bash
   aws secretsmanager describe-secret --secret-id <secret_name>
   aws secretsmanager get-secret-value --secret-id <secret_name> | jq
   ```
3. Validate that Terraform rendered the correct template by running from your environment directory:
   ```bash
   cd infra/terraform/envs/<env>
   terraform plan -target=module.medusa.module.external_secrets
   ```
4. Fix malformed template variables in Terraform (`terraform.tfvars` or module overrides) and re-apply:
   ```bash
   terraform apply -target=module.medusa.module.external_secrets
   ```
5. Force a re-sync once the plan completes:
   ```bash
   kubectl annotate externalsecret medusa-secrets -n medusa external-secrets.io/refresh-trigger=$(date +%s)
   ```
6. Confirm reconciliation succeeds (`kubectl get externalsecret -n medusa` should show `Ready=True`).

### 2. SecretStore Permission Issues

**Symptoms**

- ESO events log `AccessDeniedException`, `InvalidClientTokenId`, or `failed to authenticate` messages.
- `kubectl get events -n external-secrets --field-selector involvedObject.kind=SecretStore` surfaces IRSA or credential errors.
- No Kubernetes `Secret` is created despite valid templates.

**Diagnostic Commands**

```bash
kubectl describe secretstore medusa-prod-cluster-secrets -n external-secrets
kubectl logs deployment/external-secrets -n external-secrets | grep -i access
aws iam get-role --role-name external-secrets-operator
aws sts assume-role-with-web-identity --role-arn <irsa-role-arn> --role-session-name debug --web-identity-token file://token.jwt
```

**Response Playbook**

1. Confirm the IRSA role trust relationship includes the cluster's OIDC provider and references the correct service account (`system:serviceaccount:external-secrets:external-secrets`).
2. If the Terraform state drifted, re-run IRSA provisioning:
   ```bash
   cd infra/terraform/envs/<env>
   terraform plan -target=module.external_secrets
   terraform apply -target=module.external_secrets
   ```
3. Validate the AWS policy grants `secretsmanager:GetSecretValue` on required ARNs. Update the Terraform IAM policy document if new secrets were added without updating `worker_policy_documents`.
4. Restart the controller to refresh the projected token (only after confirming IAM is correct):
   ```bash
   kubectl rollout restart deployment/external-secrets -n external-secrets
   kubectl rollout status deployment/external-secrets -n external-secrets
   ```
5. Re-describe the `SecretStore` to verify the condition is `Ready=True`.

### 3. Secret Rotation Procedures

Routine rotation is a controlled change; incident rotation (e.g., suspected compromise) must follow the security incident response plan.

**Planned Rotation via Terraform**

1. Update the secret payload in AWS Secrets Manager or HashiCorp Vault (preferred: automated rotation Lambda). Document the change ticket.
2. If the secret value lives in Terraform variables (e.g., `observability_grafana_admin_credentials`), update the value and re-run:
   ```bash
   cd infra/terraform/envs/<env>
   terraform fmt && terraform validate
   terraform plan -target=module.medusa.module.external_secrets
   terraform apply -target=module.medusa.module.external_secrets
   ```
3. Monitor ESO until the new value is synced:
   ```bash
   kubectl get externalsecret medusa-secrets -n medusa -w
   kubectl get secret medusa-secrets -n medusa -o jsonpath='{.metadata.annotations.external-secrets\.io/revision}'
   ```
4. Notify dependent services (controller, workers) if a restart is required. Most Medusa pods reload secrets on the next queue poll; only restart if the secret is mounted as a file.

**Emergency Rotation**

1. Immediately disable suspected credentials in AWS Secrets Manager by updating the secret value or scheduling deletion with a 7-day recovery window.
2. Create a new secret version with the rotated credential and tag it with the incident ticket ID.
3. Apply Terraform with `-target=module.medusa.module.external_secrets` to refresh the `ExternalSecret` template and Kubernetes secret.
4. Trigger pod restarts for affected components:
   ```bash
   kubectl rollout restart deployment/medusa-medusa-controller -n medusa
   kubectl delete pods -l app.kubernetes.io/name=medusa-worker --namespace medusa
   ```
5. Validate the secret revision and audit events (see checklists below) before closing the incident.

## Validation Checklists

### CI/CD Secret Delivery Gate

Use this checklist in pipelines or pre-deployment reviews to prevent drift from merging.

- [ ] `terraform plan` against the environment shows no pending changes to `module.external_secrets` or `module.medusa.module.external_secrets`.
- [ ] `terraform output` exposes the expected secret store name and IRSA role ARN; commit these values to environment documentation.
- [ ] `kubectl get externalsecret medusa-secrets -n medusa -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'` returns `True` in the staging cluster used for CI smoke tests.
- [ ] `kubectl get secret medusa-secrets -n medusa -o jsonpath='{.metadata.annotations.external-secrets\.io/revision}'` increments after a planned rotation rehearsal.
- [ ] Audit logs (AWS CloudTrail or Vault audit devices) confirm the ESO service account identity, not developer credentials, fetched the secret during tests.

### Incident Response Verification

Execute this checklist during an active incident before declaring remediation complete.

- [ ] Capture `kubectl describe externalsecret medusa-secrets -n medusa` output and attach it to the incident ticket.
- [ ] Confirm the `SecretStore` condition is `Ready=True` and IRSA authentication succeeded via `kubectl get secretstore -n external-secrets`.
- [ ] Validate the new secret version in AWS Secrets Manager: `aws secretsmanager get-secret-value --secret-id <secret_name> --version-stage AWSCURRENT`.
- [ ] Confirm pods consume the new material:
  ```bash
  kubectl exec -n medusa deploy/medusa-medusa-controller -- env | grep MEDUSA_
  kubectl logs -n medusa deploy/medusa-medusa-controller --since=5m | grep -i "secret rotation"
  ```
- [ ] Review CloudTrail/Vault audit entries for the rotation window and export them to the security data lake.
- [ ] Update the post-incident report with lessons learned and required Terraform follow-ups.

## Escalation

- **PagerDuty**: Notify the on-call SRE if ESO is degraded for more than 10 minutes.
- **Security**: Page the security incident commander for any emergency rotation triggered by suspected compromise.
- **Vendors**: If the outage originates from AWS Secrets Manager or the ESO upstream chart, open vendor support tickets and cross-reference the incident ID.

