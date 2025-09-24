package medusa.policy.network

component_policy[component] = cfg {
  some name
  worker := input.values.workers[name]
  worker.enabled == true
  cfg := worker.networkPolicy
  not cfg.enabled == false
  component := worker.component
}

worker_policy_map[component] = policy {
  policy := input.documents[_]
  policy.kind == "NetworkPolicy"
  comp := policy.spec.podSelector.matchLabels["app.kubernetes.io/component"]
  comp != ""
  component_policy[comp] = cfg
  component := comp
}

minio_component := comp {
  comp := input.values.minio.component
} else := "minio"

minio_port := port {
  port := input.values.minio.service.apiPort
}

dns_namespace := "kube-system"

test_worker_namespace_restrictions {
  some component
  policy := worker_policy_map[component]
  not disallowed_namespace(policy)
}

disallowed_namespace(policy) {
  rule := policy.spec.egress[_]
  to := rule.to[_]
  ns := to.namespaceSelector.matchLabels["kubernetes.io/metadata.name"]
  ns != ""
  ns != dns_namespace
}

test_worker_dns_egress {
  some component
  policy := worker_policy_map[component]
  cfg := component_policy[component]
  allow := cfg.allowDNS
  allow == true
  dns_rule(policy)
}

dns_rule(policy) {
  rule := policy.spec.egress[_]
  to := rule.to[_]
  to.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == dns_namespace
  ports := {port.port | port := rule.ports[_]}
  ports == {53}
}

test_worker_artifact_storage_egress {
  some component
  policy := worker_policy_map[component]
  cfg := component_policy[component]
  cfg.allowArtifactStorage == true
  artifact_rule(policy)
}

artifact_rule(policy) {
  rule := policy.spec.egress[_]
  to := rule.to[_]
  selector := to.podSelector
  selector.matchLabels["app.kubernetes.io/component"] == minio_component
  ports := {port.port | port := rule.ports[_]}
  ports == {minio_port}
}
