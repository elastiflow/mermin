---
hidden: true
---

# Kubernetes Metadata Issues

This guide helps resolve problems with missing or incomplete Kubernetes metadata in network flows.

## Missing Pod Metadata

### Symptom

Flows are captured but don't include pod names, namespaces, or labels.

### Diagnosis

Check if Kubernetes informer is enabled:

```bash
kubectl logs mermin-xxxxx -n mermin | grep -i "informer\|kubernetes"
```

Expected output:

```
INFO Starting Kubernetes informers
INFO Synced Pod informer
INFO Synced Service informer
```

Check metrics:

```bash
curl http://localhost:10250/metrics | grep mermin_kubernetes_objects
```

If object counts are 0, informers aren't working.

### Common Causes

#### 1. Informer Not Configured

**Solution**: Ensure informer is enabled in configuration:

```hcl
discovery "informer" "k8s" {
  # K8s API connection configuration
  # Use in-cluster config (default in Kubernetes)
  # kubeconfig_path is optional
  informers_sync_timeout = "30s"
  informers_resync_period = "10m"

  selectors = [
    { kind = "Pod" },
    { kind = "Service" },
    { kind = "Node" }
  ]
}
```

#### 2. RBAC Permissions Missing

**Symptom**: Logs show permission errors:

```
ERROR Failed to list pods: pods is forbidden
```

**Solution**: Verify Mermin has required ClusterRole permissions:

```bash
kubectl describe clusterrole mermin
```

Required permissions:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "endpoints", "nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies", "ingresses"]
    verbs: ["get", "list", "watch"]
```

Apply fix:

```bash
kubectl apply -f https://raw.githubusercontent.com/elastiflow/mermin/main/charts/mermin/templates/clusterrole.yaml
```

#### 3. Informer Sync Timeout

**Symptom**: Logs show:

```
WARN Kubernetes informers did not sync within 30s
```

**Solution**: Increase sync timeout for large clusters:

```hcl
discovery "informer" "k8s" {
  informers_sync_timeout = "60s"  # Increase from 30s
  # ... rest of configuration
}
```

#### 4. Wrong Namespace Filtered

If namespace filtering is configured, pods outside those namespaces won't have metadata.

**Check configuration**:

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "Pod", namespaces = ["production"] }  # Only watching "production"
  ]
}
```

**Solution**: Add missing namespaces or remove filter:

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "Pod" }  # No namespaces = watch all namespaces
  ]
}
```

## Incomplete Owner Information

### Symptom

Flows show pod information but not deployment, statefulset, or other owner metadata.

### Diagnosis

Check logs for owner resolution:

```bash
kubectl logs mermin-xxxxx -n mermin -grep -i owner
```

### Common Causes

#### 1. Owner Relations Not Configured

**Solution**: Enable owner relations:

```hcl
discovery "owners" {
  max_depth = 5  # Walk up to 5 levels (Pod -> ReplicaSet -> Deployment)

  # Optionally filter
  include_kinds = ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
}
```

#### 2. Insufficient Max Depth

**Symptom**: Shows ReplicaSet but not Deployment.

**Solution**: Increase `max_depth`:

```hcl
discovery "owners" {
  max_depth = 10  # Increase to walk deeper owner chains
}
```

#### 3. Missing Workload Controller Permissions

**Symptom**: Owner metadata missing for Deployments/StatefulSets but Pod metadata present.

**Solution**: Ensure RBAC includes workload controllers:

```yaml
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "watch"]
```

## Informer Sync Failures

### Symptom

Logs repeatedly show:

```
ERROR Failed to sync Pod informer: connection refused
ERROR List operation timeout
```

### Common Causes

#### 1. Can't Reach Kubernetes API

**Diagnosis**:

```bash
# From within Mermin pod
kubectl exec mermin-xxxxx -n mermin -- curl -k https://kubernetes.default.svc
```

**Solution**: Verify network policies don't block API server access.

#### 2. API Server Overloaded

Large clusters with many watchers can overload API server.

**Solution**: Reduce watch load:

```hcl
discovery "informer" "k8s" {
  # Increase resync period (less frequent full list)
  informers_resync_period = "5m"  # From 30s

  # Watch only necessary resources
  selectors = [
    { kind = "Pod" },
    { kind = "Service" }
  ]
}
```

#### 3. Kubeconfig Issues (Non-Kubernetes Deployments)

If running outside Kubernetes (Docker bare metal), kubeconfig is required.

**Solution**:

```hcl
discovery "informer" "k8s" {
  kubeconfig_path = "/etc/kubernetes/admin.conf"
  # ... rest of configuration
}
```

Ensure kubeconfig is mounted and accessible.

## Missing Service or Endpoint Metadata

### Symptom

Flows show destination pod but not service name.

### Common Causes

#### 1. Service Informer Not Enabled

**Solution**:

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "Service" },
    { kind = "Endpoint" },      # For Kubernetes <1.21
    { kind = "EndpointSlice" }  # For Kubernetes >=1.21
  ]
}
```

#### 2. Service Has No Endpoints

Service metadata only appears if service endpoints exist.

**Diagnosis**:

```bash
kubectl get endpoints <service-name> -n <namespace>
```

If endpoints are empty, service won't be associated with flows.

## Missing NetworkPolicy Metadata

### Symptom

No NetworkPolicy information in flows.

### Solution

Enable NetworkPolicy informer and selector relations:

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "NetworkPolicy" }
  ]

  selector_relations = [
    {
      kind = "NetworkPolicy"
      to = "Pod"
      selector_match_labels_field = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    }
  ]
}
```

## Label and Annotation Filtering

### Symptom

Some labels/annotations are missing from flows.

Mermin extracts all labels and annotations by default, but you can filter:

```hcl
attributes {
  source {
    extract {
      pod_labels = ["app", "version"]  # Only these labels
      pod_annotations = []              # No annotations
    }
  }
}
```

**Solution**: Remove or adjust filters to include desired labels/annotations.

## Verifying Metadata Enrichment

### Test Flow with Known Pod

1. **Generate traffic from a known pod**:

```bash
kubectl run test-client --image=curlimages/curl --labels="app=test" \
  --rm -it -- curl http://kubernetes.default.svc
```

2. **Check Mermin logs** for flow with pod metadata:

```bash
kubectl logs mermin-xxxxx -n mermin | grep "test-client"
```

Expected output includes:

```
source.pod.name: test-client
source.pod.labels.app: test
source.namespace: default
```

## Next Steps

* [**Configuration: Kubernetes Informers**](../configuration/kubernetes-informers.md): Detailed informer configuration
* [**Configuration: Owner Relations**](../configuration/kubernetes-owner-relations.md): Owner reference configuration
* [**Configuration: Attributes**](../configuration/attributes-source-k8s.md): Flow attribute extraction
* [**Deployment Issues**](deployment-issues.md): RBAC configuration
