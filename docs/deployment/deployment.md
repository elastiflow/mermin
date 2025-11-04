# Deployment Overview

This section provides comprehensive guidance for deploying Mermin in various environments, from local development to production Kubernetes clusters.

## Deployment Options

Mermin supports multiple deployment scenarios:

| Deployment Type                                  | Use Case                  | Complexity | Production Ready |
| ------------------------------------------------ | ------------------------- | ---------- | ---------------- |
| [**Kubernetes with Helm**](kubernetes-helm.md)   | Standard K8s clusters     | Low        | ✅ Yes            |
| [**Cloud Platforms**](cloud-platforms.md)        | GKE, EKS, AKS             | Low        | ✅ Yes            |
| [**Advanced Scenarios**](advanced-scenarios.md)  | Custom CNI, multi-cluster | Medium     | ✅ Yes            |
| [**Docker on Bare Metal**](docker-bare-metal.md) | Non-K8s Linux hosts       | Medium     | ⚠️ Limited       |

## Architecture Considerations

### DaemonSet Pattern

Mermin is typically deployed as a Kubernetes DaemonSet, which ensures:

* **One Pod Per Node**: Each node runs its own Mermin agent
* **Automatic Scaling**: New nodes automatically get Mermin pods
* **Node Affinity**: Pods can target specific node pools or architectures
* **Resource Isolation**: Each agent operates independently

### Resource Requirements

Plan your deployment based on these resource guidelines:

**Minimum Resources** (for low-traffic environments):

* CPU: 100m (0.1 cores)
* Memory: 128 Mi

**Recommended Resources** (for moderate traffic):

* CPU: 500m (0.5 cores)
* Memory: 256 Mi

**High-Traffic Resources** (for busy production nodes):

* CPU: 1-2 cores
* Memory: 512 Mi - 1 Gi

Actual requirements vary based on:

* Network traffic volume
* Number of pods per node
* Flow timeout configurations
* OTLP batch sizes and export frequency

{% hint style="info" %}
Start with recommended resources and adjust based on observed CPU and memory usage. Monitor metrics at `/metrics` endpoint.
{% endhint %}

### Network Interface Selection

Mermin captures traffic from network interfaces matching your configured patterns. Choose interfaces based on your observability goals:

**Inter-Node Traffic** (default):

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "en*"]
}
```

Captures traffic between nodes, to/from external networks, and through the node.

**Intra-Node Traffic** (pod-to-pod on same node):

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "cni*", "gke*", "cilium_*"]
}
```

Includes CNI bridge interfaces but may cause duplicate flow records for inter-node traffic.

See [Network Interface Discovery](../configuration/discovery-interfaces.md) for details.

## Prerequisites by Environment

### All Environments

* Linux kernel 4.18 or newer with eBPF support
* Privileged container support
* Network access to OTLP collector endpoint

### Kubernetes

* Kubernetes 1.20 or newer
* Helm 3.x
* kubectl configured for cluster access
* Permissions to create ClusterRole and ClusterRoleBinding
* Privileged DaemonSets allowed (most clusters)

### Cloud Platforms

**GKE (Google Kubernetes Engine)**:

* GKE Standard or Autopilot (with Autopilot limitations)
* Node OS: Container-Optimized OS (COS) or Ubuntu
* Workload Identity (optional, for managed identity)

**EKS (Amazon Elastic Kubernetes Service)**:

* EKS 1.20 or newer
* Amazon Linux 2 or Bottlerocket node OS
* IAM roles for service accounts (optional)

**AKS (Azure Kubernetes Service)**:

* AKS 1.20 or newer
* Ubuntu or Azure Linux node OS
* Azure AD pod identity (optional)

### Bare Metal / Virtual Machines

* Linux distribution with kernel 4.18+
* Docker or containerd installed
* Root/sudo access to run privileged containers
* No Kubernetes metadata enrichment available

## Security Considerations

### Required Privileges

Mermin requires elevated privileges to function:

```yaml
securityContext:
  privileged: true
  capabilities:
    add:
      - SYS_ADMIN
      - NET_ADMIN
      - BPF
```

This is necessary to:

* Load eBPF programs into the kernel
* Attach to network interfaces
* Access the host network namespace

{% hint style="warning" %}
Never reduce these privileges. Mermin will fail to start without them.
{% endhint %}

### RBAC Permissions

Mermin needs read access to Kubernetes resources for metadata enrichment:

* `get`, `list`, `watch` on pods, services, deployments, etc.
* Cluster-wide access (all namespaces)
* Non-sensitive data only (no secrets)

The Helm chart creates a minimal ClusterRole with only necessary permissions.

### Network Policies

If using Kubernetes NetworkPolicies:

* **Egress to OTLP Collector**: Allow traffic to your collector endpoint
* **Egress to Kubernetes API**: Allow access to the API server (typically allowed by default)
* **No Ingress Required**: Mermin doesn't accept inbound connections (except health checks)

Example egress policy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mermin-egress
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: mermin
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: otel-collector
      ports:
        - protocol: TCP
          port: 4317
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 6443  # Kubernetes API
```

## Deployment Checklist

Before deploying Mermin to production:

* [ ] Review [Architecture](../getting-started/architecture.md) to understand how Mermin works
* [ ] Choose appropriate [deployment method](deployment.md#deployment-options)
* [ ] Plan [resource allocation](deployment.md#resource-requirements)
* [ ] Configure [network interfaces](../configuration/discovery-interfaces.md)
* [ ] Set up [OTLP collector](../integrations/opentelemetry-collector.md) endpoint
* [ ] Configure [authentication and TLS](../configuration/export-otlp.md) for OTLP
* [ ] Define [flow filters](../configuration/filtering.md) if needed
* [ ] Set appropriate [resource limits](kubernetes-helm.md)
* [ ] Test in non-production environment first
* [ ] Monitor [metrics](../configuration/api-metrics.md) after deployment
* [ ] Review [troubleshooting guide](../troubleshooting/troubleshooting.md)

## Upgrade Strategy

When upgrading Mermin:

1. **Review Release Notes**: Check for breaking changes or new features
2. **Update Helm Chart**: `helm repo update` for chart updates
3. **Test in Staging**: Always test upgrades in non-production first
4. **Rolling Update**: DaemonSet controller performs rolling updates automatically
5. **Monitor Health**: Watch pod status and metrics during rollout
6. **Rollback if Needed**: `helm rollback mermin` to revert

The DaemonSet `updateStrategy` controls upgrade behavior:

```yaml
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1  # Update one node at a time
```

## Next Steps

Choose your deployment path:

* **Standard Kubernetes**: [Kubernetes with Helm](kubernetes-helm.md)
* **Cloud Platform**: [GKE, EKS, or AKS](cloud-platforms.md)
* **Advanced Setup**: [Custom CNI, Multi-Cluster](advanced-scenarios.md)
* **Non-Kubernetes**: [Docker on Bare Metal](docker-bare-metal.md)

After deploying, configure Mermin for your environment:

* [Configuration Overview](../configuration/configuration.md)
* [OTLP Export Configuration](../configuration/export-otlp.md)
* [Observability Backends](../observability/backends.md)
