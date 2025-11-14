---
hidden: true
---

# Kubernetes with Helm

This guide covers deploying Mermin to a Kubernetes cluster using Helm, the recommended method for production deployments.

## Prerequisites

Before you begin, ensure you have:

* **Kubernetes cluster**: Version 1.20 or newer, with `kubectl` configured
* **Helm**: Version 3.x installed ([installation guide](https://helm.sh/docs/intro/install/))
* **Cluster permissions**: Ability to create ClusterRole, ClusterRoleBinding, and DaemonSets
* **OTLP endpoint**: An OpenTelemetry Collector or compatible backend to receive flows

## Installation

### Step 1: Add the Helm Repository

{% hint style="info" %}
If installing from a local clone of the Mermin repository, skip this step and use the local chart path instead.
{% endhint %}

```bash
# Add the Mermin Helm repository (when available)
helm repo add mermin https://elastiflow.github.io/mermin
helm repo update
```

### Step 2: Create a Configuration File

Create an HCL configuration file for Mermin. Start with this minimal production configuration:

```hcl
# mermin-config.hcl

# Logging level
log_level = "info"

# Network interfaces to monitor
discovery "instrument" {
  interfaces = ["eth*", "ens*"]
}

# Configure Kubernetes informer and resources to watch
discovery "informer" "k8s" {
  # K8s API connection configuration
  informers_sync_timeout = "30s"   # Sync timeout for initial load

  selectors = [
    { kind = "Service" },
    { kind = "Endpoint" },
    { kind = "EndpointSlice" },
    { kind = "Pod" },
    { kind = "ReplicaSet" },
    { kind = "Deployment" },
    { kind = "DaemonSet" },
    { kind = "StatefulSet" },
    { kind = "Job" },
    { kind = "CronJob" },
  ]

  # Owner reference walking configuration
  owner_relations = {
    max_depth = 5
    include_kinds = []  # Empty = include all
    exclude_kinds = []
  }
}

# Flow attributes configuration (source)
attributes "source" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.namespace",
      "[*].metadata.uid",
    ]
  }

  association {
    pod = {
      sources = [
        {
          from = "flow", name = "source.ip",
          to = ["status.podIP", "status.podIPs[*]"]
        }
      ]
    }
    service = {
      sources = [
        {
          from = "flow", name = "source.ip",
          to = ["spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]"]
        },
        { from = "flow", name = "source.port", to = ["spec.ports[*].port"] }
      ]
    }
  }
}

# Flow attributes configuration (destination)
attributes "destination" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.namespace",
      "[*].metadata.uid",
    ]
  }

  association {
    pod = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to = ["status.podIP", "status.podIPs[*]"]
        }
      ]
    }
    service = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to = ["spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]"]
        },
        { from = "flow", name = "destination.port", to = ["spec.ports[*].port"] }
      ]
    }
  }
}

# Flow span configuration
span {
  max_record_interval = "60s"
  generic_timeout = "30s"
  icmp_timeout = "10s"
  tcp_timeout = "20s"
  tcp_fin_timeout = "5s"
  tcp_rst_timeout = "5s"
  udp_timeout = "60s"
  community_id_seed = 0
}

# OTLP exporter configuration
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
    timeout = "10s"
    max_batch_size = 512
    max_batch_interval = "5s"
    max_queue_size = 2048
    max_concurrent_exports = 1
    max_export_timeout = "30s"
  }
}

# API server configuration (health checks)
api {
  enabled = true
  listen_address = "0.0.0.0"
  port = 8080
}

# Metrics server configuration (Prometheus)
metrics {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250
}
```

Replace `http://otel-collector:4317` with your actual OTLP collector endpoint.

### Step 3: Deploy with Helm

Install Mermin using the Helm chart:

```bash
# Using remote chart (when available)
helm install mermin mermin/mermin \
  --set-file config.content=mermin-config.hcl \
  --wait \
  --timeout 10m

# Or using local chart from repository
helm install mermin ./charts/mermin \
  --set-file config.content=mermin-config.hcl \
  --wait \
  --timeout 10m
```

The `--wait` flag ensures Helm waits for all pods to be ready before returning.

### Step 4: Verify the Deployment

Check that Mermin pods are running:

```bash
kubectl get pods -l app.kubernetes.io/name=mermin
```

You should see one pod per node:

```
NAME           READY   STATUS    RESTARTS   AGE
mermin-abc123  1/1     Running   0          2m
mermin-def456  1/1     Running   0          2m
mermin-ghi789  1/1     Running   0          2m
```

Check the logs:

```bash
kubectl logs -l app.kubernetes.io/name=mermin --tail=50
```

Verify health endpoints:

```bash
POD=$(kubectl get pod -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -- wget -q -O- http://localhost:8080/livez
kubectl exec $POD -- wget -q -O- http://localhost:8080/readyz
```

Both should return `ok`.

## Configuration via values.yaml

Alternatively, you can configure Mermin using Helm values. Create a `values.yaml` file:

```yaml
# values.yaml

image:
  repository: ghcr.io/elastiflow/mermin
  tag: "latest"
  pullPolicy: IfNotPresent

# Resource limits
resources:
  limits:
    cpu: 1
    memory: 512Mi
  requests:
    cpu: 500m
    memory: 256Mi

# Configuration
config:
  # Restart pods when config changes
  restartOnConfigChange: true

  # Enable host PID namespace for process enrichment
  hostPidEnrichment: true

  # Inline HCL configuration
  content: |
    log_level = "info"

    discovery "instrument" {
      interfaces = ["eth*", "ens*"]
    }

    export "traces" {
      otlp = {
        endpoint = "http://otel-collector:4317"
        protocol = "grpc"
      }
    }

# Tolerations for scheduling
tolerations:
  - effect: NoSchedule
    operator: Exists

# Node selector
nodeSelector: {}
  # Example: Only deploy to specific nodes
  # node-role.kubernetes.io/worker: "true"

# Pod annotations
podAnnotations: {}
  # Example: Prometheus scraping
  # prometheus.io/scrape: "true"
  # prometheus.io/port: "10250"

# Service account
serviceAccount:
  create: true
  annotations: {}
  name: ""
```

Deploy with values file:

```bash
helm install mermin mermin/mermin -f values.yaml --wait
```

## Configuration via HCL File

For complex configurations, using a dedicated HCL file is cleaner:

```bash
helm install mermin mermin/mermin \
  --set-file config.content=mermin-config.hcl \
  -f values.yaml \
  --wait
```

The HCL file takes precedence over inline configuration in `values.yaml`.

## DaemonSet Deployment Pattern

Mermin is deployed as a DaemonSet, which means:

* **Automatic Node Coverage**: Every node gets a Mermin pod
* **Node Addition**: New nodes automatically get Mermin pods
* **Node Removal**: Pods are removed when nodes are drained
* **Rolling Updates**: Updates happen one node at a time (configurable)

The DaemonSet spec includes:

```yaml
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1  # Update one node at a time
    maxSurge: 0
```

This ensures zero downtime during updates, with only one node's Mermin pod down at a time.

## Resource Configuration

Set appropriate resource limits based on your traffic:

**Low Traffic** (< 1,000 flows/second):

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

**Medium Traffic** (1,000-10,000 flows/second):

```yaml
resources:
  requests:
    cpu: 500m
    memory: 256Mi
  limits:
    cpu: 1
    memory: 512Mi
```

**High Traffic** (> 10,000 flows/second):

```yaml
resources:
  requests:
    cpu: 1
    memory: 512Mi
  limits:
    cpu: 2
    memory: 1Gi
```

Monitor actual usage via metrics endpoint and adjust accordingly.

## Upgrading Mermin

### Upgrade Helm Chart and Application

```bash
# Update Helm repository
helm repo update

# Upgrade to latest version
helm upgrade mermin mermin/mermin \
  --set-file config.content=mermin-config.hcl \
  --wait \
  --timeout 10m

# Or upgrade from local chart
helm upgrade mermin ./charts/mermin \
  --set-file config.content=mermin-config.hcl \
  --wait
```

### Upgrade Only Configuration

To update just the configuration without changing the version:

```bash
helm upgrade mermin mermin/mermin \
  --reuse-values \
  --set-file config.content=mermin-config.hcl
```

With `config.restartOnConfigChange: true`, pods will restart automatically with new configuration.

### Rollback

If an upgrade causes issues, rollback to the previous release:

```bash
# View release history
helm history mermin

# Rollback to previous version
helm rollback mermin

# Rollback to specific revision
helm rollback mermin 3
```

## Uninstalling Mermin

To remove Mermin from your cluster:

```bash
helm uninstall mermin
```

This removes all Mermin resources except:

* Custom resource definitions (if any)
* Persistent volumes (if any)
* Namespace (if created by you)

To fully clean up:

```bash
# Remove any leftover resources
kubectl delete clusterrole mermin
kubectl delete clusterrolebinding mermin
kubectl delete serviceaccount mermin -n default
```

## Advanced Configuration

### Custom Image Repository

Use a private registry:

```yaml
image:
  repository: my-registry.com/mermin
  tag: "v1.0.0"
  pullPolicy: Always

imagePullSecrets:
  - name: my-registry-secret
```

### Node Affinity

Deploy only to specific nodes:

```yaml
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/worker
              operator: In
              values:
                - "true"
```

### Priority Class

Set pod priority:

```yaml
priorityClassName: system-node-critical
```

### Host PID Namespace

Enable process enrichment (requires `hostPidEnrichment: true`):

```yaml
config:
  hostPidEnrichment: true
```

This allows Mermin to map network flows to specific processes on the host.

## Troubleshooting

### Pods Not Starting

Check events:

```bash
kubectl describe pod <pod-name>
```

Common issues:

* Insufficient privileges: Ensure `privileged: true` is set
* Image pull errors: Check `imagePullSecrets` and registry access
* Resource limits: Ensure nodes have sufficient CPU/memory

### No Flow Traces

Check logs for errors:

```bash
kubectl logs <pod-name> | grep -i error
```

Common issues:

* No matching interfaces: Check `discovery.instrument.interfaces` configuration
* eBPF load failure: Ensure kernel version >= 4.18 with eBPF support
* OTLP connection failure: Verify collector endpoint and network policies

### High Resource Usage

Monitor metrics:

```bash
kubectl port-forward <pod-name> 10250:10250
curl http://localhost:10250/metrics
```

Adjust configuration:

* Increase flow timeouts to reduce flow table size
* Decrease batch frequency to reduce CPU
* Add flow filters to reduce processed flows

See [Troubleshooting Guide](../troubleshooting/troubleshooting.md) for more solutions.

## Next Steps

* [**Configure OTLP Export**](../configuration/export-otlp.md): Set up authentication and TLS
* [**Customize Filters**](../configuration/filtering.md): Filter flows before export
* [**Observability Backends**](../observability/backends.md): Send Flow Traces to your backend
* [**Monitor Mermin**](../configuration/api-metrics.md): Set up Prometheus scraping
