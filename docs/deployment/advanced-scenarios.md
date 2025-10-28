# Advanced Scenarios

This guide covers advanced Mermin deployment scenarios including custom CNI configurations, multi-cluster deployments, high-availability setups, and performance tuning for high-throughput environments.

## Custom CNI Configurations

Different Container Network Interfaces (CNIs) create different network interface patterns. Mermin must be configured to monitor the correct interfaces.

### Cilium

Cilium uses `cilium_*` interfaces for pod networking:

```hcl
discovery "instrument" {
  # Capture both physical and Cilium interfaces
  interfaces = ["eth*", "ens*", "cilium_*"]
}
```

**Considerations:**

* Cilium's eBPF datapath is separate from Mermin's monitoring
* Monitor physical interfaces for inter-node traffic
* Monitor `cilium_*` for intra-node pod-to-pod traffic
* May see duplicate flows for traffic that crosses nodes

**Cilium-specific configuration:**

```hcl
discovery "instrument" {
  # Physical interfaces for inter-node traffic
  interfaces = ["eth*", "ens*"]

  # Add Cilium interfaces only if you need intra-node visibility
  # interfaces = ["eth*", "ens*", "cilium_*"]
}

# Cilium uses its own NetworkPolicies
discovery "informer" "k8s" {
  selectors = [
    { kind = "CiliumNetworkPolicy" },
    { kind = "Pod" },
    { kind = "Service" },
    # ... other resources
  ]
}
```

### Calico

Calico uses `cali*` interfaces for pod networking:

```hcl
discovery "instrument" {
  # Capture both physical and Calico interfaces
  interfaces = ["eth*", "ens*", "cali*"]
}
```

**Considerations:**

* Calico interfaces are `califxxxxxxxx` format
* Monitor physical interfaces for most traffic
* Add `cali*` for intra-node pod-to-pod visibility
* Be aware of potential flow duplication

### Flannel

Flannel uses CNI bridge interfaces:

```hcl
discovery "instrument" {
  # Flannel typically uses cni0 or flannel.1
  interfaces = ["eth*", "ens*", "cni*", "flannel.*"]
}
```

### Weave Net

Weave Net uses `weave` interface:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "weave"]
}
```

### Canal (Flannel + Calico)

Canal combines Flannel for networking and Calico for policies:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "cali*"]
}
```

## Multi-Cluster Deployments

For observability across multiple Kubernetes clusters:

### Strategy 1: Cluster-Specific OTLP Endpoints

Deploy Mermin in each cluster with cluster-specific configuration:

**Cluster 1 (us-west):**

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector-us-west:4317"
    protocol = "grpc"

    # Add cluster identifier as resource attribute
    resource_attributes = {
      "k8s.cluster.name" = "us-west-prod"
      "k8s.cluster.region" = "us-west-2"
    }
  }
}
```

**Cluster 2 (eu-west):**

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector-eu-west:4317"
    protocol = "grpc"

    resource_attributes = {
      "k8s.cluster.name" = "eu-west-prod"
      "k8s.cluster.region" = "eu-west-1"
    }
  }
}
```

### Strategy 2: Central OTLP Collector

All clusters send to a central collector:

```hcl
export "traces" {
  otlp = {
    endpoint = "https://central-collector.example.com:4317"
    protocol = "grpc"

    # Authentication for multi-tenant collector
    auth = {
      basic = {
        user = "cluster-us-west"
        pass = "SECRET_PASSWORD"
      }
    }

    # TLS for secure transport
    tls = {
      insecure_skip_verify = false
      ca_cert = "/etc/mermin/certs/ca.crt"
    }

    resource_attributes = {
      "k8s.cluster.name" = "us-west-prod"
    }
  }
}
```

### Strategy 3: Hierarchical Collectors

Regional collectors aggregate to central collector:

```
Cluster 1 (us-west-1) ──┐
                        ├──> Regional Collector (us-west) ──┐
Cluster 2 (us-west-2) ──┘                                   │
                                                             ├──> Central Collector ──> Backend
Cluster 3 (eu-west-1) ──┐                                   │
                        ├──> Regional Collector (eu-west) ──┘
Cluster 4 (eu-west-2) ──┘
```

Each cluster points to its regional collector, which aggregates and forwards to central.

## High-Availability Configurations

### OTLP Collector Redundancy

Configure multiple OTLP endpoints for failover:

```hcl
export "traces" {
  # Primary OTLP endpoint
  otlp = {
    endpoint = "http://otel-collector-primary:4317"
    protocol = "grpc"
    timeout = "5s"
  }

  # Note: Multiple OTLP endpoints require OpenTelemetry Collector
  # configuration with failover/retry logic
}
```

For true HA, deploy multiple OpenTelemetry Collectors behind a load balancer:

```hcl
export "traces" {
  otlp = {
    # Load balancer endpoint fronting multiple collectors
    endpoint = "http://otel-lb.example.com:4317"
    protocol = "grpc"

    # Adjust timeouts for HA scenarios
    timeout = "10s"
    max_export_timeout = "30s"

    # Increase queue for temporary outages
    max_queue_size = 4096
  }
}
```

### Mermin Agent Resilience

Mermin agents are resilient by design:

* **DaemonSet**: Automatically restarts failed pods
* **Node-local**: Failure of one agent doesn't affect others
* **Stateless**: No data loss on restart (flows are regenerated)
* **Queue-based**: Buffers flows during temporary collector outages

Configure aggressive restart policy:

```yaml
# values.yaml
podRestartPolicy: Always

livenessProbe:
  httpGet:
    path: /livez
    port: api
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: api
  initialDelaySeconds: 15
  periodSeconds: 5
  timeoutSeconds: 5
  failureThreshold: 3
```

## Resource Tuning for High-Throughput Environments

### High-Traffic Configuration

For environments with high network traffic (> 10,000 flows/second):

```hcl
# Increase internal buffering
packet_channel_capacity = 4096
packet_worker_count = 4

# Aggressive flow expiration to limit memory
span {
  max_record_interval = "30s"  # Export active flows more frequently
  generic_timeout = "15s"       # Shorter timeout for inactive flows
  tcp_timeout = "15s"
  udp_timeout = "30s"
}

# Larger batches for efficient export
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"

    # Large batches reduce overhead
    max_batch_size = 1024
    max_batch_interval = "2s"

    # Larger queue for burst traffic
    max_queue_size = 8192

    # More concurrent exports
    max_concurrent_exports = 4
  }
}
```

**Resource allocation:**

```yaml
resources:
  requests:
    cpu: 2
    memory: 1Gi
  limits:
    cpu: 4
    memory: 2Gi
```

### Low-Latency Configuration

For environments requiring low export latency:

```hcl
# Smaller batches, more frequent exports
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"

    # Small batches for low latency
    max_batch_size = 128
    max_batch_interval = "1s"  # Export every second

    # Fast timeouts
    timeout = "5s"
    max_export_timeout = "10s"
  }
}
```

### Memory-Constrained Environments

For nodes with limited memory:

```hcl
# Reduce buffer sizes
packet_channel_capacity = 512
packet_worker_count = 1

# Aggressive flow expiration
span {
  max_record_interval = "30s"
  generic_timeout = "10s"
  tcp_timeout = "10s"
  udp_timeout = "20s"
}

# Smaller export batches
export "traces" {
  otlp = {
    max_batch_size = 256
    max_queue_size = 1024
  }
}
```

**Resource limits:**

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

## Network Interface Selection Strategies

### Inter-Node Traffic Only (Default)

Capture only traffic crossing node boundaries:

```hcl
discovery "instrument" {
  # Physical interfaces only
  interfaces = ["eth*", "ens*", "en*"]
}
```

**Advantages:**

* No flow duplication
* Lower resource usage
* Clearer network topology

**Limitations:**

* Misses pod-to-pod traffic on same node
* Misses loopback traffic

### Complete Visibility (All Traffic)

Capture all traffic including intra-node:

```hcl
discovery "instrument" {
  # Physical + CNI interfaces
  interfaces = ["eth*", "ens*", "cni*", "cali*", "cilium_*", "gke*"]
}
```

**Advantages:**

* Complete network visibility
* Captures all pod-to-pod traffic

**Limitations:**

* Flow duplication for inter-node traffic
* Higher resource usage
* Requires deduplication in backend

### Selective Monitoring

Monitor specific interface patterns:

```hcl
discovery "instrument" {
  # Regex for specific interfaces
  interfaces = ["/^eth[0-9]+$/", "/^ens[0-9]+$/"]
}
```

### Dynamic Interface Discovery

Use glob patterns that adapt to host configuration:

```hcl
discovery "instrument" {
  # Matches various naming conventions
  interfaces = ["eth*", "ens*", "en*", "eno*", "enp*"]
}
```

## Performance Monitoring and Tuning

### Metrics to Monitor

Expose Mermin metrics to Prometheus:

```yaml
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "10250"
  prometheus.io/path: "/metrics"
```

Key metrics:

* `mermin_flows_total`: Total flows processed
* `mermin_packets_total`: Total packets captured
* `mermin_drops_total`: Packets dropped due to overload
* `mermin_export_errors_total`: OTLP export failures
* `mermin_flow_table_size`: Current number of active flows

### Tuning Guidelines

**If you see packet drops:**

1. Increase `packet_channel_capacity`
2. Increase `packet_worker_count`
3. Add more CPU resources
4. Reduce monitored interfaces

**If you see high memory usage:**

1. Decrease flow timeouts
2. Increase export frequency
3. Add flow filters to reduce processed flows
4. Add more memory resources

**If you see export errors:**

1. Check collector connectivity
2. Increase `max_queue_size`
3. Increase `max_export_timeout`
4. Check collector capacity

## Security Hardening

### Network Policies

Restrict Mermin's network access:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mermin-network-policy
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: mermin
  policyTypes:
    - Egress
  egress:
    # Allow OTLP export
    - to:
        - podSelector:
            matchLabels:
              app: otel-collector
      ports:
        - protocol: TCP
          port: 4317
    # Allow Kubernetes API (for informers)
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              component: apiserver
      ports:
        - protocol: TCP
          port: 443
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

### Pod Security Standards

Apply Pod Security Standards:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: mermin
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
```

Note: Mermin requires `privileged` policy due to eBPF requirements.

### Secrets Management

Use Kubernetes secrets for sensitive configuration:

```bash
# Create secret for OTLP credentials
kubectl create secret generic mermin-otlp-auth \
  --from-literal=username=mermin \
  --from-literal=password=SECRET_PASSWORD

# Reference in configuration
kubectl create configmap mermin-config \
  --from-file=config.hcl=mermin-config.hcl
```

Mount secrets in pods:

```yaml
volumes:
  - name: auth-secret
    secret:
      secretName: mermin-otlp-auth

volumeMounts:
  - name: auth-secret
    mountPath: /etc/mermin/secrets
    readOnly: true
```

Reference in HCL:

```hcl
export "traces" {
  otlp = {
    endpoint = "https://collector.example.com:4317"
    auth = {
      basic = {
        user = "mermin"
        pass = "env(OTLP_PASSWORD)"  # Load from environment
      }
    }
  }
}
```

## Next Steps

* [**Configuration Reference**](../configuration/configuration.md): Deep dive into all configuration options
* [**Filtering**](../configuration/filtering.md): Configure flow filters for security and performance
* [**Integration Guides**](../integrations/integrations.md): Connect to your observability backend
* [**Troubleshooting Performance**](../troubleshooting/performance.md): Diagnose and resolve performance issues
