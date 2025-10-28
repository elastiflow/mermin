# Configuration Examples

This page provides complete, real-world configuration examples for common Mermin deployment scenarios.

## Production-Ready Configuration

Optimized for reliability, security, and comprehensive observability in production environments.

```hcl
# Production configuration for Mermin
log_level = "info"
shutdown_timeout = "30s"

# Optimized for production load
packet_worker_count = 8
packet_channel_capacity = 4096

# API for health checks (required for liveness/readiness probes)
api {
  enabled = true
  listen_address = "0.0.0.0"
  port = 8080
}

# Metrics for Prometheus scraping
metrics {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250
}

# Standard tunnel detection
parser {
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
}

# Monitor physical and CNI interfaces
discovery "instrument" {
  interfaces = ["eth*", "ens*", "cni*"]
}

# Full Kubernetes metadata enrichment
informer "k8s" {
  informers_sync_timeout = "60s"
  informers_resync_period = "30m"

  resources {
    # Core resources
    pod = { enabled = true }
    service = { enabled = true }
    endpoint = { enabled = true }
    endpointslice = { enabled = true }
    node = { enabled = true }

    # Workload controllers
    deployment = { enabled = true }
    replicaset = { enabled = true }
    statefulset = { enabled = true }
    daemonset = { enabled = true }
    job = { enabled = true }
    cronjob = { enabled = true }

    # Networking
    networkpolicy = { enabled = true }
    ingress = { enabled = true }
  }
}

# Walk owner references for workload attribution
discovery "owners" {
  max_depth = 10
  include_kinds = [
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob"
  ]
}

# Enable selector-based relations (NetworkPolicy, Service)
discovery "selector_relations" {}

# Extract comprehensive source metadata
attributes {
  source {
    extract {
      pod_labels = []          # All labels
      pod_annotations = []      # All annotations
      namespace_labels = []
    }

    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
      endpoint = { enabled = true }
      endpointslice = { enabled = true }
      ingress = { enabled = true }
      networkpolicy = { enabled = true }
    }
  }

  destination {
    extract {
      pod_labels = []
      pod_annotations = []
      namespace_labels = []
    }

    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
      endpoint = { enabled = true }
      endpointslice = { enabled = true }
      ingress = { enabled = true }
      networkpolicy = { enabled = true }
    }
  }
}

# Balanced flow timeouts
span {
  max_record_interval = "1m"
  generic_timeout = "2m"
  icmp_timeout = "30s"
  tcp_timeout = "5m"
  tcp_fin_timeout = "30s"
  tcp_rst_timeout = "15s"
  udp_timeout = "1m"
  community_id_seed = 0
}

# Secure OTLP export with TLS and authentication
export "traces" {
  otlp = {
    endpoint = "otel-collector.observability.svc.cluster.local:4317"
    protocol = "grpc"
    timeout = "30s"

    # Batching for efficiency
    max_batch_size = 1024
    max_batch_interval = "10s"
    max_queue_size = 4096
    max_concurrent_exports = 4
    max_export_timeout = "1m"

    # TLS with CA verification
    tls = {
      insecure = false
      ca_file = "/etc/mermin/certs/ca.crt"
    }

    # Basic authentication
    auth = {
      basic = {
        username = "${OTLP_USERNAME}"
        password = "${OTLP_PASSWORD}"
      }
    }
  }
}
```

## Development/Testing Configuration

Simplified configuration for local development and testing with stdout export.

```hcl
# Development configuration
log_level = "debug"  # Verbose logging for troubleshooting

api {
  enabled = true
  port = 8080
}

metrics {
  enabled = true
  port = 10250
}

# Simple interface pattern for kind clusters
discovery "instrument" {
  interfaces = ["eth*", "cni*"]
}

# Basic Kubernetes enrichment
informer "k8s" {
  resources {
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
  }
}

# Simple owner tracking
discovery "owners" {
  max_depth = 5
}

# Minimal metadata extraction
attributes {
  source {
    association {
      pod = { enabled = true }
      service = { enabled = true }
    }
  }
  destination {
    association {
      pod = { enabled = true }
      service = { enabled = true }
    }
  }
}

# Short timeouts for quick testing
span {
  max_record_interval = "15s"
  generic_timeout = "30s"
}

# Output to stdout for easy inspection
export "traces" {
  stdout = "text_indent"

  # Also send to local collector (no TLS/auth)
  otlp = {
    endpoint = "localhost:4317"
    protocol = "grpc"
    tls = {
      insecure = true
    }
  }
}
```

## Cilium CNI Configuration

Optimized for Kubernetes clusters using Cilium CNI.

```hcl
log_level = "info"

api {
  enabled = true
  port = 8080
}

metrics {
  enabled = true
  port = 10250
}

# Cilium-specific interfaces
discovery "instrument" {
  interfaces = [
    "eth*",      # Physical interfaces for inter-node traffic
    "cilium_*"   # Cilium veth pairs for intra-node traffic
  ]
}

informer "k8s" {
  resources {
    pod = { enabled = true }
    service = { enabled = true }
    endpoint = { enabled = true }
    node = { enabled = true }
    deployment = { enabled = true }
    networkpolicy = { enabled = true }  # Cilium NetworkPolicies
  }
}

discovery "owners" {
  max_depth = 10
}

discovery "selector_relations" {}

attributes {
  source {
    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
      networkpolicy = { enabled = true }  # Important for Cilium
    }
  }
  destination {
    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
      networkpolicy = { enabled = true }
    }
  }
}

span {
  max_record_interval = "1m"
  generic_timeout = "2m"
}

export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    protocol = "grpc"
  }
}
```

## Calico CNI Configuration

Optimized for Kubernetes clusters using Calico CNI.

```hcl
log_level = "info"

api {
  enabled = true
  port = 8080
}

metrics {
  enabled = true
  port = 10250
}

# Calico-specific interfaces
discovery "instrument" {
  interfaces = [
    "eth*",    # Physical interfaces
    "ens*",    # Alternative physical naming
    "cali*"    # Calico veth pairs
  ]
}

informer "k8s" {
  resources {
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
    deployment = { enabled = true }
    networkpolicy = { enabled = true }
  }
}

discovery "owners" {
  max_depth = 10
}

discovery "selector_relations" {}

attributes {
  source {
    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
      networkpolicy = { enabled = true }
    }
  }
  destination {
    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
      networkpolicy = { enabled = true }
    }
  }
}

span {
  max_record_interval = "1m"
  generic_timeout = "2m"
}

export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    protocol = "grpc"
  }
}
```

## High-Throughput Configuration

Optimized for high packet rate environments (>10 Gbps).

```hcl
log_level = "warn"  # Reduce logging overhead

# Maximize worker parallelism
packet_worker_count = 16
packet_channel_capacity = 16384

api {
  enabled = true
  port = 8080
}

metrics {
  enabled = true
  port = 10250
}

discovery "instrument" {
  interfaces = ["eth*", "cni*"]
}

# Optimize Kubernetes informer load
informer "k8s" {
  informers_resync_period = "1h"  # Reduce API server load

  resources {
    # Only essential resources
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }

    # Disable less critical resources
    ingress = { enabled = false }
    networkpolicy = { enabled = false }
  }
}

discovery "owners" {
  max_depth = 5  # Limit depth to reduce processing
}

# Minimal metadata extraction
attributes {
  source {
    extract {
      pod_labels = ["app", "version"]  # Only critical labels
      pod_annotations = []              # Skip annotations
    }
    association {
      pod = { enabled = true }
      service = { enabled = true }
    }
  }
  destination {
    extract {
      pod_labels = ["app", "version"]
      pod_annotations = []
    }
    association {
      pod = { enabled = true }
      service = { enabled = true }
    }
  }
}

# Aggressive flow expiry
span {
  max_record_interval = "30s"
  generic_timeout = "1m"
  tcp_timeout = "3m"
  udp_timeout = "30s"
}

# Aggressive batching for export
export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    protocol = "grpc"

    # Large batches, fast export
    max_batch_size = 4096
    max_batch_interval = "5s"
    max_queue_size = 8192
    max_concurrent_exports = 8
    timeout = "60s"
  }
}
```

## Security-Hardened Configuration

Focused on secure export and minimal attack surface.

```hcl
log_level = "info"

api {
  enabled = true
  listen_address = "127.0.0.1"  # Localhost only
  port = 8080
}

metrics {
  enabled = true
  listen_address = "127.0.0.1"  # Localhost only
  port = 10250
}

discovery "instrument" {
  interfaces = ["eth*", "cni*"]
}

# Namespace filtering for security
informer "k8s" {
  resources {
    namespace_selector = {
      match_names = ["production", "staging"]  # Only specific namespaces
    }

    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
    deployment = { enabled = true }
  }
}

discovery "owners" {
  max_depth = 10
}

attributes {
  source {
    extract {
      # Exclude sensitive annotations
      pod_annotations = []
    }
    association {
      pod = { enabled = true }
      service = { enabled = true }
    }
  }
  destination {
    extract {
      pod_annotations = []
    }
    association {
      pod = { enabled = true }
      service = { enabled = true }
    }
  }
}

span {
  max_record_interval = "1m"
  generic_timeout = "2m"
}

# Secure OTLP export with mTLS
export "traces" {
  otlp = {
    endpoint = "otel-collector.observability.svc.cluster.local:4317"
    protocol = "grpc"

    # Mutual TLS
    tls = {
      insecure = false
      ca_file = "/etc/mermin/certs/ca.crt"
      cert_file = "/etc/mermin/certs/client.crt"
      key_file = "/etc/mermin/certs/client.key"
    }

    # Authentication
    auth = {
      basic = {
        username = "${OTLP_USERNAME}"
        password = "${OTLP_PASSWORD}"
      }
    }
  }
}
```

## Multi-Backend OTLP Configuration

Export to multiple observability backends simultaneously.

```hcl
log_level = "info"

api {
  enabled = true
  port = 8080
}

metrics {
  enabled = true
  port = 10250
}

discovery "instrument" {
  interfaces = ["eth*", "cni*"]
}

informer "k8s" {
  resources {
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
    deployment = { enabled = true }
  }
}

discovery "owners" {
  max_depth = 10
}

attributes {
  source {
    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
    }
  }
  destination {
    association {
      pod = { enabled = true }
      service = { enabled = true }
      node = { enabled = true }
    }
  }
}

span {
  max_record_interval = "1m"
  generic_timeout = "2m"
}

# Note: Mermin currently supports one OTLP endpoint per instance.
# For multi-backend export, use an OpenTelemetry Collector as an intermediary:
#
#   Mermin → OTel Collector → Multiple Backends
#
# See integrations/opentelemetry-collector.md for collector configuration.

export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"  # Central collector handles fanout
    protocol = "grpc"
  }
}
```

**OpenTelemetry Collector Configuration for Multi-Backend**:

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:

processors:
  batch:

exporters:
  otlp/tempo:
    endpoint: tempo:4317

  otlp/jaeger:
    endpoint: jaeger:4317

  elasticsearch:
    endpoints: ["http://elasticsearch:9200"]

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/tempo, otlp/jaeger, elasticsearch]
```

## Cloud Platform Configurations

### GKE (Google Kubernetes Engine)

```hcl
log_level = "info"

discovery "instrument" {
  interfaces = ["eth*", "gke-*"]  # GKE-specific interfaces
}

# Standard configuration for GKE
informer "k8s" {
  resources {
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
    deployment = { enabled = true }
  }
}

discovery "owners" {
  max_depth = 10
}

span {
  max_record_interval = "1m"
  generic_timeout = "2m"
}

export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    protocol = "grpc"
  }
}
```

### EKS (Amazon Elastic Kubernetes Service)

```hcl
log_level = "info"

discovery "instrument" {
  interfaces = ["eth0"]  # EKS typically uses eth0 for pod networking
}

informer "k8s" {
  resources {
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
    deployment = { enabled = true }
  }
}

discovery "owners" {
  max_depth = 10
}

span {
  max_record_interval = "1m"
  generic_timeout = "2m"
}

export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    protocol = "grpc"
  }
}
```

### AKS (Azure Kubernetes Service)

```hcl
log_level = "info"

discovery "instrument" {
  interfaces = ["eth0", "cni*"]  # AKS with Azure CNI or Kubenet
}

informer "k8s" {
  resources {
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
    deployment = { enabled = true }
  }
}

discovery "owners" {
  max_depth = 10
}

span {
  max_record_interval = "1m"
  generic_timeout = "2m"
}

export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    protocol = "grpc"
  }
}
```

## Next Steps

* [**Global Options**](global-options.md): Reference for all global configuration fields
* [**Discovery Configuration**](discovery-interfaces.md): Interface selection details
* [**Export Configuration**](export-otlp.md): OTLP export options
* [**Deployment Guide**](../deployment/deployment.md): Deploy with your chosen configuration
