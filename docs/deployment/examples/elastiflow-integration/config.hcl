# Mermin Configuration for Elastiflow Integration
# This configuration addresses common requirements for integrating Mermin with Elastiflow flow collectors

log_level = "info"

# Pipeline configuration
pipeline {
  flow_capture {
    flow_stats_capacity  = 100000
    flow_events_capacity  = 1024
  }
  flow_producer {
    workers                  = 4
    worker_queue_capacity    = 2048
    flow_store_poll_interval = "5s"
    flow_span_queue_capacity = 16384
  }
  k8s_decorator {
    threads                       = 4
    decorated_span_queue_capacity = 32768
  }
}

# Network interface discovery: omit to use defaults.
# Mermin exports flow spans (OTLP traces); you don't need to configure the underlay.
# Default discovery covers veth*, tunnel, and CNI interfaces for pod and inter-node traffic.

# Kubernetes informer configuration
discovery "informer" "k8s" {
  kubeconfig_path        = ""    # Use in-cluster config
  informers_sync_timeout = "30s"

  # Resource selectors - control which resources are watched
  selectors = [
    # Include standard resources
    { kind = "Service" },
    { kind = "Endpoint" },
    { kind = "EndpointSlice" },
    { kind = "Gateway" },
    { kind = "Ingress" },
    { kind = "Pod" },
    { kind = "ReplicaSet" },
    { kind = "Deployment" },
    { kind = "Daemonset" },
    { kind = "StatefulSet" },
    { kind = "Job" },
    { kind = "CronJob" },
    { kind = "NetworkPolicy" },
    
    # Example: Exclude namespace "XYZ" from flow generation
    # Uncomment and modify as needed
    # {
    #   namespaces = ["XYZ"]
    #   kind       = "Pod"
    #   include    = false
    # },
    # {
    #   namespaces = ["XYZ"]
    #   kind       = "Service"
    #   include    = false
    # },
    # {
    #   namespaces = ["XYZ"]
    #   kind       = "Deployment"
    #   include    = false
    # },
  ]

  # Owner relations - walk owner references to get workload metadata
  owner_relations = {
    max_depth = 5
    include_kinds = [
      "Deployment",
      "ReplicaSet",
      "StatefulSet",
      "DaemonSet",
      "Job",
      "CronJob",
    ]
    exclude_kinds = [
      "EndpointSlice",
    ]
  }

  # Selector relations - match Services and NetworkPolicies to Pods
  selector_relations = [
    {
      kind                        = "NetworkPolicy"
      to                          = "Pod"
      selector_match_labels_field = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },
    {
      kind                        = "Service"
      to                          = "Pod"
      selector_match_labels_field = "spec.selector"
    },
  ]
}

# Source IP/port attribution configuration
attributes "source" "k8s" {
  extract {
    # Extract standard metadata (namespace, name, uid)
    # These provide stable keys for enrichment even with ephemeral IPs
    metadata = [
      "[*].metadata.namespace",  # Required for namespace-based enrichment keys
      "[*].metadata.name",       # Required for name-based enrichment keys
      "[*].metadata.uid",        # Required for UID-based enrichment keys (most stable)
    ]

    # NOTE: Label and annotation extraction is NOT YET SUPPORTED
    # The following blocks will not work until the feature is implemented:
    #
    # label {
    #   from      = "service"
    #   key_regex = "app.kubernetes.io/(.*)"
    #   attribute = "$1"
    # }
    #
    # annotation {
    #   from      = "pod"
    #   key       = "app.kubernetes.io/component"
    #   attribute = "component"
    # }
  }

  association {
    # Pod association - maps source IP/port to pod metadata
    # Container name is automatically extracted when port matches
    pod = {
      sources = [
        {
          from = "source.ip",
          to   = [
            "status.podIP",
            "status.podIPs[*]",
            "status.hostIP",
            "status.hostIPs[*]",
          ]
        },
        {
          from = "source.port",
          to   = [
            "spec.containers[*].ports[*].containerPort",
            "spec.containers[*].ports[*].hostPort",
          ]
        },
        {
          from = "network.transport",
          to   = ["spec.containers[*].ports[*].protocol"]
        },
      ]
    }

    # Node association - for host networking scenarios
    node = {
      sources = [
        {
          from = "source.ip",
          to   = ["status.addresses[*].address"]
        },
      ]
    }

    # Service association - maps source IP/port to service metadata
    service = {
      sources = [
        {
          from = "source.ip",
          to   = [
            "spec.clusterIP",
            "spec.clusterIPs[*]",
            "spec.externalIPs[*]",
            "spec.loadBalancerIP",
            "spec.externalName",
          ]
        },
        {
          from = "source.port",
          to   = ["spec.ports[*].port"]
        },
        {
          from = "network.transport",
          to   = ["spec.ports[*].protocol"]
        },
        {
          from = "network.type",
          to   = ["spec.ipFamilies[*]"]
        },
      ]
    }

    # EndpointSlice association
    endpointslice = {
      sources = [
        {
          from = "source.ip",
          to   = ["endpoints[*].addresses[*]"]
        },
        {
          from = "source.port",
          to   = ["ports[*].port"]
        },
        {
          from = "network.transport",
          to   = ["ports[*].protocol"]
        },
        {
          from = "network.type",
          to   = ["addressType"]
        },
      ]
    }

    # Ingress association - for OCP routes
    ingress = {
      sources = [
        {
          from = "source.ip",
          to   = [
            "status.loadBalancer.ingress[*].ip",
            "status.loadBalancer.ingress[*].hostname",
          ]
        },
        {
          from = "source.port",
          to   = [
            "spec.defaultBackend.service.port",
            "spec.rules[*].http.paths[*].backend.service.port.number",
          ]
        },
      ]
    }

    # Gateway association - for Gateway API routes
    gateway = {
      sources = [
        {
          from = "source.ip",
          to   = [
            "spec.addresses[*].value",
            "status.addresses[*].value",
          ]
        },
        {
          from = "source.port",
          to   = ["spec.listeners[*].port"]
        },
      ]
    }
  }
}

# Destination IP/port attribution configuration
attributes "destination" "k8s" {
  extract {
    # Same metadata extraction as source
    metadata = [
      "[*].metadata.namespace",
      "[*].metadata.name",
      "[*].metadata.uid",
    ]
  }

  association {
    # Pod association
    pod = {
      sources = [
        {
          from = "destination.ip",
          to   = [
            "status.podIP",
            "status.podIPs[*]",
            "status.hostIP",
            "status.hostIPs[*]",
          ]
        },
        {
          from = "destination.port",
          to   = [
            "spec.containers[*].ports[*].containerPort",
            "spec.containers[*].ports[*].hostPort",
          ]
        },
        {
          from = "network.transport",
          to   = ["spec.containers[*].ports[*].protocol"]
        },
      ]
    }

    # Node association
    node = {
      sources = [
        {
          from = "destination.ip",
          to   = ["status.addresses[*].address"]
        },
      ]
    }

    # Service association
    service = {
      sources = [
        {
          from = "destination.ip",
          to   = [
            "spec.clusterIP",
            "spec.clusterIPs[*]",
            "spec.externalIPs[*]",
            "spec.loadBalancerIP",
            "spec.externalName",
          ]
        },
        {
          from = "destination.port",
          to   = ["spec.ports[*].port"]
        },
        {
          from = "network.transport",
          to   = ["spec.ports[*].protocol"]
        },
        {
          from = "network.type",
          to   = ["spec.ipFamilies[*]"]
        },
      ]
    }

    # EndpointSlice association
    endpointslice = {
      sources = [
        {
          from = "destination.ip",
          to   = ["endpoints[*].addresses[*]"]
        },
        {
          from = "destination.port",
          to   = ["ports[*].port"]
        },
        {
          from = "network.transport",
          to   = ["ports[*].protocol"]
        },
      ]
    }

    # Ingress association
    ingress = {
      sources = [
        {
          from = "destination.ip",
          to   = [
            "status.loadBalancer.ingress[*].ip",
            "status.loadBalancer.ingress[*].hostname",
          ]
        },
        {
          from = "destination.port",
          to   = [
            "spec.defaultBackend.service.port",
            "spec.rules[*].http.paths[*].backend.service.port.number",
          ]
        },
      ]
    }

    # Gateway association
    gateway = {
      sources = [
        {
          from = "destination.ip",
          to   = [
            "spec.addresses[*].value",
            "status.addresses[*].value",
          ]
        },
        {
          from = "destination.port",
          to   = ["spec.listeners[*].port"]
        },
      ]
    }
  }
}

# Flow filtering (optional)
# Uncomment and modify to exclude specific flows
# filter "source" {
#   address = {
#     match     = []
#     not_match = []  # Example: ["10.42.100.0/24"] to exclude namespace XYZ IPs
#   }
#   port = {
#     match     = []
#     not_match = []
#   }
# }
#
# filter "destination" {
#   address = {
#     match     = []
#     not_match = []  # Example: ["10.42.100.0/24"] to exclude namespace XYZ IPs
#   }
#   port = {
#     match     = []
#     not_match = []
#   }
# }

# Flow span configuration
span {
  max_record_interval        = "60s"
  generic_timeout            = "30s"
  icmp_timeout               = "10s"
  tcp_timeout                = "20s"
  tcp_fin_timeout            = "5s"
  tcp_rst_timeout            = "5s"
  udp_timeout                = "60s"
  community_id_seed          = 0
  trace_id_timeout           = "24h"
  enable_hostname_resolution  = true
  hostname_resolve_timeout    = "100ms"
}

# OTLP exporter configuration
export "traces" {
  otlp = {
    endpoint               = "http://otel-collector:4317"
    protocol               = "grpc"
    timeout                = "10s"
    max_batch_size         = 512
    max_batch_interval     = "5s"
    max_queue_size         = 32768
    max_concurrent_exports = 1
    max_export_timeout     = "10s"

    # Uncomment and configure if authentication is required
    # auth = {
    #   basic = {
    #     user = "USERNAME"
    #     pass = "PASSWORD"
    #   }
    # }

    # Uncomment and configure if TLS is required
    # tls = {
    #   insecure_skip_verify = false
    #   ca_cert              = "/etc/certs/ca.crt"
    #   client_cert          = "/etc/certs/cert.crt"
    #   client_key           = "/etc/certs/cert.key"
    # }
  }
}

# Internal metrics server (Prometheus)
internal "metrics" {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 10250
  debug_metrics_enabled = false
  stale_metric_ttl = "5m"
}

# Internal HTTP server (health checks)
internal "server" {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 8080
}
