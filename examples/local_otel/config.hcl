# Mermin Configuration for Local OpenTelemetry Testing
# This configuration is designed to work with the local_otel example deployment

# Logging configuration
log_level = "info"

# Automatic configuration reloading
auto_reload = false

# Shutdown timeout
shutdown_timeout = "5s"

# Internal channel and performance related configuration options
packet_channel_capacity = 1024
packet_worker_count     = 2

# API server configuration (health endpoints)
api {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 8080
}

# Metrics server configuration (for Prometheus scraping)
metrics {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 10250
}

# Parser configuration for eBPF packet parsing
parser {
  # Tunnel port detection (IANA defaults)
  geneve_port    = 6081
  vxlan_port     = 4789
  wireguard_port = 51820

  # Maximum nested header depth
  max_header_depth = 6

  # Protocol parsing flags (defaults optimized for Kubernetes)
  parse_ipv6_hopopt    = false
  parse_ipv6_fragment  = false
  parse_ipv6_routing   = false
  parse_ipv6_dest_opts = false
}

# K8s informer configuration
informer "k8s" {
  kubeconfig_path         = ""
  informers_sync_timeout  = "30s"
  informers_resync_period = "30m"
}

# Discovery configuration
discovery "instrument" {
  # Network interfaces to monitor - default patterns for most K8s CNIs
  # Uncomment and customize if needed for your environment
  # interfaces = ["veth*", "tunl*", "ip6tnl*", "vxlan*", "flannel*", "cali*", "cilium_*", "lxc*"]

  # TC priority for program attachment (netlink only, kernel < 6.6)
  tc_priority = 50

  # TCX ordering strategy (TCX only, kernel >= 6.6)
  tcx_order = "last"
}

discovery "informer" "k8s" {
  selectors = [
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
  ]

  owner_relations = {
    max_depth = 5
    include_kinds = [
      "Service",
    ]
    exclude_kinds = [
      "EndpointSlice",
    ]
  }

  selector_relations = [
    {
      kind                             = "NetworkPolicy"
      to                               = "Pod"
      selector_match_labels_field      = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },
    {
      kind                        = "Service"
      to                          = "Pod"
      selector_match_labels_field = "spec.selector"
    },
  ]
}

# Source attributes - maps flow source data to K8s resources
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
          to   = ["status.podIP", "status.podIPs[*]", "status.hostIP", "status.hostIPs[*]"]
        },
        {
          from = "flow", name = "source.port",
          to   = ["spec.containers[*].ports[*].containerPort", "spec.containers[*].ports[*].hostPort"]
        },
        { from = "flow", name = "network.transport", to = ["spec.containers[*].ports[*].protocol"] },
      ]
    }
    node = {
      sources = [
        { from = "flow", name = "source.ip", to = ["status.addresses[*].address"] },
      ]
    }
    service = {
      sources = [
        {
          from = "flow", name = "source.ip", to = [
            "spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]", "spec.loadBalancerIP", "spec.externalName"
          ]
        },
        { from = "flow", name = "source.port", to = ["spec.ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["spec.ports[*].protocol"] },
        { from = "flow", name = "network.type", to = ["spec.ipFamilies[*]"] },
      ]
    }
    endpoint = {
      sources = [
        { from = "flow", name = "source.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "flow", name = "source.port", to = ["subsets[*].ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    endpointslice = {
      sources = [
        { from = "flow", name = "source.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "flow", name = "source.port", to = ["ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["ports[*].protocol"] },
        { from = "flow", name = "network.type", to = ["addressType"] },
      ]
    }
    ingress = {
      sources = [
        {
          from = "flow", name = "source.ip",
          to   = ["status.loadBalancer.ingress[*].ip", "status.loadBalancer.ingress[*].hostname"]
        },
        {
          from = "flow", name = "source.port",
          to   = ["spec.defaultBackend.service.port", "spec.rules[*].http.paths[*].backend.service.port.number"]
        }
      ]
    }
    gateway = {
      sources = [
        { from = "flow", name = "source.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "flow", name = "source.port", to = ["spec.listeners[*].port"] },
      ]
    }
    networkpolicy = {
      sources = [
        {
          from = "flow", name = "source.ip",
          to   = ["spec.ingress[*].from[*].ipBlock.cidr", "spec.egress[*].to[*].ipBlock.cidr"]
        },
        { from = "flow", name = "source.port", to = ["spec.ingress[*].ports[*].port", "spec.egress[*].ports[*].port"] },
        {
          from = "flow", name = "network.transport",
          to   = ["spec.ingress[*].ports[*].protocol", "spec.egress[*].ports[*].protocol"]
        },
      ]
    }
  }
}

# Destination attributes - maps flow destination data to K8s resources
attributes "destination" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.namespace",
      "pod.metadata.uid",
    ]
  }

  association {
    pod = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to   = ["status.podIP", "status.podIPs[*]", "status.hostIP", "status.hostIPs[*]"]
        },
        {
          from = "flow", name = "destination.port",
          to   = ["spec.containers[*].ports[*].containerPort", "spec.containers[*].ports[*].hostPort"]
        },
        { from = "flow", name = "network.transport", to = ["spec.containers[*].ports[*].protocol"] },
      ]
    }
    node = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["status.addresses[*].address"] },
      ]
    }
    service = {
      sources = [
        {
          from = "flow", name = "destination.ip", to = [
            "spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]", "spec.loadBalancerIP", "spec.externalName"
          ]
        },
        { from = "flow", name = "destination.port", to = ["spec.ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["spec.ports[*].protocol"] },
        { from = "flow", name = "network.type", to = ["spec.ipFamilies[*]"] },
      ]
    }
    endpoint = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "flow", name = "destination.port", to = ["subsets[*].ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    endpointslice = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "flow", name = "destination.port", to = ["ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["ports[*].protocol"] },
      ]
    }
    ingress = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to   = ["status.loadBalancer.ingress[*].ip", "status.loadBalancer.ingress[*].hostname"]
        },
        {
          from = "flow", name = "destination.port",
          to   = ["spec.defaultBackend.service.port", "spec.rules[*].http.paths[*].backend.service.port.number"]
        }
      ]
    }
    gateway = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "flow", name = "destination.port", to = ["spec.listeners[*].port"] },
      ]
    }
    networkpolicy = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to   = ["spec.ingress[*].from[*].ipBlock.cidr", "spec.egress[*].to[*].ipBlock.cidr"]
        },
        {
          from = "flow", name = "destination.port",
          to   = ["spec.ingress[*].ports[*].port", "spec.egress[*].ports[*].port"]
        },
        {
          from = "flow", name = "network.transport",
          to   = ["spec.ingress[*].ports[*].protocol", "spec.egress[*].ports[*].protocol"]
        },
      ]
    }
  }
}

# Filter configuration (using OBI-aligned syntax)
filter "source" {
  address = { match = "", not_match = "" }
  port    = { match = "", not_match = "" }
}

filter "destination" {
  address = { match = "", not_match = "" }
  port    = { match = "", not_match = "" }
}

filter "network" {
  transport       = { match = "", not_match = "" }
  type            = { match = "", not_match = "" }
  interface_name  = { match = "", not_match = "" }
  interface_index = { match = "", not_match = "" }
  interface_mac   = { match = "", not_match = "" }
}

filter "flow" {
  connection_state = { match = "", not_match = "" }
  end_reason       = { match = "", not_match = "" }
  ip_dscp_name     = { match = "", not_match = "" }
  ip_ecn_name      = { match = "", not_match = "" }
  ip_ttl           = { match = "", not_match = "" }
  ip_flow_label    = { match = "", not_match = "" }
  icmp_type_name   = { match = "", not_match = "" }
  icmp_code_name   = { match = "", not_match = "" }
  tcp_flags        = { match = "", not_match = "" }
}

# Span configuration
span {
  max_record_interval = "60s"
  generic_timeout     = "30s"
  icmp_timeout        = "10s"
  tcp_timeout         = "20s"
  tcp_fin_timeout     = "5s"
  tcp_rst_timeout     = "5s"
  udp_timeout         = "60s"
  community_id_seed   = 0
}

# Export configuration - send traces to OpenTelemetry Collector
export "traces" {
  # Enable stdout for debugging (optional)
  stdout = {
    format = "text_indent"
  }

  otlp = {
    endpoint               = "https://otel-collector:4317"
    protocol               = "grpc"
    timeout                = "10s"
    max_batch_size         = 512
    max_batch_interval     = "5s"
    max_queue_size         = 2048
    max_concurrent_exports = 1
    max_export_timeout     = "30s"

    tls = {
      insecure_skip_verify = true
    }
  }
}
