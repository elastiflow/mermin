# Mermin Default Configuration for Local Development
# This configuration file contains default settings for the Mermin eBPF network observability tool for local development.

# Logging configuration
log_level = "info"

# Automatic configuration reloading
auto_reload = false

# Shutdown timeout
shutdown_timeout = "5s"

# Pipeline performance and channel configuration options
pipeline {
  flow_capture {
    flow_stats_capacity  = 100000
    flow_events_capacity = 1024
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

# Parser configuration for eBPF packet parsing
# Configure tunnel port detection and protocol parsing options
parser {
  # Tunnel port detection (IANA defaults shown)
  geneve_port    = 6081  # IANA default for Geneve
  vxlan_port     = 4789  # IANA default for VXLAN
  wireguard_port = 51820 # IANA default for WireGuard
}

discovery "instrument" {
  # Network interfaces to monitor
  #
  # Supports literal names, glob patterns (*, ?), and regex (/pattern/)
  #
  # Default strategy (if not specified): Complete visibility without duplication
  # - veth* for same-node pod-to-pod traffic
  # - CNI-specific tunnel/overlay interfaces for inter-node traffic
  # - Does NOT monitor physical interfaces (eth*, ens*) to avoid duplication
  #
  # Visibility strategies:
  #
  # 1. Complete visibility (DEFAULT - recommended for most deployments):
  #    interfaces = ["veth*", "tunl*", "ip6tnl*", "vxlan*", "flannel*", "cali*", "cilium_*", "lxc*"]
  #    ✅ Captures all traffic (same-node + inter-node, IPv4 + IPv6)
  #    ✅ No flow duplication (avoids bridges and physical interfaces)
  #    ⚠️  Higher overhead (many veth interfaces in large clusters)
  #
  # 2. Inter-node only (lower overhead, incomplete visibility):
  #    interfaces = ["eth*", "ens*"]
  #    ✅ Low overhead (few interfaces)
  #    ❌ Misses same-node pod-to-pod traffic
  #
  # 3. Custom CNI-specific patterns:
  #    - Flannel: ["veth*", "flannel*", "cni*"]
  #    - Calico:  ["veth*", "cali*", "tunl*", "ip6tnl*"]
  #    - Cilium:  ["lxc*", "cilium_*"]
  #    - GKE:     ["gke*", "cilium_*", "lxc*"]
  #    - GKE Dataplane V2: ["gke*", "cilium_*", "lxc*"]
  #    - Dual-stack: Add "ip6tnl*" to any of the above
  #
  # Leave empty or comment out to use defaults
  # interfaces = [
  #   "veth*",      # Same-node pod-to-pod traffic
  #   "tunl*",      # Calico IPIP tunnels (IPv4)
  #   "ip6tnl*",    # IPv6 tunnels (Calico, dual-stack)
  #   "vxlan*",     # VXLAN overlays
  #   "flannel*",   # Flannel interfaces
  #   "cali*",      # Calico interfaces
  #   "cilium_*",   # Cilium overlays
  #   "lxc*",       # Cilium pod interfaces
  #   "gke*",       # GKE interfaces
  #   "eni*",       # AWS VPC CNI
  #   "azure*",     # Azure CNI
  #   "ovn-k8s*",   # OVN-Kubernetes
  # ]

  # TC priority for program attachment (netlink only, kernel < 6.6)
  # Controls execution order in TC chain. Lower priority = runs earlier.
  # Default: 1 (runs first, before orphaned programs from previous instances)
  # Range: 1-32767
  #
  # Why priority 1?: Ensures new mermin programs execute before orphaned programs
  # from crashed pods, preventing flow gaps after restart. Orphaned programs still
  # reference old maps, causing split-brain if they execute first.
  #
  # Conflicts?: Rare. Mermin is passive (TC_ACT_UNSPEC), so running first usually
  # doesn't interfere with CNI programs. If issues occur, increase to 50-100.
  tc_priority = 1

  # TCX ordering strategy (TCX only, kernel >= 6.6)
  # Controls where mermin attaches in the TCX program chain.
  # Default: "first" (prevents orphan program issues on restart)
  # Options:
  #   "first" - Runs before all other programs (recommended)
  #   "last"  - Runs after all other programs
  #
  # Technical details: TCX (Traffic Control eXpress) allows multiple programs per hook
  # with explicit ordering. "first" ensures new mermin programs execute before any
  # orphaned programs from previous instances, maintaining state continuity.
  tcx_order = "first"

  # Automatically discover and attach to new interfaces matching patterns
  # Recommended for ephemeral interfaces like veth* (created/destroyed with pods)
  # Default: true
  # auto_discover_interfaces = true
}

discovery "informer" "k8s" {
  # K8s API connection configuration
  kubeconfig_path        = ""    # Empty uses in-cluster config (default for pods)
  informers_sync_timeout = "30s" # Timeout for initial cache sync (increase for large clusters)

  /*
    Define which flow will be processed and sent to the output.
    Impacts the "In-mem K8s objects cache" build by K8s informer (https://www.plural.sh/blog/manage-kubernetes-events-informers/)
      - By default `namespaces = []`, which means "all namespaces", e.g. no filtering by namespaces.
      - `kind` is case insensitive
  */
  selectors = [
    { kind = "Service" }, { kind = "Endpoint" }, { kind = "EndpointSlice" }, { kind = "Gateway" }, { kind = "Ingress" },
    { kind = "Pod" }, { kind = "ReplicaSet" }, { kind = "Deployment" }, { kind = "Daemonset" }, { kind = "StatefulSet" },
    { kind = "Job" }, { kind = "CronJob" }, { kind = "NetworkPolicy" },

    /*
      Examples with more granular selectors
    */
    # Do not include gateways in "loggers" namespace
    # {
    #   namespaces = ["loggers"]
    #   kind       = "Gateway"
    #   include    = false
    # }

    # # Only include pods with label `operated-prometheus = "true"` AND label `env` in `["dev", "stage"]`
    # {
    #   kind = "Pod"

    #   match_labels = {
    #     operated-prometheus = "true"
    #   }

    #   match_expressions = [{
    #     key      = "env"
    #     operator = "In"
    #     values   = ["dev", "stage"]
    #   }]
    # }
  ]

  /*
    Owner reference walking configuration

    Controls how Mermin walks K8s owner references (Pod <- Job <- CronJob <- ...)
    and attaches owner metadata to flows.

    Valid owner kinds: Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob
  */
  owner_relations = {
    # Limit the ownerReference walk depth and depth of attached metadata
    max_depth = 5

    # Include specific owner kinds in flow metadata (case insensitive)
    include_kinds = [
      "Service", # Add Service metadata as flow attributes
    ]

    # Exclude specific owner kinds from flow metadata (case insensitive)
    # Exclusions override inclusions
    exclude_kinds = [
      "EndpointSlice", # Do not add EndpointSlice metadata as flow attributes
    ]
  }

  /*
    Selector-based K8s resource relations

    Extracts selectors from K8s resource definitions and matches them against other resources
    (e.g., NetworkPolicy selects Pods, Service selects Pods via spec.selector)

    Supported resource kinds:
    - NetworkPolicy, Service (network resources)
    - Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob (workload controllers)
  */
  selector_relations = [
    # NetworkPolicy -> Pod association
    # Extract podSelector from NetworkPolicy, find matching Pods, attach NetworkPolicy metadata to their flows
    {
      kind                             = "NetworkPolicy" # case insensitive
      to                               = "Pod"           # case insensitive
      selector_match_labels_field      = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },

    # Service -> Pod association
    # Extract spec.selector from Service, find matching Pods, attach Service metadata to their flows
    {
      kind                        = "Service" # case insensitive
      to                          = "Pod"     # case insensitive
      selector_match_labels_field = "spec.selector"
    },

    # Workload controller examples (uncomment to enable)
    # These provide reverse lookup: find all controllers that select a given pod via label selectors
    # Complements owner_relations which walks the owner reference chain

    # {
    #   kind                        = "Deployment"
    #   to                          = "Pod"
    #   selector_match_labels_field = "spec.selector.matchLabels"
    # },
    # {
    #   kind                        = "ReplicaSet"
    #   to                          = "Pod"
    #   selector_match_labels_field = "spec.selector.matchLabels"
    # },
    # {
    #   kind                        = "StatefulSet"
    #   to                          = "Pod"
    #   selector_match_labels_field = "spec.selector.matchLabels"
    # },
    # {
    #   kind                        = "DaemonSet"
    #   to                          = "Pod"
    #   selector_match_labels_field = "spec.selector.matchLabels"
    # },
    # {
    #   kind                        = "Job"
    #   to                          = "Pod"
    #   selector_match_labels_field = "spec.selector.matchLabels"
    # },
    # {
    #   kind                        = "CronJob"
    #   to                          = "Pod"
    #   selector_match_labels_field = "spec.jobTemplate.spec.selector.matchLabels"
    # }
  ]
}

/*
  Maps flow data (source IPs, ports) to Kubernetes resources:
*/
attributes "source" "k8s" {
  /*
    `extract` defines the metadata to extract from all objects.
  */
  extract {
    metadata = [
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "[*].metadata.name",      # All kinds, metadata.name
      "[*].metadata.uid",       # All kinds, metadata.uid (if present)
    ]

    /*
      Extract K8s label to Otel attribute extract example:
    */
    # Using regex
    # label {
    #   from            = "service" # case insensitive
    #   key_regex       = "kubernetes.io/(.*)"
    #   value_regex     = "(.*)"
    #   attribute       = "$1"
    #   attribute_value = "$1"
    # }

    # Using direct key match example
    # label {
    #   from      = "service" # case insensitive
    #   key       = "kubernetes.io/barbaz"
    #   attribute = "barbaz"
    # }


    /*
      Extract K8s annotation to Otel attribute extract example:
    */
    # Using regex
    # annotation {
    #   from            = "service" # case insensitive
    #   key_regex       = "kubernetes.io/(.*)"
    #   value_regex     = "(.*)"
    #   attribute       = "$1"
    #   attribute_value = "$1"
    # }
  }

  /*
    `association` blocks define how to map flow attributes to the K8s object attributes.
  */
  association {
    /*
      Flow to Pod mapping.
    */
    pod = {
      sources = [
        { from = "source.ip", to = ["status.podIP", "status.podIPs[*]", "status.hostIP", "status.hostIPs[*]"] },
        { from = "source.port", to = ["spec.containers[*].ports[*].containerPort", "spec.containers[*].ports[*].hostPort"] },
        { from = "network.transport", to = ["spec.containers[*].ports[*].protocol"] },
      ]
    }
    /*
      Flow to Node mapping
        - `status.addresses[*].address` name resolution needs to happen when `status.addresses[].type == Hostname`, fine if name resolution failed
    */
    node = {
      sources = [
        { from = "source.ip", to = ["status.addresses[*].address"] },
      ]
    }
    /*
      Service mapping
        - `spec.externalName` name resolution needs to happen
    */
    service = {
      sources = [
        {
          from = "source.ip",
          to   = ["spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]", "spec.loadBalancerIP", "spec.externalName"]
        },
        { from = "source.port", to = ["spec.ports[*].port"] },
        { from = "network.transport", to = ["spec.ports[*].protocol"] },
        { from = "network.type", to = ["spec.ipFamilies[*]"] },
      ]
    }
    /*
      Endpoint mapping (deprecated, full attribute paths, no kind)
    */
    endpoint = {
      sources = [
        { from = "source.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "source.port", to = ["subsets[*].ports[*].port"] },
        { from = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    /*
      EndpointSlice mapping
    */
    endpointslice = {
      sources = [
        { from = "source.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "source.port", to = ["ports[*].port"] },
        { from = "network.transport", to = ["ports[*].protocol"] },
        { from = "network.type", to = ["addressType"] },
      ]
    }
    /*
      Ingress mapping
        - `status.loadBalancer.ingress[*].hostname` name resolution needs to happen
    */
    ingress = {
      sources = [
        {
          from = "source.ip",
          to   = ["status.loadBalancer.ingress[*].ip", "status.loadBalancer.ingress[*].hostname"]
        },
        {
          from = "source.port",
          to   = ["spec.defaultBackend.service.port", "spec.rules[*].http.paths[*].backend.service.port.number"]
        }
      ]
    }
    /*
      Gateway mapping
        `spec.addresses[*].value` name resolution needs to happen if `spec.addresses[*].type == Hostname`
        `status.addresses[*].value` name resolution needs to happen if `status.addresses[*].type == Hostname`
    */
    gateway = {
      sources = [
        { from = "source.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "source.port", to = ["spec.listeners[*].port"] },
      ]
    }
    /*
      NetworkPolicy src mapping (SRC/DST IP/Port/Protocol)
        - If `spec.ingress[*].ports[*].endPort` or `spec.egress[*].ports[*].endPort` is defined for a port,
          than port matching should be done against `port - endPort` range
        - If `spec.ingress[*].ports[*].endPort` or `spec.egress[*].ports[*].endPort` is a string,
          port should be retrieved from related pods (https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#networkpolicypeer-v1-networking-k8s-io)
    */
    networkpolicy = {
      sources = [
        {
          from = "source.ip",
          to   = ["spec.ingress[*].from[*].ipBlock.cidr", "spec.egress[*].to[*].ipBlock.cidr"]
        },
        { from = "source.port", to = ["spec.ingress[*].ports[*].port", "spec.egress[*].ports[*].port"] },
        {
          from = "network.transport",
          to   = ["spec.ingress[*].ports[*].protocol", "spec.egress[*].ports[*].protocol"]
        },
      ]
    }
  }
}
/*
  Maps flow data (destination IPs, ports) to Kubernetes resources:
*/
attributes "destination" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",      # All kinds, metadata.name
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "pod.metadata.uid",       # All kinds, metadata.uid
    ]

    /*
      Extract K8s label to Otel attribute extract example:
    */
    # Using regex
    # label {
    #   from            = "service" # case insensitive
    #   key_regex       = "kubernetes.io/(.*)"
    #   value_regex     = "(.*)"
    #   attribute       = "$1"
    #   attribute_value = "$1"
    # }

    # Using direct key match example
    # label {
    #   from      = "service" # case insensitive
    #   key       = "kubernetes.io/barbaz"
    #   attribute = "barbaz"
    # }


    /*
      Extract K8s annotation to Otel attribute extract example:
    */
    # Using regex
    # annotation {
    #   from            = "service" # case insensitive
    #   key_regex       = "kubernetes.io/(.*)"
    #   value_regex     = "(.*)"
    #   attribute       = "$1"
    #   attribute_value = "$1"
    # }

# Using direct key match example
# annotation {
#   from      = "service" # case insensitive
#   key       = "kubernetes.io/barbaz"
#   attribute = "barbaz"
# }

  }

  association {
    /*
      Flow to Pod mapping
    */
    pod = {
      sources = [
        { from = "destination.ip", to = ["status.podIP", "status.podIPs[*]", "status.hostIP", "status.hostIPs[*]"] },
        { from = "destination.port", to = ["spec.containers[*].ports[*].containerPort", "spec.containers[*].ports[*].hostPort"] },
        { from = "network.transport", to = ["spec.containers[*].ports[*].protocol"] },
      ]
    }
    /*
      Flow to Node mapping
        - `status.addresses[*].address` name resolution needs to happen when `status.addresses[].type == Hostname`, fine if name resolution failed
    */
    node = {
      sources = [
        { from = "destination.ip", to = ["status.addresses[*].address"] },
      ]
    }
    /*
      Service mapping
        - `spec.externalName` name resolution needs to happen
    */
    service = {
      sources = [
        {
          from = "destination.ip",
          to   = ["spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]", "spec.loadBalancerIP", "spec.externalName"]
        },
        { from = "destination.port", to = ["spec.ports[*].port"] },
        { from = "network.transport", to = ["spec.ports[*].protocol"] },
        { from = "network.type", to = ["spec.ipFamilies[*]"] },
      ]
    }
    /*
      Endpoint mapping (deprecated, full attribute paths, no kind)
    */
    endpoint = {
      sources = [
        { from = "destination.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "destination.port", to = ["subsets[*].ports[*].port"] },
        { from = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    /*
      EndpointSlice mapping
    */
    endpointslice = {
      sources = [
        { from = "destination.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "destination.port", to = ["ports[*].port"] },
        { from = "network.transport", to = ["ports[*].protocol"] },
      ]
    }
    /*
      Ingress mapping
        - `status.loadBalancer.ingress[*].hostname` name resolution needs to happen
    */
    ingress = {
      sources = [
        { from = "destination.ip", to = ["status.loadBalancer.ingress[*].ip", "status.loadBalancer.ingress[*].hostname"] },
        {
          from = "destination.port",
          to   = ["spec.defaultBackend.service.port", "spec.rules[*].http.paths[*].backend.service.port.number"]
        }
      ]
    }
    /*
      Gateway mapping
        `spec.addresses[*].value` name resolution needs to happen if `spec.addresses[*].type == Hostname`
        `status.addresses[*].value` name resolution needs to happen if `status.addresses[*].type == Hostname`
    */
    gateway = {
      sources = [
        { from = "destination.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "destination.port", to = ["spec.listeners[*].port"] },
      ]
    }
    /*
      NetworkPolicy src mapping (SRC/DST IP/Port/Protocol)
        - If `spec.ingress[*].ports[*].endPort` or `spec.egress[*].ports[*].endPort` is defined for a port,
          than port matching should be done against `port - endPort` range
        - If `spec.ingress[*].ports[*].endPort` or `spec.egress[*].ports[*].endPort` is a string,
          port should be retrieved from related pods (https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#networkpolicypeer-v1-networking-k8s-io)
    */
    networkpolicy = {
      sources = [
        { from = "destination.ip", to = ["spec.ingress[*].from[*].ipBlock.cidr", "spec.egress[*].to[*].ipBlock.cidr"] },
        { from = "destination.port", to = ["spec.ingress[*].ports[*].port", "spec.egress[*].ports[*].port"] },
        { from = "network.transport", to = ["spec.ingress[*].ports[*].protocol", "spec.egress[*].ports[*].protocol"] },
      ]
    }
  }
}

/*
  Flow filtering configuration
  Define which flows will be captured and processed based on various criteria.
  Empty match/not_match means no filtering on that attribute:
    * match = [] - include all
    * not_match = [] - exclude none
*/
filter "source" {
  address = {
    match     = [] # CIDR/IP to include (e.g., ["10.0.0.0/16", "91.1.1.1"])
    not_match = [] # CIDR/IP to exclude (e.g., ["192.168.0.0/16", "92.1.1.1"])
  }
  port = {
    match     = [] # Ports, port ranges to include (e.g., ["80", "443", "8000-9000"])
    not_match = [] # Ports, port ranges to exclude (e.g., ["22", "3306-3307"])
  }
}

filter "destination" {
  address = {
    match     = [] # CIDR/IP to include (e.g., ["10.0.0.0/16", "91.1.1.1"])
    not_match = [] # CIDR/IP to exclude (e.g., ["192.168.0.0/16", "92.1.1.1"])
  }
  port = {
    match     = [] # Ports, port ranges to include (e.g., ["80", "443", "8000-9000"])
    not_match = [] # Ports, port ranges to exclude (e.g., ["22", "3306-3307"])
  }
}

filter "network" {
  transport       = { match = [], not_match = [] } # Protocols (e.g., ["tcp", "udp", "icmp", "icmpv6"])
  type            = { match = [], not_match = [] } # IP versions (e.g., ["ipv4", "ipv6"])
  interface_name  = { match = [], not_match = [] } # Interface names (e.g., ["eth*"])
  interface_index = { match = [], not_match = [] } # Interface indices (e.g., ["2"])
  interface_mac   = { match = [], not_match = [] } # MAC addresses (e.g., ["00:11:22:33:44:55"])
}

filter "flow" {
  connection_state = { match = [], not_match = [] } # States to  (e.g., ["established", "close_wait"])
  tcp_flags_tags   = { match = [], not_match = [] } # TCP flags (e.g., ["SYN", "ACK"])
  ip_dscp_name     = { match = [], not_match = [] } # DSCP values (e.g., ["CS0", "AF21"])
  ip_ecn_name      = { match = [], not_match = [] } # ECN values (e.g., ["ECT0"])
  ip_ttl           = { match = [], not_match = [] } # TTL values (e.g., ["1"])
  ip_flow_label    = { match = [], not_match = [] } # IPv6 flow labels (e.g., ["12345"])
  icmp_type_name   = { match = [], not_match = [] } # ICMP types (e.g., ["echo_request"])
  icmp_code_name   = { match = [], not_match = [] } # ICMP codes (e.g., ["0"])
}

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
  enable_hostname_resolution = true
  hostname_resolve_timeout   = "100ms"
}

# OTLP exporter configuration
export "traces" {
  stdout = {
    format = "text_indent" // text, text_indent(*new), json, json_indent
  }

  otlp = {
    endpoint               = "http://otelcol:4317"
    protocol               = "grpc"
    timeout                = "10s"
    max_batch_size         = 512
    max_batch_interval     = "5s"
    max_queue_size         = 2048
    max_concurrent_exports = 1
    max_export_timeout     = "30s"

    auth = {
      basic = {
        user = "USERNAME"
        pass = "PASSWORD"
      }
    }

    tls = {
      insecure_skip_verify = false
      ca_cert              = "/etc/certs/ca.crt"
      client_cert          = "/etc/certs/cert.crt"
      client_key           = "/etc/certs/cert.key"
    }

    headers = {
      # Examples
      # "x-greptime-db-name"       = "public"
      # "x-greptime-pipeline-name" = "greptime_trace_v1"
    }
  }
}

# Internal configuration options
internal "traces" {
  span_format = "full"

  # stdout = {
  #   format = "text_indent" // text_indent
  # }

  otlp = {
    endpoint               = "http://otelcol:4317"
    protocol               = "grpc"
    timeout                = "10s"
    max_batch_size         = 512
    max_batch_interval     = "5s"
    max_queue_size         = 2048
    max_concurrent_exports = 1
    max_export_timeout     = "30s"

    auth = {
      basic = {
        user = "USERNAME"
        pass = "PASSWORD"
      }
    }

    tls = {
      insecure_skip_verify = false
      ca_cert              = "/etc/certs/ca.crt"
      client_cert          = "/etc/certs/cert.crt"
      client_key           = "/etc/certs/cert.key"
    }
  }
}

# Metrics server configuration (for Prometheus scraping)
internal "metrics" {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 10250

  # Enable debug metrics
  # WARNING: Enabling debug metrics can cause significant memory growth in production
  # Only enable for debugging purposes in development/staging environments
  debug_metrics_enabled = false # Set to true for per-resource metrics (interface, task, K8s resource labels)

  # Time-to-live for stale metrics after resource deletion (only applies when debug_metrics_enabled = true)
  # Examples: "5m", "300s", "1h", "0s" for immediate cleanup
  # Recommended: "5m" handles pod restarts while preventing unbounded growth
  stale_metric_ttl = "5m"

  # Histogram bucket configuration (optional)
  # Customize bucket sizes for histogram metrics to better match your workload
  # If not specified, default buckets optimized for typical workloads are used
  #
  # histogram_buckets {
  #   mermin_pipeline_duration_seconds                        = [0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
  #   mermin_export_batch_size                                = [1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
  #   mermin_k8s_watcher_ip_index_update_duration_seconds     = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
  #   mermin_taskmanager_shutdown_duration_seconds            = [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0]  # Only when debug_metrics_enabled = true
  # }

  # Endpoints available:
  # - /metrics          - All metrics (standard + debug if enabled)
  # - /metrics/standard - Standard metrics only (aggregated, no high-cardinality labels)
  # - /metrics/debug    - Debug metrics only (returns 404 if debug not enabled)
  # - /metrics:summary  - JSON summary of all available metrics with metadata
}

# HTTP server configuration (health endpoints)
internal "server" {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 8080
}
