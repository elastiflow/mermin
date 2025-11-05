# Mermin Default Configuration for Local Development
# This configuration file contains default settings for the Mermin eBPF network observability tool for local development.

# Logging configuration
log_level = "info"

# Automatic configuration reloading
auto_reload = false

# Shutdown timeout
shutdown_timeout = "5s"

# Internal channel and performance related configuration options
packet_channel_capacity = 1024
packet_worker_count     = 2

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
# Configure tunnel port detection (defaults shown)
parser {
  geneve_port    = 6081  # IANA default for Geneve
  vxlan_port     = 4789  # IANA default for VXLAN
  wireguard_port = 51820 # IANA default for WireGuard
}

# K8s informer configuration
informer "k8s" {
  kubeconfig_path         = ""
  informers_sync_timeout  = "30s"
  informers_resync_period = "30m"
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
  #    - GKE:     ["veth*", "gke*"]
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
}

discovery "informer" "k8s" {
  /*
    Define which flow will be processed and sent to the output.
    Impacts the "In-mem K8s objects cache" build by K8s informer (https://www.plural.sh/blog/manage-kubernetes-events-informers/)
      - By default `namespaces = []`, which means "all namespaces", e.g. no filtering by namespaces.
      - `kind` is case insensitive
  */
  selectors = [
    { kind = "Service" }, { kind = "Endpoint" }, { kind = "EndpointSlice" }, { kind = "Gateway" }, { kind = "Ingress" },
    { kind = "Pod" }, { kind = "ReplicaSet" }, { kind = "Deployment" }, { kind = "Daemonset" },
    { kind = "StatefulSet" },
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

// /*
//   We are not using named blocks for discovery to enable the conversion from hcl to yaml.
// */
// discovery {
//   instrument {
//     # Network interfaces to monitor
//     interfaces = ["eth0"]
//   }

//   informer "k8s" {
//     /*
//       Define which flow will be processed and sent to the output.
//       Impacts the "In-mem K8s objects cache" build by K8s informer (https://www.plural.sh/blog/manage-kubernetes-events-informers/)
//         - By default `namespaces = []`, which means "all namespaces", e.g. no filtering by namespaces.
//         - `kind` is case insensitive
//     */
//     selectors = [
//       { kind = "Service" }, { kind = "Endpoint" }, { kind = "EndpointSlice" }, { kind = "Gateway" }, { kind = "Ingress" },
//       { kind = "Pod" }, { kind = "ReplicaSet" }, { kind = "Deployment" }, { kind = "Daemonset" }, { kind = "StatefulSet" },
//       { kind = "Job" }, { kind = "CronJob" }, { kind = "NetworkPolicy" },

//       /*
//         Examples with more granular selectors
//       */
//       # Do not include gateways in "loggers" namespace
//       # {
//       #   namespaces = ["loggers"]
//       #   kind       = "Gateway"
//       #   include    = false
//       # }

//       # # Only include pods with label `operated-prometheus = "true"` AND label `env` in `["dev", "stage"]`
//       # {
//       #   kind = "Pod"

//       #   match_labels = {
//       #     operated-prometheus = "true"
//       #   }

//       #   match_expressions = [{
//       #     key      = "env"
//       #     operator = "In"
//       #     values   = ["dev", "stage"]
//       #   }]
//       # }
//     ]

//     /*
//       Owner reference walking configuration

//       Controls how Mermin walks K8s owner references (Pod <- Job <- CronJob <- ...)
//       and attaches owner metadata to flows.
//     */
//     owner_relations = {
//       # Limit the ownerReference walk depth and depth of attached metadata
//       max_depth = 5

//       # Include specific owner kinds in flow metadata (case insensitive)
//       include_kinds = [
//         "Service", # Add Service metadata as flow attributes
//       ]

//       # Exclude specific owner kinds from flow metadata (case insensitive)
//       # Exclusions override inclusions
//       exclude_kinds = [
//         "EndpointSlice", # Do not add EndpointSlice metadata as flow attributes
//       ]
//     }

//     /*
//       Selector-based K8s resource relations

//       Extracts selector s from K8s resource definitions and matches them against other resources
//       (e.g., NetworkPolicy selects Pods, Service selects Pods via spec.selector)
//     */
//     selector_relations = [
//       # NetworkPolicy -> Pod association
//       # Extract podSelector from NetworkPolicy, find matching Pods, attach NetworkPolicy metadata to their flows
//       {
//         kind                             = "NetworkPolicy" # case insensitive
//         to                               = "Pod"           # case insensitive
//         selector_match_labels_field      = "spec.podSelector.matchLabels"
//         selector_match_expressions_field = "spec.podSelector.matchExpressions"
//       },

//       # Service -> Pod association
//       # Extract spec.selector from Service, find matching Pods, attach Service metadata to their flows
//       {
//         kind                        = "Service" # case insensitive
//         to                          = "Pod"     # case insensitive
//         selector_match_labels_field = "spec.selector"
//       }
//     ]
//   }
// }

/*
  How to associate the flow data to a K8s object.
  Association config of type "k8s_flow_attributes" with name "main_src"
*/
attributes "source" "k8s" {
  /*
    `extract` defines the metadata to extract from all objects.
  */
  extract {
    metadata = [
      "[*].metadata.name",      # All kinds, metadata.name
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "[*].metadata.uid",       # All kinds, metadata.uid (if present)
    ]

    /*
      Otel label extract example, full doc: https://grafana.com/docs/agent/latest/flow/reference/components/otelcol.processor.k8sattributes/#extract-label-block
      None by default, example:
    */
    # label {
    #   from      = "service" # case insensitive
    #   key_regex = "kubernetes.io/(.*)"
    #   tag_name  = "$1"
    # }

    /*
      Otel annotation extract example, full doc: https://grafana.com/docs/agent/latest/flow/reference/components/otelcol.processor.k8sattributes/#annotation-block
      None by default, example:
    */
    # annotation {
    #   from      = "pod" # case insensitive
    #   key_regex = "kubernetes.io/(.*)"
    #   tag_name  = "$1"
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
    /*
      Flow to Node mapping
        - `status.addresses[*].address` name resolution needs to happen when `status.addresses[].type == Hostname`, fine if name resolution failed
    */
    node = {
      sources = [
        { from = "flow", name = "source.ip", to = ["status.addresses[*].address"] },
      ]
    }
    /*
      Service mapping
        - `spec.externalName` name resolution needs to happen
    */
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
    /*
      Endpoint mapping (deprecated, full attribute paths, no kind)
    */
    endpoint = {
      sources = [
        { from = "flow", name = "source.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "flow", name = "source.port", to = ["subsets[*].ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    /*
      EndpointSlice mapping
    */
    endpointslice = {
      sources = [
        { from = "flow", name = "source.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "flow", name = "source.port", to = ["ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["ports[*].protocol"] },
        { from = "flow", name = "network.type", to = ["addressType"] },
      ]
    }
    /*
      Ingress mapping
        - `status.loadBalancer.ingress[*].hostname` name resolution needs to happen
    */
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
    /*
      Gateway mapping
        `spec.addresses[*].value` name resolution needs to happen if `spec.addresses[*].type == Hostname`
        `status.addresses[*].value` name resolution needs to happen if `status.addresses[*].type == Hostname`
    */
    gateway = {
      sources = [
        { from = "flow", name = "source.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "flow", name = "source.port", to = ["spec.listeners[*].port"] },
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

/*
  How to associate the flow data to a K8s object
  Association config of type "k8s_flow_attributes" with name "main_src"
*/
attributes "destination" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",      # All kinds, metadata.name
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "pod.metadata.uid",       # All kinds, metadata.uid
    ]

    /*
      Otel label extract, full doc: https://grafana.com/docs/agent/latest/flow/reference/components/otelcol.processor.k8sattributes/#extract-label-block
      All by default, example:
      label {
        from      = "service"
        key_regex = "kubernetes.io/(.*)"
        tag_name  = "$1"
      }
    */

    /*
      Otel annotation extract, full doc: https://grafana.com/docs/agent/latest/flow/reference/components/otelcol.processor.k8sattributes/#annotation-block
      All by default, example:
      annotation {
        from      = "pod"
        key_regex = "kubernetes.io/(.*)"
        tag_name  = "$1"
      }
    */
  }

  association {
    /*
      Flow to Pod mapping
    */
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
    /*
      Flow to Node mapping
        - `status.addresses[*].address` name resolution needs to happen when `status.addresses[].type == Hostname`, fine if name resolution failed
    */
    node = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["status.addresses[*].address"] },
      ]
    }
    /*
      Service mapping
        - `spec.externalName` name resolution needs to happen
    */
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
    /*
      Endpoint mapping (deprecated, full attribute paths, no kind)
    */
    endpoint = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "flow", name = "destination.port", to = ["subsets[*].ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    /*
      EndpointSlice mapping
    */
    endpointslice = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "flow", name = "destination.port", to = ["ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["ports[*].protocol"] },
      ]
    }
    /*
      Ingress mapping
        - `status.loadBalancer.ingress[*].hostname` name resolution needs to happen
    */
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
    /*
      Gateway mapping
        `spec.addresses[*].value` name resolution needs to happen if `spec.addresses[*].type == Hostname`
        `status.addresses[*].value` name resolution needs to happen if `status.addresses[*].type == Hostname`
    */
    gateway = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "flow", name = "destination.port", to = ["spec.listeners[*].port"] },
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

# Use the syntax and rules of OBI: https://opentelemetry.io/docs/zero-code/obi/configure/filter-metrics-traces/
# For globs we can use https://docs.rs/globset/latest/globset/#syntax to match the functionality of OBI.
# OBI-aligned filter configuration with glob pattern strings
filter "source" {
  address = {
    match     = "" # CIDR/IP glob to include (e.g., "10.0.0.0/8", "192.168.1.*")
    not_match = "" # CIDR/IP glob to exclude
  }
  port = {
    match     = "" # Port range/glob to include (e.g., "80", "443", "8000-8999")
    not_match = "" # Port range/glob to exclude
  }
}

filter "destination" {
  address = {
    match     = "" # CIDR/IP glob to include
    not_match = "" # CIDR/IP glob to exclude
  }
  port = {
    match     = "" # Port range/glob to include
    not_match = "" # Port range/glob to exclude
  }
}

filter "network" {
  transport = {
    match     = "" # e.g., "tcp", "udp"
    not_match = "" # e.g., "icmp"
  }
  type = {
    match     = "" # e.g., "ipv4", "ipv6"
    not_match = ""
  }
  interface_name  = { match = "", not_match = "" }
  interface_index = { match = "", not_match = "" }
  interface_mac   = { match = "", not_match = "" }
}

filter "flow" {
  connection_state = {
    match     = "" # e.g., "established", "close_wait", "syn_sent"
    not_match = ""
  }
  end_reason     = { match = "", not_match = "" }
  ip_dscp_name   = { match = "", not_match = "" }
  ip_ecn_name    = { match = "", not_match = "" }
  ip_ttl         = { match = "", not_match = "" }
  ip_flow_label  = { match = "", not_match = "" }
  icmp_type_name = { match = "", not_match = "" }
  icmp_code_name = { match = "", not_match = "" }
  tcp_flags      = { match = "", not_match = "" }
}

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

# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
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
  }
}
