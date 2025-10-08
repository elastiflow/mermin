# Mermin Default Configuration for Local Development
# This configuration file contains default settings for the Mermin eBPF network observability tool for local development.

# Network interfaces to monitor
discovery "instrument" {
  # Literal example
  interfaces = ["eth0"]
  # Glob example: match all ethernet interfaces starting with "eth"
  # interfaces = ["eth*"]
  # Regex example: match slot-based PNIN like en0p<digits>
  # interfaces = ["/^en0p\\d+$/"]
}

# Logging configuration
log_level = "info"

# Automatic configuration reloading
auto_reload = false

# Pipeline configuration
packet_channel_capacity = 1024
packet_worker_count     = 2
shutdown_timeout        = "5s"

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

# Flow Span configuration
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

# Parser configuration for eBPF packet parsing
# Configure tunnel port detection (defaults shown)
parser {
  geneve_port    = 6081   # IANA default for Geneve
  vxlan_port     = 4789   # IANA default for VXLAN
  wireguard_port = 51820  # IANA default for WireGuard
}

# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = ""

  otlp = {
    endpoint = "https://192.0.2.100:443"

    tls = {
      insecure = true
    }
  }
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
    #
    #   match_labels = {
    #     operated-prometheus = "true"
    #   }
    #
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

    Extracts selector s from K8s resource definitions and matches them against other resources
    (e.g., NetworkPolicy selects Pods, Service selects Pods via spec.selector)
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
    }
  ]
}
