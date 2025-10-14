# Mermin Default Configuration for Local Development
# This configuration file contains default settings for the Mermin eBPF network observability tool for local development.

# Network interfaces to monitor
interfaces = ["eth0"]

# Logging configuration
log_level     = "info"
trace_printer = "disabled" // disabled, text, text_indent(*new), json, json_indent

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

# Use the syntax and rules of OBI: https://opentelemetry.io/docs/zero-code/obi/configure/filter-metrics-traces/
# For globs we can use https://docs.rs/globset/latest/globset/#syntax to match the functionality of OBI.
# OBI-aligned filter configuration with glob pattern strings
filter {
  source {
    address {
      match     = "" # CIDR/IP glob to include (e.g., "10.0.0.0/8", "192.168.1.*")
      not_match = "" # CIDR/IP glob to exclude
    }
    port {
      match     = "" # Port range/glob to include (e.g., "80", "443", "8000-8999")
      not_match = "" # Port range/glob to exclude
    }
  }

  destination {
    address {
      match     = "" # CIDR/IP glob to include
      not_match = "" # CIDR/IP glob to exclude
    }
    port {
      match     = "" # Port range/glob to include
      not_match = "" # Port range/glob to exclude
    }
  }

  network {
    transport {
      match     = "" # e.g., "tcp", "udp"
      not_match = "" # e.g., "icmp"
    }
    type {
      match     = "" # e.g., "ipv4", "ipv6"
      not_match = ""
    }
  }

  flow {
    connection {
      state {
        match     = "" # e.g., "established", "close_wait", "syn_sent"
        not_match = ""
      }
    }
  }
}

traces {

}

/*
  OBI-style service discovery configuration

  Analogous to OBI's discovery.instrument pattern, this section defines which K8s resources
  to cache for network flow decoration. Instead of discovering processes to instrument,
  Mermin discovers K8s resources to associate with network flows.

  See: https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/
*/
discovery {
  /*
    K8s resources to cache for flow decoration

    Uses OBI's discovery.instrument structure with OBI's standard field names from:
    https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/#discovery-services

    IMPORTANT: Mermin requires k8s_kind to specify which K8s resource types to cache.
    This is Mermin-specific (OBI discovers processes via open_ports/exe_path, Mermin discovers K8s resources).

    All other field names follow OBI's standard (flat properties, glob patterns):
    - k8s_namespace (string glob)
    - k8s_pod_name (string glob)
    - k8s_deployment_name, k8s_replicaset_name, k8s_statefulset_name, k8s_daemonset_name (string globs)
    - k8s_owner_name (string glob)
    - k8s_pod_labels (map[string]string, values are globs)
    - k8s_pod_annotations (map[string]string, values are globs)

    All selectors in an entry must match (AND logic).
  */
  instrument = [
    # Cache all Services in all namespaces
    { k8s_kind = "Service" },

    # Cache all basic K8s networking resources
    { k8s_kind = "Endpoint" },
    { k8s_kind = "EndpointSlice" },
    { k8s_kind = "Gateway" },
    { k8s_kind = "Ingress" },

    # Cache all Pod-related resources
    { k8s_kind = "Pod" },
    { k8s_kind = "ReplicaSet" },
    { k8s_kind = "Deployment" },
    { k8s_kind = "Daemonset" },
    { k8s_kind = "StatefulSet" },
    { k8s_kind = "Job" },
    { k8s_kind = "CronJob" },

    # Cache NetworkPolicy resources
    { k8s_kind = "NetworkPolicy" },

    /*
      Examples using OBI's standard field names for granular selection:
    */

    # Cache only Pods in "frontend" namespace with label app="web"
    # {
    #   k8s_kind       = "Pod"
    #   k8s_namespace  = "frontend"  # OBI standard field (string glob)
    #   k8s_pod_labels = {           # OBI standard field (map with glob values)
    #     app = "web"                # Value is a glob pattern
    #   }
    # }

    # Cache only Pods owned by deployments matching "my-app-*"
    # {
    #   k8s_kind            = "Pod"
    #   k8s_deployment_name = "my-app-*"  # OBI standard field (string glob)
    # }

    # Cache Pods in backend namespace with specific annotation
    # {
    #   k8s_kind            = "Pod"
    #   k8s_namespace       = "backend"       # OBI standard field
    #   k8s_pod_annotations = {               # OBI standard field
    #     "mermin.observe" = "true"           # Value is a glob pattern
    #   }
    # }

    # Cache Pods by owner name (Deployment/ReplicaSet/DaemonSet/StatefulSet)
    # {
    #   k8s_kind       = "Pod"
    #   k8s_owner_name = "nginx-*"  # OBI standard field (string glob)
    # }
  ]

  /*
    K8s resources to exclude from caching (uses OBI's discovery.exclude_instrument syntax)

    Exclusions are processed first - if a resource matches an exclusion rule, it's ignored
    even if it matches an inclusion rule.

    Uses the same OBI field names as instrument entries above.
  */
  exclude_instrument = [
    # Example: Do not cache gateways in "loggers" namespace
    # {
    #   k8s_kind      = "Gateway"
    #   k8s_namespace = "loggers"  # OBI field name
    # }

    # Example: Exclude pods with specific label
    # {
    #   k8s_kind       = "Pod"
    #   k8s_pod_labels = {
    #     "mermin.ignore" = "true"
    #   }
    # }
  ]

  /*
    Owner reference walking configuration

    Controls how Mermin walks K8s owner references (Pod <- Job <- CronJob <- ...)
    and attaches owner metadata to flows.
  */
  k8s_owner = {
    # Limit the ownerReference walk depth and depth of attached metadata
    # Example: If max_depth = 1 and Pod <- Job <- CronJob
    # Only Pod and Job metadata is attached to flows
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
    Selector-based K8s resource association

    Extracts selectors from K8s resource definitions and matches them against other resources
    (e.g., NetworkPolicy selects Pods, Service selects Pods via spec.selector)
  */
  k8s_selector = [
    # NetworkPolicy -> Pod association
    # Extract podSelector from NetworkPolicy, find matching Pods, attach NetworkPolicy metadata to their flows
    {
      k8s_kind                         = "NetworkPolicy" # case insensitive
      to                               = "Pod"           # case insensitive
      selector_match_labels_field      = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },

    # Service -> Pod association
    # Extract spec.selector from Service, find matching Pods, attach Service metadata to their flows
    {
      k8s_kind                    = "Service" # case insensitive
      to                          = "Pod"     # case insensitive
      selector_match_labels_field = "spec.selector"
    }
  ]
}

/*
  OBI-style attributes configuration for flow decoration

  Similar to OBI's attributes.kubernetes which decorates metrics/traces with K8s metadata,
  Mermin decorates network flows with K8s metadata by associating flow attributes
  (source/destination IP/port) with K8s resource fields.

  See: https://opentelemetry.io/docs/zero-code/obi/configure/metrics-traces-attributes/
*/
attributes {
  /*
    Kubernetes metadata decoration (follows OBI's attributes.kubernetes pattern)

    Analogous to OBI's attributes.kubernetes decorator which adds standard K8s labels
    (k8s.namespace.name, k8s.deployment.name, etc.) to metrics and traces,
    Mermin extracts K8s metadata and associates it with flow source/destination attributes.
  */
  kubernetes {
    /*
      Source flow decoration

      Defines how to associate source flow attributes (source.ip, source.port, etc.)
      with Kubernetes resource fields to extract and attach relevant metadata.
    */
    source {
      /*
        Metadata extraction configuration

        Similar to OBI's extra_group_attributes which defines additional K8s metadata
        to include (e.g., k8s.app.version), this specifies which K8s resource fields
        to extract as flow attributes.
      */
      extract {
        # Metadata fields to extract from all K8s resource types
        metadata = [
          "[*].metadata.name",      # Resource name (e.g., k8s.pod.name, k8s.service.name)
          "[*].metadata.namespace", # Resource namespace (k8s.namespace.name)
          "[*].metadata.uid",       # Resource UID (k8s.pod.uid, if present)
        ]

        /*
          Label extraction (follows OBI's label/annotation extraction pattern)

          Extracts labels from K8s resources and adds them as flow attributes.
          Similar to OBI's resource.opentelemetry.io/ annotation prefix pattern
          for custom attributes.

          Example:
        */
        # label {
        #   from      = "service" # K8s resource type (case insensitive)
        #   key_regex = "kubernetes.io/(.*)"
        #   tag_name  = "$1"
        # }

        /*
          Annotation extraction

          Extracts annotations from K8s resources and adds them as flow attributes.

          Example:
        */
        # annotation {
        #   from      = "pod" # K8s resource type (case insensitive)
        #   key_regex = "kubernetes.io/(.*)"
        #   tag_name  = "$1"
        # }
      }

      /*
        Association rules (Mermin-specific extension)

        Unlike OBI which automatically decorates with standard K8s labels,
        Mermin needs explicit rules to map flow attributes to K8s resource fields
        for matching and metadata extraction.

        Each block defines how flow attributes match against K8s resource field
        values to determine which resource metadata to attach to the flow.
      */

      # Pod association
      pod {
        select = [
          { from = "flow", name = "source.ip", to = ["pod.status.podIP", "pod.status.podIPs[*]", "pod.status.hostIP", "pod.status.hostIPs[*]"] },
          { from = "flow", name = "source.port", to = ["pod.spec.containers[*].ports[*].containerPort", "pod.spec.containers[*].ports[*].hostPort"] },
          { from = "flow", name = "network.transport", to = ["pod.spec.containers[*].ports[*].protocol"] },
        ]
      }

      # Node association
      # Note: node.status.addresses[*].address may require DNS resolution when type == Hostname
      node {
        select = [
          { from = "flow", name = "source.ip", to = ["node.status.addresses[*].address"] },
        ]
      }

      # Service association
      # Note: service.spec.externalName requires DNS resolution
      service {
        select = [
          { from = "flow", name = "source.ip", to = ["service.spec.clusterIP", "service.spec.clusterIPs[*]", "service.spec.externalIPs[*]", "service.spec.loadBalancerIP", "service.spec.externalName"] },
          { from = "flow", name = "source.port", to = ["service.spec.ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["service.spec.ports[*].protocol"] },
          { from = "flow", name = "network.type", to = ["service.spec.ipFamilies[*]"] },
        ]
      }

      # Endpoint association (deprecated K8s resource, but still supported)
      endpoint {
        select = [
          { from = "flow", name = "source.ip", to = ["endpoint.subsets[*].addresses[*].ip"] },
          { from = "flow", name = "source.port", to = ["endpoint.subsets[*].ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["endpoint.subsets[*].ports[*].protocol"] },
        ]
      }

      # EndpointSlice association
      endpointslice {
        select = [
          { from = "flow", name = "source.ip", to = ["endpointslice.endpoints[*].addresses[*]"] },
          { from = "flow", name = "source.port", to = ["endpointslice.ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["endpointslice.ports[*].protocol"] },
          { from = "flow", name = "network.type", to = ["endpointslice.addressType"] },
        ]
      }

      # Ingress association
      # Note: ingress.status.loadBalancer.ingress[*].hostname requires DNS resolution
      ingress {
        select = [
          { from = "flow", name = "source.ip", to = ["ingress.status.loadBalancer.ingress[*].ip", "ingress.status.loadBalancer.ingress[*].hostname"] },
          { from = "flow", name = "source.port", to = ["ingress.spec.defaultBackend.service.port", "ingress.spec.rules[*].http.paths[*].backend.service.port.number"] }
        ]
      }

      # Gateway association
      # Note: gateway addresses require DNS resolution when type == Hostname
      gateway {
        select = [
          { from = "flow", name = "source.ip", to = ["gateway.spec.addresses[*].value", "gateway.status.addresses[*].value"] },
          { from = "flow", name = "source.port", to = ["gateway.spec.listeners[*].port"] },
        ]
      }

      # NetworkPolicy association
      # Note: If endPort is defined, matching is against port-endPort range
      # Note: If port is a string, it should be resolved from related pods
      networkpolicy {
        select = [
          { from = "flow", name = "source.ip", to = ["networkpolicy.spec.ingress[*].from[*].ipBlock.cidr", "networkpolicy.spec.egress[*].to[*].ipBlock.cidr"] },
          { from = "flow", name = "source.port", to = ["networkpolicy.spec.ingress[*].ports[*].port", "networkpolicy.spec.egress[*].ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["networkpolicy.spec.ingress[*].ports[*].protocol", "networkpolicy.spec.egress[*].ports[*].protocol"] },
        ]
      }
    }

    /*
      Destination flow decoration

      Defines how to associate destination flow attributes (destination.ip, destination.port, etc.)
      with Kubernetes resource fields to extract and attach relevant metadata.
    */
    destination {
      extract {
        metadata = [
          "[*].metadata.name",      # Resource name
          "[*].metadata.namespace", # Resource namespace
          "pod.metadata.uid",       # Pod UID
        ]

        /*
          Label and annotation extraction examples (same pattern as source)
        */
        # label {
        #   from      = "service"
        #   key_regex = "kubernetes.io/(.*)"
        #   tag_name  = "$1"
        # }

        # annotation {
        #   from      = "pod"
        #   key_regex = "kubernetes.io/(.*)"
        #   tag_name  = "$1"
        # }
      }

      # Pod association
      pod {
        select = [
          { from = "flow", name = "destination.ip", to = ["pod.status.podIP", "pod.status.podIPs[*]", "pod.status.hostIP", "pod.status.hostIPs[*]"] },
          { from = "flow", name = "destination.port", to = ["pod.spec.containers[*].ports[*].containerPort", "pod.spec.containers[*].ports[*].hostPort"] },
          { from = "flow", name = "network.transport", to = ["pod.spec.containers[*].ports[*].protocol"] },
        ]
      }

      # Node association
      node {
        select = [
          { from = "flow", name = "destination.ip", to = ["node.status.addresses[*].address"] },
        ]
      }

      # Service association
      service {
        select = [
          { from = "flow", name = "destination.ip", to = ["service.spec.clusterIP", "service.spec.clusterIPs[*]", "service.spec.externalIPs[*]", "service.spec.loadBalancerIP", "service.spec.externalName"] },
          { from = "flow", name = "destination.port", to = ["service.spec.ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["service.spec.ports[*].protocol"] },
          { from = "flow", name = "network.type", to = ["service.spec.ipFamilies[*]"] },
        ]
      }

      # Endpoint association
      endpoint {
        select = [
          { from = "flow", name = "destination.ip", to = ["endpoint.subsets[*].addresses[*].ip"] },
          { from = "flow", name = "destination.port", to = ["endpoint.subsets[*].ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["endpoint.subsets[*].ports[*].protocol"] },
        ]
      }

      # EndpointSlice association
      endpointslice {
        select = [
          { from = "flow", name = "destination.ip", to = ["endpointslice.endpoints[*].addresses[*]"] },
          { from = "flow", name = "destination.port", to = ["endpointslice.ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["endpointslice.ports[*].protocol"] },
        ]
      }

      # Ingress association
      ingress {
        select = [
          { from = "flow", name = "destination.ip", to = ["ingress.status.loadBalancer.ingress[*].ip", "ingress.status.loadBalancer.ingress[*].hostname"] },
          { from = "flow", name = "destination.port", to = ["ingress.spec.defaultBackend.service.port", "ingress.spec.rules[*].http.paths[*].backend.service.port.number"] }
        ]
      }

      # Gateway association
      gateway {
        select = [
          { from = "flow", name = "destination.ip", to = ["gateway.spec.addresses[*].value", "gateway.status.addresses[*].value"] },
          { from = "flow", name = "destination.port", to = ["gateway.spec.listeners[*].port"] },
        ]
      }

      # NetworkPolicy association
      networkpolicy {
        select = [
          { from = "flow", name = "destination.ip", to = ["networkpolicy.spec.ingress[*].from[*].ipBlock.cidr", "networkpolicy.spec.egress[*].to[*].ipBlock.cidr"] },
          { from = "flow", name = "destination.port", to = ["networkpolicy.spec.ingress[*].ports[*].port", "networkpolicy.spec.egress[*].ports[*].port"] },
          { from = "flow", name = "network.transport", to = ["networkpolicy.spec.ingress[*].ports[*].protocol", "networkpolicy.spec.egress[*].ports[*].protocol"] },
        ]
      }
    }
  }
}

# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
otel {
  traces = {
    export = {
      endpoint = "http://otelcol:4317"
      protocol = "grpc"
      timeout  = "10s"

      auth = {
        basic = {
          user = "USERNAME"
          pass = "PASSWORD"
        }
      }

      tls = {
        enabled     = false
        insecure    = false
        ca_cert     = "/etc/certs/ca.crt"
        client_cert = "/etc/certs/cert.crt"
        client_key  = "/etc/certs/cert.key"
      }
    }
  }
}

/*
Outstanding questions:

Kubernetes metadata decoration:
https://opentelemetry.io/docs/zero-code/obi/configure/metrics-traces-attributes/#kubernetes-decorator

- OBI has an attributes.kubernetes.enable flag. Do we want this or are we saying it's enabled if you have the attributes.kubernetes section?
- There is also a kubeconfig_path field. Do we want this?
- They have a attributes.kubernetes.disable_informers field. Do we want this? For us, we are currently controlling that through the discovery instrument section. There is some functional overlap, but it's not clear which direction we want to go.
- Do we want the attributes.kubernetes.meta_restrict_local_node field?
- What about the attributes.kubernetes.informers_sync_timeout field?
- What about the attributes.kubernetes.informers_resync_period field?

General metadata decoration:
- In the attributes section we could also enabled the decoration config of non kubernetes fields like tunnel  attributes and so on. Basically, everything that is listed as opt-in within the spec: /mermin/docs/semcov/spec.md

Interal configuration options:
- They are missing as I'm not sure what they are.
 */
