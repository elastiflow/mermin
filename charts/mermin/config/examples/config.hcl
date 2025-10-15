global_opt = "global_opt_value"

/*
  Agent config for type "flows" with name main
*/
agent "traces" {
  /*
    Define which flow will be processed and sent to the output.
    Impacts the "In-mem K8s objects cache" build by K8s informer (https://www.plural.sh/blog/manage-kubernetes-events-informers/)
      - By default `namespaces = []`, which means "all namespaces", e.g. no filtering by namespaces.
      - `kind` is case insensitive
  */
  k8s = {
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
  }

  # Include configurations
  flow_connection = "flow.connection"
  network_interface = {
    include_names = [] # ["lo", "eth0"], empty list means all
    exclude_names = [] # ["lo", "eth0"], empty list means none
  }

  source      = "flow.span.source"
  destination = "flow.span.destination"

  include_network_transports = [] # ["tcp", "udp"], empty list means all
  exclude_network_transports = [] # ["tcp", "udp"], empty list means none
  include_network_types = [] # ["ipv4", "ipv6"], empty list means all
  exclude_network_types = [] # ["ipv4", "ipv6"], empty list means none

  discovery_owner    = "discovery.k8s_owner.main"
  discovery_selector = "discovery.k8s_selector.main"

  association_source      = "association.k8s_flow_attributes.source"
  association_destination = "association.k8s_flow_attributes.destination"

  exporters = ["exporter.stdout.json", "exporter.otlp.main"]
}

# Network Filtering options, includes but not limited to https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/#network-attributes

flow "connection" {
  include_states = [] # close_wait, empty list means all
  exclude_states = [] # close_wait, empty list means none
}

flow "span" "source" {
  include_cidrs = [] # empty list means all
  exclude_cidrs = [] # empty list means none
  include_ports = [] # empty list means all
  exclude_ports = [] # empty list means none
}

flow "span" "destination" {
  include_cidrs = [] # empty list means all
  exclude_cidrs = [] # empty list means none
  include_ports = [] # empty list means all
  exclude_ports = [] # empty list means none
}

# Discovery config of type "k8s_owner" with name "main"
discovery "k8s_owner" {
  /*
    Limit the ownerReference walk depth, e.g. If `walk_max_depth = 3`
    If Pod <- Job <- CronJob <- Controller1 <- Controller2 <- Controller3 <- ...
    Only Pod <- Job <- CronJob relation is discovered
  */
  walk_max_depth = 10

  /*
    depth of attached metadata, e.g., if `maxDepth = 1`
    and object ownership `Pod <- Job <- CronJob` only Pod and Job fields are attached
  */
  max_depth = 5

  # case insensitive
  include_kinds = [
    "Service", # Add (include) `EndpointSlice` metadata as flow labels (fields)
  ]

  # Exclude overrides include, case insensitive
  # If an item matches an exclusion rule, it is immediately removed and isn't considered by the inclusion rules
  exclude_kinds = [
    "EndpointSlice", # Do not add (exclude) `EndpointSlice` metadata as flow labels (fields)
  ]
}

# Discovery config of type "k8s_selector" with name "main"
discovery "k8s_selector" {
  /*
    Extract selector fields from the NetworkPolicy definition, select Pods (`to` field) based on the selectors,
    attach NetworkPolicy metadata to flows related to the selected pods
  */
  k8s_object {
    kind = "NetworkPolicy" # case insensitive
    to = "Pod"           # case insensitive
    selector_match_labels_field      = "spec.podSelector.matchLabels"
    selector_match_expressions_field = "spec.podSelector.matchExpressions"
  }

  /*
    Extract selector fields from the Service definition, select Pods (`to` field) based on the selectors,
    attach Service metadata to flows related to the selected pods
  */
  k8s_object {
    kind = "Service" # case insensitive
    to = "Pod"     # case insensitive
    selector_match_labels_field = "spec.selector"
  }
}

/*
  How to associate the flow data to a K8s object.
  Association config of type "k8s_flow_attributes" with name "main_src"
*/
association "k8s_flow_attributes" "source" {
  /*
    `extract` defines the metadata to extract from all objects.
  */
  extract {
    metadata = [
      "[*].metadata.name", # All kinds, metadata.name
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "[*].metadata.uid", # All kinds, metadata.uid (if present)
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

  /*
    Flow to Pod mapping.
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["pod.status.podIP", "pod.status.podIPs[*]", "pod.status.hostIP", "pod.status.hostIPs[*]"] },
      { from = "flow", name = "source.port", to = ["pod.spec.containers[*].ports[*].containerPort", "pod.spec.containers[*].ports[*].hostPort"] },
      { from = "flow", name = "network.transport", to = ["pod.spec.containers[*].ports[*].protocol"] },
    ]
  }

  /*
    Flow to Node mapping
      - `node.status.addresses[*].address` name resolution needs to happen when `status.addresses[].type == Hostname`, fine if name resolution failed
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["node.status.addresses[*].address"] },
    ]
  }

  /*
    Service mapping
      - `service.spec.externalName` name resolution needs to happen
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["service.spec.clusterIP", "service.spec.clusterIPs[*]", "service.spec.externalIPs[*]", "service.spec.loadBalancerIP", "service.spec.externalName"] },
      { from = "flow", name = "source.port", to = ["service.spec.ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["service.spec.ports[*].protocol"] },
      { from = "flow", name = "network.type", to = ["service.spec.ipFamilies[*]"] },
    ]
  }

  /*
    Endpoint mapping (deprecated, full attribute paths, no kind)
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["endpoint.subsets[*].addresses[*].ip"] },
      { from = "flow", name = "source.port", to = ["endpoint.subsets[*].ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["endpoint.subsets[*].ports[*].protocol"] },
    ]
  }

  /*
    EndpointSlice mapping
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["endpointslice.endpoints[*].addresses[*]"] },
      { from = "flow", name = "source.port", to = ["endpointslice.ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["endpointslice.ports[*].protocol"] },
      { from = "flow", name = "network.type", to = ["endpointslice.addressType"] },
    ]
  }

  /*
    Ingress mapping
      - `ingress.status.loadBalancer.ingress[*].hostname` name resolution needs to happen
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["ingress.status.loadBalancer.ingress[*].ip", "ingress.status.loadBalancer.ingress[*].hostname"] },
      { from = "flow", name = "source.port", to = ["ingress.spec.defaultBackend.service.port", "ingress.spec.rules[*].http.paths[*].backend.service.port.number"] }
    ]
  }

  /*
    Gateway mapping
      `gateway.spec.addresses[*].value` name resolution needs to happen if `gateway.spec.addresses[*].type == Hostname`
      `gateway.status.addresses[*].value` name resolution needs to happen if `gateway.status.addresses[*].type == Hostname`
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["gateway.spec.addresses[*].value", "gateway.status.addresses[*].value"] },
      { from = "flow", name = "source.port", to = ["gateway.spec.listeners[*].port"] },
    ]
  }

  /*
    NetworkPolicy src mapping (SRC/DST IP/Port/Protocol)
      - If `networkpolicy.spec.ingress[*].ports[*].endPort` or `networkpolicy.spec.egress[*].ports[*].endPort` is defined for a port,
        than port matching should be done against `port - endPort` range
      - If `networkpolicy.spec.ingress[*].ports[*].endPort` or `networkpolicy.spec.egress[*].ports[*].endPort` is a string,
        port should be retrieved from related pods (https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#networkpolicypeer-v1-networking-k8s-io)
  */
  association {
    sources = [
      { from = "flow", name = "source.ip", to = ["networkpolicy.spec.ingress[*].from[*].ipBlock.cidr", "networkpolicy.spec.egress[*].to[*].ipBlock.cidr"] },
      { from = "flow", name = "source.port", to = ["networkpolicy.spec.ingress[*].ports[*].port", "networkpolicy.spec.egress[*].ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["networkpolicy.spec.ingress[*].ports[*].protocol", "networkpolicy.spec.egress[*].ports[*].protocol"] },
    ]
  }
}

/*
  How to associate the flow data to a K8s object
  Association config of type "k8s_flow_attributes" with name "main_src"
*/
association "k8s_flow_attributes" "destination" {
  extract {
    metadata = [
      "[*].metadata.name", # All kinds, metadata.name
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "pod.metadata.uid", # All kinds, metadata.uid
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

  /*
    Flow to Pod mapping
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["pod.status.podIP", "pod.status.podIPs[*]", "pod.status.hostIP", "pod.status.hostIPs[*]"] },
      { from = "flow", name = "destination.port", to = ["pod.spec.containers[*].ports[*].containerPort", "pod.spec.containers[*].ports[*].hostPort"] },
      { from = "flow", name = "network.transport", to = ["pod.spec.containers[*].ports[*].protocol"] },
    ]
  }

  /*
    Flow to Node mapping
      - `node.status.addresses[*].address` name resolution needs to happen when `status.addresses[].type == Hostname`, fine if name resolution failed
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["node.status.addresses[*].address"] },
    ]
  }

  /*
    Service mapping
      - `service.spec.externalName` name resolution needs to happen
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["service.spec.clusterIP", "service.spec.clusterIPs[*]", "service.spec.externalIPs[*]", "service.spec.loadBalancerIP", "service.spec.externalName"] },
      { from = "flow", name = "destination.port", to = ["service.spec.ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["service.spec.ports[*].protocol"] },
      { from = "flow", name = "network.type", to = ["service.spec.ipFamilies[*]"] },
    ]
  }

  /*
    Endpoint mapping (deprecated, full attribute paths, no kind)
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["endpoint.subsets[*].addresses[*].ip"] },
      { from = "flow", name = "destination.port", to = ["endpoint.subsets[*].ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["endpoint.subsets[*].ports[*].protocol"] },
    ]
  }

  /*
    EndpointSlice mapping
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["endpointslice.endpoints[*].addresses[*]"] },
      { from = "flow", name = "destination.port", to = ["endpointslice.ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["endpointslice.ports[*].protocol"] },
    ]
  }

  /*
    Ingress mapping
      - `ingress.status.loadBalancer.ingress[*].hostname` name resolution needs to happen
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["ingress.status.loadBalancer.ingress[*].ip", "ingress.status.loadBalancer.ingress[*].hostname"] },
      { from = "flow", name = "destination.port", to = ["ingress.spec.defaultBackend.service.port", "ingress.spec.rules[*].http.paths[*].backend.service.port.number"] }
    ]
  }

  /*
    Gateway mapping
      `gateway.spec.addresses[*].value` name resolution needs to happen if `gateway.spec.addresses[*].type == Hostname`
      `gateway.status.addresses[*].value` name resolution needs to happen if `gateway.status.addresses[*].type == Hostname`
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["gateway.spec.addresses[*].value", "gateway.status.addresses[*].value"] },
      { from = "flow", name = "destination.port", to = ["gateway.spec.listeners[*].port"] },
    ]
  }

  /*
    NetworkPolicy src mapping (SRC/DST IP/Port/Protocol)
      - If `networkpolicy.spec.ingress[*].ports[*].endPort` or `networkpolicy.spec.egress[*].ports[*].endPort` is defined for a port,
        than port matching should be done against `port - endPort` range
      - If `networkpolicy.spec.ingress[*].ports[*].endPort` or `networkpolicy.spec.egress[*].ports[*].endPort` is a string,
        port should be retrieved from related pods (https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#networkpolicypeer-v1-networking-k8s-io)
  */
  association {
    sources = [
      { from = "flow", name = "destination.ip", to = ["networkpolicy.spec.ingress[*].from[*].ipBlock.cidr", "networkpolicy.spec.egress[*].to[*].ipBlock.cidr"] },
      { from = "flow", name = "destination.port", to = ["networkpolicy.spec.ingress[*].ports[*].port", "networkpolicy.spec.egress[*].ports[*].port"] },
      { from = "flow", name = "network.transport", to = ["networkpolicy.spec.ingress[*].ports[*].protocol", "networkpolicy.spec.egress[*].ports[*].protocol"] },
    ]
  }
}

# Exporter (output) config of type stdout with name "json"
exporter "stdout" "json" {
  format = "json"
  # If no fields specified, all fields to stdout
  # fields = {
  #   label_app = "source.pod.labels.app"
  # }
}

# OTLP exporter configuration with name "main"
exporter "otlp" "main" {
  address = "example.com"
  port    = 4317

  auth {
    basic = {
      user = "USERNAME"
      pass = "USER_SPECIFIED_ENV_VAR_TRITON_PASS"
    }
  }

  tls {
    enabled     = true
    insecure    = false
    ca_cert     = "/etc/certs/ca.crt"
    client_cert = "/etc/certs/cert.crt"
    client_key  = "/etc/certs/cert.key"
  }
}
