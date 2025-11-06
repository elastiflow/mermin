# Beta Program

> **Version Requirement**: v0.1.0-beta.16 or higher

### Accessing Beta Image and Helm chart

Before starting, configure access to the beta Helm charts and container images:

```bash
# Add Helm repositories
helm repo add \
  --username x-access-token \
  --password ${GH_PAT} \
  mermin https://raw.githubusercontent.com/elastiflow/mermin/gh-pages

helm repo add netobserv https://elastiflow.github.io/helm-chart-netobserv/
helm repo add opensearch https://opensearch-project.github.io/helm-charts/
helm repo update

# Create namespace and image pull secret
kubectl create namespace elastiflow

kubectl -n elastiflow create secret docker-registry ghcr \
    --docker-server=ghcr.io \
    --docker-username=elastiflow-ghcr \
    --docker-password=${GH_CLASSIC_TOKEN}
```

**Required credentials:**

* `GH_PAT`: GitHub Personal Access Token, provided by ElastiFlow
* `GH_CLASSIC_TOKEN`: GitHub Classic Token for ghcr.io access, provided by ElastiFlow

### Configuration Essentials

To see flows with Kubernetes metadata enrichment, Mermin requires three core configuration blocks.

Default config (described below) is already included to the beta image

#### Network Interface Discovery

Defaults should work for majority of CNI providers, more details on network interfaces Mermin discover can be found in the [Network Interface Discovery](../configuration/discovery-interfaces.md) section.

<!-- **What you'll see**: All pod-to-pod traffic (both inter-node and intra-node)
**What you'll miss**: Host network pods, node-to-node infrastructure traffic
<!-- **Note**: Generates 4 flow records per inter-node flow, 2 per intra-node flow (deduplication coming soon) -->

**Alternative: Physical Interfaces (Infrastructure-Focused)**

**Best for node/infrastructure monitoring** - Captures only inter-node traffic:

```hcl
discovery "instrument" {
  # Physical network interfaces
  interfaces = ["eth*", "ens*", "en*"]
}
```

**What you'll see**: Inter-node pod traffic, node-to-node traffic, host network pods\
**What you'll miss**: Intra-node pod-to-pod communication\
**Note**: Generates 2 flow records per flow (one at source node, one at destination)

> **For more information please reference**:  [Network Interface Discovery](../configuration/discovery-interfaces.md) -->

#### Kubernetes Informer Discovery

Defines which Kubernetes resources to watch for metadata enrichment

```hcl
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
```

#### Flow-to-Kubernetes Attribute Mapping

Maps flow data (IPs, ports) to Kubernetes resources below:

<details>
<summary>attributes source/destination</summary>


```hcl
/*
  Maps flow data (source IPs, ports) to Kubernetes resources:
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
```

</details>

#### OTLP Exporter

OTLP is the standard protocol for OpenTelemetry telemetry data. Mermin exports network flows as OTLP trace spans, enabling integration with any OTLP-compatible backend including OpenTelemetry Collector, Grafana Tempo, Jaeger, and more.

```hcl
export "traces" {
  stdout = {
    format = "text_indent" // text, text_indent(*new), json, json_indent
  }

  # otlp = {
  #   endpoint               = "http://otelcol:4317" # Use `https` for TLS encrypted OTLP receivers

  #   # Authentication config
  #   # auth = {
  #   #   basic = {
  #   #     user = "USERNAME"
  #   #     pass = "PASSWORD"
  #   #   }
  #   # }

  #   # TLS config
  #   # tls = {
  #   #   insecure_skip_verify = false # Skip verifying the OTLP receiver certificate
  #   #   ca_cert              = "/etc/certs/ca.crt" # Path to the receiver certificate Certificate Authority
  #   #   client_cert          = "/etc/certs/cert.crt" # Client TLS certificate (mTLS)
  #   #   client_key           = "/etc/certs/cert.key" # Client TLS key (mTLS)
  #   # }
  # }
}
```

### Helm deployment

Deploying with default config

```bash
helm upgrade --install mermin mermin/mermin \
  --namespace elastiflow \
  --set extraArgs='{--config,/etc/mermin/config.hcl}' \
  --devel \
  --wait \
  --timeout 5m

# Verify deployment
kubectl -n elastiflow get pods -l app.kubernetes.io/name=mermin
```

#### Deploying with custom config

```bash
helm upgrade --install mermin mermin/mermin \
  --namespace elastiflow \
  --set-file config.content=PATH/TO/config.hcl \
  --devel \
  --wait \
  --timeout 5m

# Verify deployment
kubectl -n elastiflow get pods -l app.kubernetes.io/name=mermin
```

### See Your First Flows

View network flows captured by Mermin:

```bash
# Stream flow logs
kubectl -n elastiflow logs -l app.kubernetes.io/name=mermin -f --tail=20

# In a new terminal, generate test traffic
kubectl run test-traffic --rm -it --image=busybox -- ping -c 5 8.8.8.8
```

**Expected output** (flow span example):

```text
Spans
Span #0
	Instrumentation Scope
		Name         : "mermin"

	Name         : flow_ipv4_tcp
	TraceId      : 3a156c0ca71492db5eafd4d9bb99a825
	SpanId       : 6c2402e7ce18012e
	TraceFlags   : TraceFlags(1)
	ParentSpanId : None (root span)
	Kind         : Internal
	Start time   : 2025-11-06 16:27:13.145452
	End time     : 2025-11-06 16:27:13.146010
	Status       : Unset
	Attributes:
		 ->  flow.community_id: String(Owned("1:yqMXaKYTc3IYuit980u3AiXTXFM="))
		 ->  network.type: String(Static("ipv4"))
		 ->  network.transport: String(Static("tcp"))
		 ->  source.address: String(Owned("10.244.1.4"))
		 ->  source.port: I64(8080)
		 ->  destination.address: String(Owned("10.244.1.1"))
		 ->  destination.port: I64(51354)
		 ->  flow.bytes.delta: I64(489)
		 ->  flow.bytes.total: I64(489)
		 ->  flow.packets.delta: I64(5)
		 ->  flow.packets.total: I64(5)
		 ->  flow.reverse.bytes.delta: I64(376)
		 ->  flow.reverse.bytes.total: I64(376)
		 ->  flow.reverse.packets.delta: I64(5)
		 ->  flow.reverse.packets.total: I64(5)
		 ->  flow.end_reason: String(Static("end of Flow detected"))
		 ->  network.interface.index: I64(14)
		 ->  network.interface.name: String(Owned("veth3afa1569"))
		 ->  network.interface.mac: String(Owned("4a:ca:1a:59:63:4a"))
		 ->  flow.ip.dscp.id: I64(0)
		 ->  flow.ip.dscp.name: String(Owned("df"))
		 ->  flow.ip.ecn.id: I64(0)
		 ->  flow.ip.ecn.name: String(Owned("non-ect"))
		 ->  flow.ip.ttl: I64(64)
		 ->  flow.tcp.flags.bits: I64(27)
		 ->  flow.tcp.flags.tags: Array(String([Owned("fin"), Owned("syn"), Owned("psh"), Owned("ack")]))
		 ->  source.k8s.namespace.name: String(Owned("elastiflow"))
		 ->  source.k8s.pod.name: String(Owned("mermin-t7wpj"))
		 ->  source.k8s.daemonset.name: String(Owned("mermin"))
```

### Providing Feedback

* **Email**: \[Support contact - add email address]
