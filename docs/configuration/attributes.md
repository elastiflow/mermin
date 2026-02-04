# Configure Flow Span Attribution

Flow attributes define which Kubernetes metadata to extract and how to associate it with network flows.

## Overview

The `attributes` configuration has two main components:

1. **Extract**: Which metadata fields to extract from Kubernetes resources
2. **Association**: How to map flow attributes (IPs, ports) to Kubernetes object fields

## Configuration

Mermin accepts HCL or YAML for the config file. The examples below use HCL; the same structure can be expressed in YAML (see [Configuration Overview](configuration.md#file-format)).

```hcl
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
          from = "flow"
          name = "source.ip"
          to = ["status.podIP", "status.podIPs[*]"]
        }
      ]
    }

    service = {
      sources = [
        {
          from = "flow"
          name = "source.ip"
          to = ["spec.clusterIP", "spec.clusterIPs[*]"]
        },
        {
          from = "flow"
          name = "source.port"
          to = ["spec.ports[*].port"]
        }
      ]
    }
  }
}
```

## Extract Configuration

### `metadata`

Array of JSONPath-style paths to extract from Kubernetes resources. Paths are evaluated against the resource object (Pod, Service, Node, etc.).

**Common extractions:**

```hcl
extract {
  metadata = [
    "[*].metadata.name", # Resource name
    "[*].metadata.namespace", # Namespace
    "[*].metadata.uid", # Unique ID
  ]
}
```

**Syntax:**

- `[*]`: Applies to all resource kinds
- `pod.metadata.name`: Specific to pods
- `[*].metadata.labels`: Extract labels

## Association Configuration

Associations map flow fields (e.g. `source.ip`, `source.port`) to Kubernetes object fields for matching. The `to` paths are JSONPath-style paths over the resource (Pod, Service, Node, etc.).

### Pod Association

```hcl
pod = {
  sources = [
    {
      from = "flow"
      name = "source.ip"
      to = ["status.podIP", "status.podIPs[*]", "status.hostIP"]
    }
  ]
}
```

### Service Association

```hcl
service = {
  sources = [
    {
      from = "flow"
      name = "source.ip"
      to = ["spec.clusterIP", "spec.clusterIPs[*]"]
    },
    {
      from = "flow"
      name = "source.port"
      to = ["spec.ports[*].port"]
    },
    {
      from = "flow"
      name = "network.transport"
      to = ["spec.ports[*].protocol"]
    }
  ]
}
```

### Other Association Types

In addition to **pod**, **service**, and **node**, you can configure:

| Association       | Resource              | Use case                                                                         |
|-------------------|-----------------------|----------------------------------------------------------------------------------|
| **endpointslice** | EndpointSlice         | Direct matching of EndpointSlice backend IPs (e.g. `endpoints[*].addresses[*]`). |
| **networkpolicy** | NetworkPolicy         | Match flows to NetworkPolicy resources by IP.                                    |
| **ingress**       | Ingress               | Match flows to Ingress VIPs and backend IPs.                                     |
| **gateway**       | Gateway (Gateway API) | Match flows to Gateway resources.                                                |

Example for direct EndpointSlice IP matching:

```hcl
association {
  endpointslice = {
    sources = [
      {
        from = "flow"
        name = "source.ip"
        to = ["endpoints[*].addresses[*]"]
      }
    ]
  }
}
```

## Source vs Destination

Configure attributes for both flow directions:

```hcl
# Source IP/port matching
attributes "source" "k8s" {
  extract { ... }
  association { ... }
}

# Destination IP/port matching
attributes "destination" "k8s" {
  extract { ... }
  association { ... }
}
```

### Default Configuration

Summary of default associations (source and destination each get the same structure, with `source.ip`/`source.port` or `destination.ip`/`destination.port`):

| Association  | Flow fields used            | Kubernetes paths (summary)                                                                                                      |
|--------------|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| **pod**      | ip, port, network.transport | status.podIP, status.podIPs[*], status.hostIP, status.hostIPs[*], spec.containers[*].ports[*].containerPort, hostPort, protocol |
| **service**  | ip, port, network.transport | spec.clusterIP, spec.clusterIPs[*], spec.externalIPs[*], spec.loadBalancerIP, spec.ports[*].port, spec.ports[*].protocol        |
| **node**     | ip                          | status.addresses[*].address                                                                                                     |
| **endpoint** | ip                          | endpoints[*].addresses[*] (legacy; for direct EndpointSlice IP matching use **endpointslice**)                                  |

**Note:** The default **endpoint** block uses path `endpoints[*].addresses[*]`. The IP index is built from **pod**, **service**, **node**, and **endpointslice** when present.
For direct matching of EndpointSlice backend IPs, add an **endpointslice** association (see [Other association types](#other-association-types)).

```hcl
# Automatically configured - no manual setup required
attributes "source" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name", # Resource name
      "[*].metadata.namespace", # Namespace
      "[*].metadata.uid", # Unique identifier
    ]
  }

  association {
    pod = {
      sources = [
        {
          from = "flow"
          name = "source.ip"
          to = [
            "status.podIP",
            "status.podIPs[*]",
            "status.hostIP",
            "status.hostIPs[*]"
          ]
        },
        {
          from = "flow"
          name = "source.port"
          to = [
            "spec.containers[*].ports[*].containerPort",
            "spec.containers[*].ports[*].hostPort"
          ]
        },
        {
          from = "flow"
          name = "network.transport"
          to = ["spec.containers[*].ports[*].protocol"]
        }
      ]
    }

    service = {
      sources = [
        {
          from = "flow"
          name = "source.ip"
          to = [
            "spec.clusterIP",
            "spec.clusterIPs[*]",
            "spec.externalIPs[*]",
            "spec.loadBalancerIP"
          ]
        },
        {
          from = "flow"
          name = "source.port"
          to = ["spec.ports[*].port"]
        },
        {
          from = "flow"
          name = "network.transport"
          to = ["spec.ports[*].protocol"]
        }
      ]
    }

    node = {
      sources = [
        {
          from = "flow"
          name = "source.ip"
          to = ["status.addresses[*].address"]
        }
      ]
    }

    endpoint = {
      sources = [
        {
          from = "flow"
          name = "source.ip"
          to = ["endpoints[*].addresses[*]"]
        }
      ]
    }
  }
}

# Same configuration automatically applied for destination
attributes "destination" "k8s" {
  # ... identical structure with destination.ip and destination.port
}
```

**Strategy**: Comprehensive Kubernetes metadata enrichment without manual configuration

- **Pod associations** capture container networking (IPs, ports, protocols) including both pod and host networking
- **Service associations** cover all service types (ClusterIP, LoadBalancer, ExternalIP) with port and protocol matching
- **Node associations** match node IP addresses for host networking scenarios
- The default **endpoint** association is provided for compatibility; for direct EndpointSlice IP matching, use **endpointslice** (see [Other association types](#other-association-types))

This covers the most common Kubernetes networking patterns and provides immediate network observability upon deployment.

### How to Disable Default Attributes

If you need to disable the automatic attributes configuration, override it with an empty configuration:

```hcl
# Disables all default and custom attribution rules.
attributes {}
```

### How to Customize Default Attributes

You can provide your own `attributes` configuration to override the defaults:

```hcl
# Custom source attributes (replaces defaults)
attributes "source" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.labels", # Add custom fields
    ]
  }

  association {
    pod = {
      sources = [
        {
          from = "flow"
          name = "source.ip"
          to = ["status.podIP"]  # Simplified matching
        }
      ]
    }
  }
}
```

Any explicit `attributes` configuration completely replaces the defaults for that direction and provider.
If you only configure one direction (e.g. only `attributes "source" "k8s"`), the other direction gets no attribution unless you add it explicitly.

### Verification

To verify the default attributes are working:

1. Deploy Mermin without any `attributes` configuration
2. Generate network traffic in your cluster
3. Check that flow spans include Kubernetes metadata like:
    - `source.k8s.pod.name`, `source.k8s.service.name`, `source.k8s.namespace.name`
    - `destination.k8s.pod.name`, `destination.k8s.service.name`, `destination.k8s.namespace.name` (and other `destination.*` equivalents)

## Next Steps

- [**Kubernetes Informers**](discovery-kubernetes-informer.md): Configure resource watching
- [**Owner Relations**](owner-relations.md): Add owner metadata
- [**Configuration Examples**](examples.md): See complete configurations
