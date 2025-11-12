---
hidden: true
---

# Flow Attributes

Flow attributes define which Kubernetes metadata to extract and how to associate it with network flows.

## Overview

The `attributes` configuration has two main components:

1. **Extract**: Which metadata fields to extract from Kubernetes resources
2. **Association**: How to map flow attributes (IPs, ports) to Kubernetes object fields

## Configuration

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

Array of JSON paths to extract from Kubernetes resources.

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

* `[*]`: Applies to all resource kinds
* `pod.metadata.name`: Specific to pods
* `[*].metadata.labels`: Extract labels

## Association Configuration

Associations map flow fields to Kubernetes object fields for matching.

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

* **Pod associations** capture container networking (IPs, ports, protocols) including both pod and host networking
* **Service associations** cover all service types (ClusterIP, LoadBalancer, ExternalIP) with port and protocol matching
* **Node associations** match node IP addresses for host networking scenarios
* **Endpoint associations** capture endpoint slice IP addresses for service discovery

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

### Verification

To verify the default attributes are working:

1. Deploy Mermin without any `attributes` configuration
2. Generate network traffic in your cluster
3. Check that flow spans include Kubernetes metadata like:
    - `k8s.pod.name`
    - `k8s.service.name`
    - `k8s.namespace.name`

## Next Steps

* [**Kubernetes Informers**](kubernetes-informers.md): Configure resource watching
* [**Owner Relations**](owner-relations.md): Add owner metadata
* [**Configuration Examples**](examples.md): See complete configurations
