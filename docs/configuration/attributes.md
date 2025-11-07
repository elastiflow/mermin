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
    "[*].metadata.name",       # Resource name
    "[*].metadata.namespace",  # Namespace
    "[*].metadata.uid",        # Unique ID
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

## Complete Example

See `examples/local/config.hcl` in the repository for a complete, working configuration.

## Next Steps

* [**Kubernetes Informers**](kubernetes-informers.md): Configure resource watching
* [**Owner Relations**](owner-relations.md): Add owner metadata
* [**Configuration Examples**](examples.md): See complete configurations
