---
hidden: true
---

# Kubernetes Informers

This page documents how to configure Mermin's Kubernetes informers, which watch and cache Kubernetes resources for flow metadata enrichment.

## Overview

Mermin uses Kubernetes informers to maintain an in-memory cache of cluster resources. This enables enriching network flows with Kubernetes metadata like pod names, labels, services, and owner references without querying the API server for every flow.

## Configuration

```hcl
discovery "informer" "k8s" {
  # K8s API connection configuration
  kubeconfig_path = ""
  informers_sync_timeout = "30s"
  informers_resync_period = "5s"

  selectors = [
    { kind = "Service" },
    { kind = "Endpoint" },
    { kind = "EndpointSlice" },
    { kind = "Gateway" },
    { kind = "Ingress" },
    { kind = "Pod" },
    { kind = "ReplicaSet" },
    { kind = "Deployment" },
    { kind = "DaemonSet" },
    { kind = "StatefulSet" },
    { kind = "Job" },
    { kind = "CronJob" },
    { kind = "NetworkPolicy" },
  ]
}
```

## Informer Configuration Options

### `kubeconfig_path`

**Type:** String (file path) **Default:** `""` (uses in-cluster config)

Path to kubeconfig file for API server connection.

**Examples:**

```hcl
discovery "informer" "k8s" {
  # Use in-cluster config (default for pods)
  kubeconfig_path = ""

  # Use specific kubeconfig
  # kubeconfig_path = "/etc/mermin/kubeconfig"

  # ... rest of configuration
}
```

**When to set:**

* Testing locally outside cluster
* Using specific service account
* Multi-cluster scenarios

### `informers_sync_timeout`

**Type:** Duration **Default:** `"30s"`

Timeout for initial informer synchronization.

**Description:**

* Maximum time to wait for informers to complete initial sync
* Mermin won't be ready until sync completes
* Large clusters may need longer timeout

**Examples:**

```hcl
discovery "informer" "k8s" {
  # Default
  informers_sync_timeout = "30s"

  # For large clusters (10,000+ pods)
  # informers_sync_timeout = "120s"

  # ... rest of configuration
}
```

### `informers_resync_period`

**Type:** Duration **Default:** `"30m"`

Periodic full resynchronization interval.

**Description:**

* Forces complete refresh of cached data
* Helps recover from missed watch events
* Balances freshness vs. API server load

**Examples:**

```hcl
discovery "informer" "k8s" {
  # Default
  informers_resync_period = "5s"

  # More frequent for critical environments
  # informers_resync_period = "15m"

  # Less frequent to reduce API load
  # informers_resync_period = "60m"

  # ... rest of configuration
}
```

## Resource Selectors

The `selectors` array determines which Kubernetes resources to watch.

### Selector Structure

```hcl
{
  kind = "Pod"               # Required: resource kind
  namespaces = []            # Optional: namespace filter
  include = true             # Optional: include/exclude
  match_labels = {}          # Optional: label selector
  match_expressions = []     # Optional: label expressions
}
```

### Basic Selector

Watch all resources of a kind:

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "Pod" },
    { kind = "Service" },
  ]
}
```

### Namespace Filtering

Watch resources in specific namespaces:

```hcl
discovery "informer" "k8s" {
  selectors = [
    # Only pods in these namespaces
    {
      kind = "Pod"
      namespaces = ["default", "production"]
    },

    # All services (no namespace filter)
    { kind = "Service" },
  ]
}
```

**Empty `namespaces = []`** means all namespaces (default).

### Label Selectors

Watch resources matching label criteria:

```hcl
discovery "informer" "k8s" {
  selectors = [
    # Pods with specific label
    {
      kind = "Pod"
      match_labels = {
        app = "nginx"
        env = "prod"
      }
    },
  ]
}
```

### Label Expressions

Advanced label matching:

```hcl
discovery "informer" "k8s" {
  selectors = [
    {
      kind = "Pod"
      match_expressions = [
        {
          key = "tier"
          operator = "In"
          values = ["frontend", "backend"]
        },
        {
          key = "deprecated"
          operator = "DoesNotExist"
        }
      ]
    },
  ]
}
```

**Operators:**

* `In`: Label value in list
* `NotIn`: Label value not in list
* `Exists`: Label key exists
* `DoesNotExist`: Label key doesn't exist

### Exclusion

Exclude specific resources:

```hcl
discovery "informer" "k8s" {
  selectors = [
    # Include all pods
    { kind = "Pod" },

    # Exclude gateways in "loggers" namespace
    {
      kind = "Gateway"
      namespaces = ["loggers"]
      include = false
    },
  ]
}
```

## Supported Resource Kinds

Mermin supports watching these Kubernetes resources:

| Kind            | Purpose                             |
| --------------- | ----------------------------------- |
| `Pod`           | Primary source for flow attribution |
| `Service`       | Service endpoints and selectors     |
| `Endpoint`      | (Deprecated) Service endpoints      |
| `EndpointSlice` | Modern service endpoints            |
| `ReplicaSet`    | Owner reference walking             |
| `Deployment`    | Owner reference walking             |
| `DaemonSet`     | Owner reference walking             |
| `StatefulSet`   | Owner reference walking             |
| `Job`           | Owner reference walking             |
| `CronJob`       | Owner reference walking             |
| `NetworkPolicy` | Network policy association          |
| `Ingress`       | Ingress controller flows            |
| `Gateway`       | Gateway API flows                   |

**Case insensitive**: `"Pod"`, `"pod"`, and `"POD"` are equivalent.

## Complete Configuration Example

```hcl
# Kubernetes informer configuration
discovery "informer" "k8s" {
  # K8s API connection configuration
  kubeconfig_path = ""
  informers_sync_timeout = "30s"
  informers_resync_period = "5s"

  # Resource selectors
  selectors = [
    # Core resources (always recommended)
    { kind = "Service" },
    { kind = "EndpointSlice" },
    { kind = "Pod" },

    # Workload controllers
    { kind = "ReplicaSet" },
    { kind = "Deployment" },
    { kind = "DaemonSet" },
    { kind = "StatefulSet" },
    { kind = "Job" },
    { kind = "CronJob" },

    # Network resources
    { kind = "NetworkPolicy" },
    { kind = "Ingress" },
    { kind = "Gateway" },
  ]

  # Owner relations configuration
  owner_relations = {
    max_depth = 5
    include_kinds = []
    exclude_kinds = []
  }

  # Selector relations (optional)
  selector_relations = []
}
```

## Performance Considerations

### Memory Usage

Memory usage scales with number of watched resources:

**Estimate:** \~1 KB per resource **10,000 pods:** \~10 MB **100,000 pods:** \~100 MB

### API Server Load

Informers use Kubernetes watch API:

* Initial LIST operation per resource type
* WATCH for ongoing updates
* Periodic resync (controlled by `informers_resync_period`)

**Reduce load:**

* Use namespace filtering
* Use label selectors
* Increase `informers_resync_period`

### Sync Time

Initial sync time depends on:

* Cluster size
* Number of resource types
* API server performance
* Network latency

**Large cluster tuning:**

```hcl
discovery "informer" "k8s" {
  # Longer timeout for large clusters
  informers_sync_timeout = "120s"

  # Less frequent resync
  informers_resync_period = "5m"

  # ... rest of configuration
}
```

## Troubleshooting

### Informer Sync Timeout

**Symptoms:** `informer sync timeout exceeded`

**Solutions:**

1. Increase `informers_sync_timeout`
2. Check API server responsiveness
3. Verify RBAC permissions
4. Reduce watched resource types

### Missing Metadata

**Symptoms:** Flows missing pod/service names

**Solutions:**

1. Verify resource kinds are in selectors
2. Check namespace filters
3. Verify label selectors
4. Review logs for sync errors

### High Memory Usage

**Symptoms:** Mermin using excessive memory

**Solutions:**

1. Add namespace filtering
2. Add label selectors
3. Remove unnecessary resource types
4. Check for resource leaks

## Best Practices

1. **Watch only needed resources**: Reduces memory and API load
2. **Use namespace filtering**: For multi-tenant clusters
3. **Monitor sync status**: Check logs and metrics
4. **Test selector changes**: Validate in non-production first
5. **Document selectors**: Comment why specific filters are used

## Next Steps

* [**Owner Relations**](owner-relations.md): Configure owner reference walking
* [**Selector Relations**](selector-relations.md): Configure selector-based matching
* [**Flow Attributes**](attributes.md): Configure metadata extraction
* [**Troubleshooting Metadata**](../troubleshooting/kubernetes-metadata.md): Debug missing metadata
