---
hidden: true
---

# Selector Relations

Selector relations enable matching Kubernetes resources based on label selectors, such as NetworkPolicy → Pod or Service → Pod associations.

## Overview

Many Kubernetes resources use selectors to target other resources. Mermin can extract these selectors and find matching resources to enrich flow metadata.

## Configuration

```hcl
discovery "informer" "k8s" {
  selector_relations = [
    {
      kind = "NetworkPolicy"
      to = "Pod"
      selector_match_labels_field = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },
    {
      kind = "Service"
      to = "Pod"
      selector_match_labels_field = "spec.selector"
    },
  ]
}
```

## Configuration Options

### `kind`

**Type:** String (case insensitive)

Source resource kind containing the selector.

**Supported:** NetworkPolicy, Service, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob

### `to`

**Type:** String (case insensitive)

Target resource kind to match against.

**Typical:** Pod

### `selector_match_labels_field`

**Type:** String (optional)

JSON path to `matchLabels` field in source resource.

**Example:** `"spec.podSelector.matchLabels"`

### `selector_match_expressions_field`

**Type:** String (optional)

JSON path to `matchExpressions` field in source resource.

**Example:** `"spec.podSelector.matchExpressions"`

## Common Configurations

### NetworkPolicy → Pod

```hcl
{
  kind = "NetworkPolicy"
  to = "Pod"
  selector_match_labels_field = "spec.podSelector.matchLabels"
  selector_match_expressions_field = "spec.podSelector.matchExpressions"
}
```

### Service → Pod

```hcl
{
  kind = "Service"
  to = "Pod"
  selector_match_labels_field = "spec.selector"
}
```

### Workload Controllers → Pod

```hcl
{
  kind = "Deployment"
  to = "Pod"
  selector_match_labels_field = "spec.selector.matchLabels"
}
```

## Complete Example

```hcl
discovery "informer" "k8s" {
  selector_relations = [
    # NetworkPolicy selection
    {
      kind = "NetworkPolicy"
      to = "Pod"
      selector_match_labels_field = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },

    # Service selection
    {
      kind = "Service"
      to = "Pod"
      selector_match_labels_field = "spec.selector"
    },
  ]
}
```

## Next Steps

* [**Flow Attributes**](attributes.md): Configure metadata extraction
* [**Owner Relations**](owner-relations.md): Configure owner reference walking
